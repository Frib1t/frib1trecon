"""
Deteccion de WAF / CDN de proteccion. Dos peticiones como maximo:
  1. GET normal a la pagina principal: se miran cabeceras y cookies que delatan
     al proveedor (Cloudflare, Akamai, Incapsula, Sucuri, AWS WAF, F5, ModSecurity...).
  2. Una peticion con un patron de prueba inocuo en la query (comilla y
     'OR 1=1', el tipo de cadena que casi todos los WAF reconocen): si la
     respuesta cambia (403/406/429/501 o pagina de bloqueo) respecto a la normal,
     hay un WAF filtrando peticiones aunque no se identifique el proveedor.
"""
import re

from . import http_client

# (nombre, regex sobre cabeceras "nombre: valor" y cookies)
SIGNATURES = [
    ("Cloudflare", r"cloudflare|cf-ray|__cfduid|cf_clearance"),
    ("Akamai", r"akamai|x-akamai|akamaighost"),
    ("Imperva Incapsula", r"incapsula|incap_ses|visid_incap|x-iinfo"),
    ("Sucuri", r"sucuri|x-sucuri"),
    ("AWS WAF / CloudFront", r"awselb|x-amz-cf-id|x-amzn-waf|cloudfront"),
    ("F5 BIG-IP ASM", r"bigipserver|\bts[0-9a-f]{8}=|x-wa-info|f5-"),
    ("ModSecurity", r"mod_security|modsecurity|noyb"),
    ("Wordfence", r"wordfence"),
    ("Barracuda", r"barra_counter_session|barracuda"),
    ("Fortinet FortiWeb", r"fortiwafsid|fortiweb"),
]
BLOCK_STATUS = {403, 406, 429, 501, 503}
BLOCK_BODY = re.compile(r"access denied|forbidden|blocked|firewall|mod_security|request rejected|waf", re.I)
CANARY = "/?frib1trecon_waf=1' OR '1'='1"


def _fingerprint(headers: dict, cookies: str) -> list[str]:
    blob = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + cookies
    return [name for name, pattern in SIGNATURES if re.search(pattern, blob, re.I)]


def detect_waf(domain: str) -> dict | None:
    """Devuelve {'proveedores': [...], 'bloqueo_probado': bool, 'status_normal', 'status_prueba'}
    o None si no hay ninguna respuesta del sitio."""
    base = None
    normal = None
    for scheme in ("https", "http"):
        r = http_client.get(f"{scheme}://{domain}/", timeout=10, allow_redirects=True)
        if r is not None:
            base, normal = f"{scheme}://{domain}", r
            break
    if normal is None:
        return None

    cookies = "; ".join(f"{c.name}={c.value}" for c in normal.cookies)
    providers = _fingerprint(dict(normal.headers), cookies)

    probe = http_client.get(base + CANARY, timeout=10, allow_redirects=False)
    blocked = False
    if probe is not None:
        if probe.status_code in BLOCK_STATUS and probe.status_code != normal.status_code:
            blocked = True
        elif BLOCK_BODY.search(probe.text or "") and not BLOCK_BODY.search(normal.text or ""):
            blocked = True
        if not providers:
            providers = _fingerprint(dict(probe.headers), "; ".join(f"{c.name}={c.value}" for c in probe.cookies))
    return {
        "proveedores": providers,
        "bloqueo_probado": blocked,
        "status_normal": normal.status_code,
        "status_prueba": probe.status_code if probe is not None else None,
    }
