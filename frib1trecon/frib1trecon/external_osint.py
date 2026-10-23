"""
Fuentes OSINT externas opcionales: GrayHatWarfare (buckets S3/Azure/GCP
expuestos), Shodan (hosts/puertos expuestos), IntelX (leaks/darkweb/
phonebook), crt.sh + Certspotter (subdominios vistos en certificados SSL,
dos fuentes independientes para redundancia: crt.sh es conocido por
caerse/saturarse), DNSDumpster (subdominios, necesita api key de pago),
VirusTotal + AbuseIPDB (reputacion del dominio/IP: motores que lo marcan
malicioso, reportes de abuso/botnet/spam) y Wayback Machine (URLs
archivadas que ya no estan enlazadas, pueden revelar backups/paneles/
endpoints olvidados). Categoria "external", opt-in (no se lanza en un
analisis normal, hay que pedirla con --categories external o --all).

Shodan, crt.sh, Certspotter y Wayback Machine son gratis y no necesitan API
key, asi que se consultan siempre que la categoria este activa.
GrayHatWarfare, IntelX, DNSDumpster, VirusTotal y AbuseIPDB necesitan que
el usuario aporte su propia API key (variable de entorno o flag de la
CLI, NUNCA hardcodeada en este fichero); si no hay key, esa fuente
concreta se omite sin fallar el resto del escaneo.
"""
import re
import socket
import time

import requests

from .metadata import SUSPICIOUS_FILENAME_RE

GHW_FILES_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
DNSDUMPSTER_URL = "https://api.dnsdumpster.com/domain/{domain}"
WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"

# extensiones/paths que convierten una URL archivada "cualquiera" en algo
# que merece la pena revisar: sin este filtro, Wayback Machine devuelve
# miles de URLs normales (paginas de producto, posts...) que no aportan nada
SENSITIVE_WAYBACK_EXTENSIONS = (
    ".sql", ".bak", ".env", ".zip", ".tar.gz", ".log", ".ini",
    ".yml", ".yaml", ".old", ".swp", ".config", ".pem", ".key",
)
WAYBACK_PATH_HINTS = ("admin", "login", "panel", "wp-admin", "backup",
                       "debug", "phpinfo", ".git/", "config", "private")


def search_grayhatwarfare(domain: str, api_key: str, timeout: int = 15) -> list[dict]:
    """Busca el dominio en nombres de fichero/ruta de buckets de almacenamiento
    en la nube (S3, Azure Blob, GCS) indexados publicamente por GrayHatWarfare."""
    try:
        resp = requests.get(
            GHW_FILES_URL,
            params={"keywords": domain},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    return data.get("files", [])


def search_shodan(domain: str, api_key: str | None, timeout: int = 15) -> list[dict]:
    """Resuelve el dominio a IP y consulta Shodan. InternetDB es gratis y
    siempre se intenta; el host completo (mas detalle: banners, org...)
    solo si se aporta una api_key."""
    try:
        ip = socket.gethostbyname(domain)
    except OSError:
        return []

    results = []

    try:
        resp = requests.get(SHODAN_INTERNETDB_URL.format(ip=ip), timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            data["_ip"] = ip
            data["_source"] = "InternetDB (gratis)"
            results.append(data)
    except (requests.RequestException, ValueError):
        pass

    if api_key:
        try:
            resp = requests.get(
                SHODAN_HOST_URL.format(ip=ip), params={"key": api_key}, timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                data["_ip"] = ip
                data["_source"] = "Shodan host"
                results.append(data)
        except (requests.RequestException, ValueError):
            pass

    return results


def search_intelx(domain: str, api_key: str) -> dict:
    """Busca el dominio en el indice de IntelX (pastes, leaks, darkweb...) y
    en su phonebook (emails/subdominios relacionados). Usa el paquete oficial
    'intelx'; si no esta instalado o la API falla, devuelve listas vacias
    sin interrumpir el resto del escaneo."""
    try:
        from intelxapi import intelx as IntelXClient
    except ImportError:
        return {"records": [], "selectors": []}

    client = IntelXClient(api_key)

    records = []
    try:
        res = client.search(domain, maxresults=50, timeout=10)
        records = res.get("records", []) or []
    except SystemExit:
        pass
    except Exception:
        pass

    selectors = []
    try:
        pages = client.phonebooksearch(domain, maxresults=200, timeout=10, target=0)
        for page in pages:
            selectors.extend(page.get("selectors", []) or [])
    except SystemExit:
        pass
    except Exception:
        pass

    return {"records": records, "selectors": selectors}


def search_crtsh(domain: str, timeout: int = 20) -> list[str]:
    """Subdominios historicos vistos en certificados SSL (Certificate
    Transparency logs, via crt.sh). Gratis, sin api key, pero crt.sh es un
    servicio comunitario conocido por saturarse/caerse a menudo: se
    reintenta una vez y si sigue fallando se omite sin interrumpir el
    resto del escaneo."""
    for _ in range(2):
        try:
            resp = requests.get(
                CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                names = set()
                for entry in data:
                    for n in entry.get("name_value", "").split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n and domain.lower() in n:
                            names.add(n)
                return sorted(names)
        except (requests.RequestException, ValueError):
            pass
    return []


def search_certspotter(domain: str, timeout: int = 20) -> list[str]:
    """Alternativa a crt.sh: mismo tipo de dato (subdominios vistos en
    certificados SSL, via Certificate Transparency), pero en un servicio
    distinto (sslmate/Certspotter). Gratis sin api key para uso moderado.
    Se consulta siempre ademas de crt.sh, nunca en su lugar: si uno de los
    dos esta caido ese dia, el otro suele seguir funcionando."""
    try:
        resp = requests.get(
            CERTSPOTTER_URL,
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    names = set()
    for entry in data:
        for n in entry.get("dns_names", []) or []:
            n = n.strip().lower().lstrip("*.")
            if n and domain.lower() in n:
                names.add(n)
    return sorted(names)


_SUBDOMAIN_RE_CACHE: dict[str, "re.Pattern"] = {}


def _subdomain_regex(domain: str):
    pattern = _SUBDOMAIN_RE_CACHE.get(domain)
    if pattern is None:
        escaped = re.escape(domain.lower())
        pattern = re.compile(rf"(?:[a-z0-9_-]+\.)+{escaped}", re.IGNORECASE)
        _SUBDOMAIN_RE_CACHE[domain] = pattern
    return pattern


def _extract_subdomain_strings(obj, domain: str, found: set):
    """Recorre cualquier estructura JSON (dict/list/str anidados) buscando
    strings con pinta de subdominio del dominio objetivo. Se usa para
    DNSDumpster porque su API es de pago y no he podido verificar el
    esquema exacto de respuesta contra una key real; esto es robusto
    independientemente de como se llamen los campos."""
    if isinstance(obj, str):
        for m in _subdomain_regex(domain).finditer(obj.lower()):
            found.add(m.group(0))
    elif isinstance(obj, dict):
        for v in obj.values():
            _extract_subdomain_strings(v, domain, found)
    elif isinstance(obj, list):
        for v in obj:
            _extract_subdomain_strings(v, domain, found)


def search_dnsdumpster(domain: str, api_key: str, timeout: int = 20) -> list[str]:
    """Subdominios via la API oficial de DNSDumpster (de pago/registro,
    api.dnsdumpster.com). El parseo es deliberadamente generico (busca
    cualquier string con pinta de subdominio en toda la respuesta) porque
    es una API de pago cuyo esquema exacto no se puede verificar sin una
    key real; asi funciona igual si cambian los nombres de los campos."""
    try:
        resp = requests.get(
            DNSDUMPSTER_URL.format(domain=domain),
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    found: set = set()
    _extract_subdomain_strings(data, domain, found)
    found.discard(domain.lower())
    return sorted(found)


def search_wayback(domain: str, timeout: int = 20, limit: int = 2000) -> list[str]:
    """URLs archivadas por Wayback Machine bajo el dominio, filtradas a las
    que tengan pinta de haber sido sensibles (backups, configs, paneles...).
    Sin este filtro Wayback devuelve miles de URLs normales sin valor.
    Gratis, sin api key."""
    try:
        resp = requests.get(
            WAYBACK_CDX_URL,
            params={
                "url": f"{domain}/*", "output": "json", "limit": limit,
                "collapse": "urlkey", "filter": "statuscode:200",
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, ValueError):
        return []

    if len(rows) < 2:
        return []

    header = rows[0]
    url_idx = header.index("original") if "original" in header else 2
    urls = {row[url_idx] for row in rows[1:] if len(row) > url_idx}

    interesting = []
    for url in urls:
        path = url.lower()
        if (SUSPICIOUS_FILENAME_RE.search(path)
                or path.endswith(SENSITIVE_WAYBACK_EXTENSIONS)
                or any(hint in path for hint in WAYBACK_PATH_HINTS)):
            interesting.append(url)
    return sorted(interesting)


VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# el tier gratuito de VirusTotal limita a 4 peticiones/minuto (500/dia):
# se espacian las llamadas para no recibir 429, igual que ya se hace con
# la NVD en vuln_lookup.py
_VT_MIN_INTERVAL = 16.0
_last_vt_call = 0.0


def _vt_throttle():
    global _last_vt_call
    wait = _VT_MIN_INTERVAL - (time.monotonic() - _last_vt_call)
    if wait > 0:
        time.sleep(wait)
    _last_vt_call = time.monotonic()


def virustotal_domain_report(domain: str, api_key: str | None, timeout: int = 20) -> dict | None:
    """Reputacion del dominio en VirusTotal: cuantos motores antivirus/
    antiphishing lo marcan malicioso, categorias detectadas, puntuacion de
    la comunidad. Requiere api key propia (hay tier gratuito). None si no
    hay key o la peticion falla."""
    if not api_key:
        return None
    _vt_throttle()
    try:
        resp = requests.get(
            VT_DOMAIN_URL.format(domain=domain),
            headers={"x-apikey": api_key}, timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
    except (requests.RequestException, ValueError):
        return None
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "categories": list((attrs.get("categories") or {}).values()),
    }


def virustotal_ip_report(ip: str, api_key: str | None, timeout: int = 20) -> dict | None:
    """Igual que virustotal_domain_report pero para una IP: ademas incluye
    el propietario del rango (AS) y el pais, utiles para contextualizar un
    hosting compartido/sospechoso."""
    if not api_key:
        return None
    _vt_throttle()
    try:
        resp = requests.get(
            VT_IP_URL.format(ip=ip),
            headers={"x-apikey": api_key}, timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
    except (requests.RequestException, ValueError):
        return None
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
    }


def abuseipdb_report(ip: str, api_key: str | None, timeout: int = 15) -> dict | None:
    """Reputacion de la IP en AbuseIPDB: puntuacion de confianza de abuso
    (0-100) acumulada de reportes de la comunidad (botnets, spam, escaneos
    de puertos, fuerza bruta...). Requiere api key propia (hay tier
    gratuito). None si no hay key o la peticion falla."""
    if not api_key:
        return None
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data") or {}
    except (requests.RequestException, ValueError):
        return None
    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "is_whitelisted": data.get("isWhitelisted"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "last_reported_at": data.get("lastReportedAt"),
    }
