"""
Postura DNS y WHOIS del dominio objetivo: registros NS/MX/TXT/CAA,
autenticacion de correo (SPF/DKIM/DMARC), DNSSEC, intento de transferencia
de zona (AXFR) y datos de registro WHOIS (registrador, fechas,
nameservers). Todo pasivo o activo-no-intrusivo: son las mismas consultas
DNS que hace cualquier resolver, y un intento de AXFR solo revela si el
servidor esta mal configurado (si lo deniega, que es lo correcto, no pasa
nada; si lo permite, es un hallazgo real que merece reportarse).

DKIM se verifica contra una lista de selectores comunes via DNS (sin API
de pago tipo DomScan): no es exhaustivo, pero no cuesta nada y detecta los
proveedores de correo mas habituales (Google Workspace, Microsoft 365,
Mailchimp, SendGrid...).
"""
import re
import shutil
import socket
import subprocess

try:
    import dns.query
    import dns.resolver
    import dns.zone
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

WHOIS_BIN = shutil.which("whois")
DNS_TIMEOUT = 8

# selectores DKIM mas comunes (Google Workspace, M365, Mailchimp,
# SendGrid, Zoho, Amazon SES...) - verificacion gratuita via DNS, sin la
# cobertura completa que daria una API de pago pero sin coste ni api key
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "dkim", "mail",
    "smtp", "s1", "s2", "mandrill", "mx", "email", "zoho", "amazonses",
]


def _resolver():
    if not DNS_AVAILABLE:
        return None
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def get_dns_records(domain: str) -> dict:
    """NS/MX/TXT/CAA del dominio. Listas vacias si dnspython no esta
    instalado o el tipo de registro no existe."""
    resolver = _resolver()
    records = {"NS": [], "MX": [], "TXT": [], "CAA": []}
    if not resolver:
        return records
    for rtype in ("NS", "MX", "TXT", "CAA"):
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                records[rtype].append(str(rdata).strip('"').rstrip("."))
        except Exception:
            continue
    return records


def check_spf(domain: str) -> dict:
    """Registro SPF publicado y problemas comunes de configuracion."""
    result = {"present": False, "record": None, "issues": []}
    resolver = _resolver()
    if not resolver:
        result["issues"].append("dnspython no instalado")
        return result
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.lower().startswith("v=spf1"):
                result["present"] = True
                result["record"] = txt
                if "+all" in txt:
                    result["issues"].append(
                        "Mecanismo '+all': cualquier servidor puede enviar correo "
                        "en nombre del dominio (critico)")
                elif "?all" in txt:
                    result["issues"].append("Mecanismo '?all' (neutral), no aplica politica real")
                elif "~all" in txt:
                    result["issues"].append("Mecanismo '~all' (softfail), recomendable migrar a '-all'")
                elif "-all" not in txt:
                    result["issues"].append("Sin mecanismo 'all' explicito al final del registro")
                break
        if not result["present"]:
            result["issues"].append("No existe registro SPF publicado")
    except Exception as e:
        result["issues"].append(f"No se pudo resolver TXT: {e}")
    return result


def check_dmarc(domain: str) -> dict:
    """Registro DMARC (_dmarc.<dominio>), su politica y problemas comunes."""
    result = {"present": False, "record": None, "policy": None, "issues": []}
    resolver = _resolver()
    if not resolver:
        result["issues"].append("dnspython no instalado")
        return result
    fqdn = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(fqdn, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.lower().startswith("v=dmarc1"):
                result["present"] = True
                result["record"] = txt
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("p="):
                        result["policy"] = part.split("=", 1)[1].strip()
                if result["policy"] == "none":
                    result["issues"].append("Politica 'p=none': solo monitoreo, no bloquea correo falsificado")
                elif result["policy"] == "quarantine":
                    result["issues"].append("Politica 'p=quarantine': mejorable a 'p=reject'")
                elif result["policy"] is None:
                    result["issues"].append("Registro DMARC sin politica 'p=' definida")
                if "rua=" not in txt.lower():
                    result["issues"].append("Sin direccion de reporting agregado (rua=) configurada")
                break
        if not result["present"]:
            result["issues"].append("No existe registro DMARC publicado")
    except Exception as e:
        result["issues"].append(f"No se encontro _dmarc.{domain}: {e}")
    return result


def check_dkim(domain: str) -> dict:
    """Prueba selectores DKIM comunes via DNS. No exhaustivo (eso requiere
    una API de pago tipo DomScan), pero gratuito y cubre los proveedores
    de correo mas habituales."""
    result = {"selectors_found": []}
    resolver = _resolver()
    if not resolver:
        return result
    for sel in COMMON_DKIM_SELECTORS:
        fqdn = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(fqdn, "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="ignore")
                if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                    result["selectors_found"].append(sel)
                    break
        except Exception:
            continue
    return result


def check_dnssec(domain: str) -> dict:
    """DNSSEC habilitado (presencia de DNSKEY o DS)."""
    result = {"enabled": False, "details": None}
    resolver = _resolver()
    if not resolver:
        return result
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        if answers:
            result["enabled"] = True
            result["details"] = f"{len(answers)} DNSKEY encontrada(s)"
            return result
    except Exception:
        pass
    try:
        ds = resolver.resolve(domain, "DS")
        if ds:
            result["enabled"] = True
            result["details"] = "Registro DS presente"
    except Exception:
        result["details"] = "Sin DNSKEY/DS: DNSSEC no habilitado"
    return result


def check_zone_transfer(domain: str, nameservers: list[str]) -> dict:
    """Intenta AXFR contra cada NS del dominio: si alguno lo permite, es
    un fallo de configuracion critico (expone TODA la zona DNS: todos los
    subdominios y hosts internos de un tiron). Lo normal y correcto es que
    todos lo denieguen."""
    result = {"vulnerable_ns": [], "tested_ns": nameservers}
    if not DNS_AVAILABLE:
        return result
    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=DNS_TIMEOUT, lifetime=DNS_TIMEOUT))
            if zone:
                result["vulnerable_ns"].append(ns)
        except Exception:
            continue
    return result


_WHOIS_PATTERNS = {
    "registrar": r"(?im)^\s*Registrar:\s*(.+)$",
    "creation_date": r"(?im)^\s*(?:Creation Date|created|Domain Registration Date):\s*(.+)$",
    "expiry_date": r"(?im)^\s*(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till):\s*(.+)$",
    "updated_date": r"(?im)^\s*(?:Updated Date|Last Updated|changed):\s*(.+)$",
    "registrant_org": r"(?im)^\s*Registrant Organization:\s*(.+)$",
    "registrant_country": r"(?im)^\s*Registrant Country:\s*(.+)$",
}


def whois_lookup(domain: str, timeout: int = 15) -> dict:
    """Datos de registro via el comando `whois` del sistema (sin libreria
    extra, casi todas las distros Linux ya lo traen). Parseo best-effort
    de los campos mas comunes (el formato exacto varia por TLD/
    registrador, muchos registrant_* salen redactados por GDPR/privacidad
    desde 2018, eso es normal y no es un fallo del parser)."""
    result = {
        "registrar": None, "creation_date": None, "expiry_date": None,
        "updated_date": None, "nameservers": [], "registrant_org": None,
        "registrant_country": None,
    }
    if not WHOIS_BIN:
        return result
    try:
        out = subprocess.run(
            [WHOIS_BIN, domain], capture_output=True, text=True, timeout=timeout)
        raw = out.stdout
    except (subprocess.SubprocessError, OSError):
        return result
    if not raw:
        return result

    for field, pattern in _WHOIS_PATTERNS.items():
        m = re.search(pattern, raw)
        if m:
            result[field] = m.group(1).strip()
    result["nameservers"] = sorted(set(
        ns.strip().rstrip(".").lower()
        for ns in re.findall(r"(?im)^\s*Name Server:\s*(.+)$", raw)
    ))
    return result
