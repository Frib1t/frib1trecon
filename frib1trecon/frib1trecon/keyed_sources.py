"""
Fuentes que necesitan credenciales propias del usuario: Censys, FOFA, HIBP,
DomScan y OTX. Ninguna clave va en el codigo: llegan por parametro (CLI o web)
o por variable de entorno, y si no estan la fuente simplemente se omite.
"""
import base64
import time
from urllib.parse import quote_plus

import requests

TIMEOUT = 20
HIBP_SPACING = 6.5  # HIBP limita las consultas por cuenta; se espacian


def censys_hosts(domain: str, api_id: str, api_secret: str) -> list[dict]:
    """Hosts de Censys cuyo certificado o DNS cita el dominio: [{ip, ports}]."""
    try:
        r = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": f"dns.names: {domain}", "per_page": 50},
            auth=(api_id, api_secret), timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return []
        hits = r.json().get("result", {}).get("hits", [])
    except (requests.RequestException, ValueError):
        return []
    out = []
    for h in hits:
        ports = sorted({s.get("port") for s in h.get("services", []) if s.get("port")})
        out.append({"ip": h.get("ip", ""), "ports": ports})
    return out


def fofa_search(domain: str, email: str, key: str) -> list[dict]:
    """Resultados de FOFA para domain="dominio": [{ip, host, port}]."""
    query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    try:
        r = requests.get(
            "https://fofa.info/api/v1/search/all",
            params={"email": email, "key": key, "qbase64": query,
                    "fields": "ip,host,port", "size": 100},
            timeout=TIMEOUT,
        )
        data = r.json()
    except (requests.RequestException, ValueError):
        return []
    if data.get("error"):
        return []
    return [{"ip": row[0], "host": row[1], "port": row[2]}
            for row in data.get("results", []) if len(row) >= 3]


def hibp_breaches(email: str, key: str) -> list[str] | None:
    """Brechas en las que aparece la cuenta. [] si no aparece, None si la clave no vale."""
    time.sleep(HIBP_SPACING)
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}",
            headers={"hibp-api-key": key, "user-agent": "frib1trecon"},
            params={"truncateResponse": "false"}, timeout=TIMEOUT,
        )
    except requests.RequestException:
        return None
    if r.status_code == 404:
        return []
    if r.status_code != 200:
        return None
    return [b.get("Name", "") for b in r.json()]


def domscan_dkim(domain: str, key: str) -> list[str] | None:
    """Selectores DKIM encontrados por DomScan. None si la API no responde bien."""
    try:
        r = requests.get("https://domscan.net/v1/tools/dkim/discover",
                         headers={"X-API-Key": key, "Accept": "application/json"},
                         params={"domain": domain}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        payload = r.json()
    except (requests.RequestException, ValueError):
        return None
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    for k in ("found", "selectors_found", "selectors", "results", "discovered"):
        val = data.get(k) if isinstance(data, dict) else None
        if isinstance(val, list):
            return [x if isinstance(x, str) else str(x.get("selector", "")) for x in val if x]
    return []


def otx_passive_dns(domain: str, api_key: str) -> tuple[set[str], set[str]]:
    """Subdominios e IPs que AlienVault OTX ha visto resolver historicamente
    para el dominio (DNS pasivo: consulta la base de OTX, no al objetivo).
    Gratis con api key. Devuelve (hosts, ips); vacios si la clave no vale."""
    hosts, ips = set(), set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers={"X-OTX-API-KEY": api_key}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return hosts, ips
        for rec in (r.json() or {}).get("passive_dns", []) or []:
            h = (rec.get("hostname") or "").lower().strip().rstrip(".")
            if h and (h == domain.lower() or h.endswith("." + domain.lower())):
                hosts.add(h)
            ip = (rec.get("address") or "").strip()
            if ip and (all(c in "0123456789." for c in ip) or ":" in ip):
                ips.add(ip)
    except (requests.RequestException, ValueError):
        pass
    return hosts, ips
