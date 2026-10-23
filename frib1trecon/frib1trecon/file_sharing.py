"""
Exposicion de ficheros compartidos: busca en el historico publico de la web
(Wayback CDX + urlscan.io, ambos gratis y sin api key) URLs de ficheros con
pinta sensible (backups, copias de BD, claves, configs...) bajo el dominio y
sus subdominios, y comprueba cuales siguen accesibles HOY. Solo se devuelven
los que siguen vivos: uno que ya no responde no es una exposicion actual.
"""
import re
from urllib.parse import urlparse

import requests

from . import http_client

HTTP_TIMEOUT = 15
MAX_CHECKS = 80

SENSITIVE_EXT = {
    "sql", "bak", "backup", "dump", "db", "sqlite", "mdb",
    "env", "conf", "config", "ini", "yml", "yaml",
    "log", "pem", "key", "pfx", "p12", "ppk", "ovpn", "kdbx",
    "zip", "tar", "gz", "tgz", "7z", "rar",
}
OFFICE_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx", "txt"}
SENSITIVE_NAME = re.compile(
    r"(client|customer|emplead|employee|nomin|payroll|salar|usuari|user|"
    r"password|passwd|credencial|credential|confiden|personal|dni|nif|iban|backup|dump|export)",
    re.IGNORECASE,
)


def _classify(url: str) -> str | None:
    path = urlparse(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in SENSITIVE_EXT:
        return "sensitive"
    if ext in OFFICE_EXT:
        return "sensitive" if SENSITIVE_NAME.search(path) else "office"
    return None


def _wayback_file_urls(domain: str) -> set[str]:
    urls = set()
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": domain, "matchType": "domain", "output": "json",
                    "fl": "original", "collapse": "urlkey", "limit": 5000},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            rows = r.json()
            for row in rows[1:] if rows and isinstance(rows[0], list) else []:
                if row and row[0]:
                    urls.add(row[0])
    except (requests.RequestException, ValueError):
        pass
    return urls


def _urlscan_file_urls(domain: str) -> set[str]:
    urls = set()
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 1000},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            for res in (r.json() or {}).get("results", []):
                u = (res.get("page", {}) or {}).get("url") or (res.get("task", {}) or {}).get("url")
                if u:
                    urls.add(u)
    except (requests.RequestException, ValueError):
        pass
    return urls


def _is_live(url: str) -> bool:
    r = http_client.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
    if r is not None and r.status_code == 405:
        r = http_client.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, stream=True)
        if r is not None:
            r.close()
    return r is not None and r.status_code in (200, 206)


def find_exposed_files(domain: str) -> list[dict]:
    """Ficheros con pinta sensible, archivados historicamente, que SIGUEN
    accesibles hoy. Gratis, sin api key (Wayback CDX + urlscan.io)."""
    all_urls = _wayback_file_urls(domain) | _urlscan_file_urls(domain)
    sensitive = sorted({u for u in all_urls if _classify(u) == "sensitive"})
    out = []
    for url in sensitive[:MAX_CHECKS]:
        if _is_live(url):
            out.append({"url": url})
    return out
