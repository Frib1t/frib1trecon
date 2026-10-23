"""
Descubrimiento de subdominios por fuerza bruta DNS con una lista corta de
etiquetas habituales (www, mail, admin, dev...). No necesita api keys: solo
resuelve nombres. Si el dominio tiene DNS wildcard (cualquier nombre resuelve),
se descarta la IP comodin para no devolver falsos positivos.
"""
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

LABELS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ns", "ns1", "ns2", "dns",
    "mx", "mx1", "mx2", "admin", "administrator", "panel", "cpanel", "whm", "webdisk", "autodiscover",
    "autoconfig", "api", "app", "apps", "dev", "devel", "development", "test", "testing", "qa",
    "stage", "staging", "preprod", "pre", "demo", "beta", "sandbox", "uat", "old", "new", "backup",
    "bak", "static", "cdn", "assets", "img", "images", "media", "files", "upload", "uploads",
    "download", "downloads", "docs", "doc", "wiki", "help", "support", "blog", "news", "shop",
    "store", "tienda", "web", "web1", "web2", "portal", "intranet", "extranet", "vpn", "remote",
    "owa", "exchange", "mail2", "lists", "list", "newsletter", "marketing", "crm", "erp", "hr",
    "login", "auth", "sso", "accounts", "account", "my", "secure", "ssl", "git", "gitlab", "svn",
    "jenkins", "ci", "build", "jira", "confluence", "monitor", "monitoring", "grafana", "status",
    "stats", "analytics", "db", "database", "mysql", "sql", "redis", "elastic", "kibana", "proxy",
    "gateway", "gw", "router", "ftp2", "server", "srv", "host", "cloud", "m", "mobile", "wap",
    "en", "es", "fr", "de", "eu", "shop2", "pay", "payments", "cart", "order", "orders",
    "control", "plataforma", "platform", "client", "clients", "cliente", "clientes", "partner",
    "partners", "agricultores", "api2", "v1", "v2", "stream", "video", "chat", "forum", "foro",
]

MAX_WORKERS = 30


def _resolve(name: str) -> str | None:
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None


def bruteforce_subdomains(domain: str, labels: list[str] | None = None) -> list[str]:
    """Subdominios de `domain` que resuelven a DNS, sin comodines."""
    labels = labels or LABELS
    wildcard_ip = _resolve(f"{secrets.token_hex(8)}.{domain}")
    candidates = [f"{label}.{domain}" for label in labels]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(_resolve, candidates))
    found = []
    for name, ip in zip(candidates, results):
        if ip and ip != wildcard_ip:
            found.append(name)
    return sorted(set(found))
