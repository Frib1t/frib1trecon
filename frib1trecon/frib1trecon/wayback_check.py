"""
Comprueba si las URLs archivadas en Wayback siguen respondiendo y marca las que
llevan parametros sensibles en la query (lista de active.py, de los repos del
autor). Una peticion HEAD/GET por URL, con tope de URLs.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

from . import http_client

MAX_CHECK = 100
WORKERS = 10
TIMEOUT = 8
SENSITIVE_PARAMS = {
    "id", "q", "search", "upload", "query", "page", "user", "username", "email", "uploads",
    "cat", "category", "dir", "file", "download", "path", "url", "redirect", "next", "downloads",
    "action", "do", "cmd", "exec", "command", "load", "include", "view", "commands", "module",
    "lang", "language", "ref", "return", "back", "to", "go",
}


def _sensitive_params(url: str) -> list[str]:
    query = urlparse(url).query
    return sorted(k for k in parse_qs(query) if k.lower() in SENSITIVE_PARAMS)


def _live(url: str):
    r = http_client.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True)
    if r is None:
        return None
    status = r.status_code
    r.close()
    return status


def check_wayback_live(urls: list[str]) -> list[tuple[str, int, list[str]]]:
    candidates = [(u, _sensitive_params(u)) for u in urls]
    candidates = [(u, p) for u, p in candidates if p][:MAX_CHECK]
    if not candidates:
        return []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        statuses = list(ex.map(lambda c: _live(c[0]), candidates))
    return [(u, st, p) for (u, p), st in zip(candidates, statuses) if st and st < 400]
