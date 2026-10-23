"""
Cliente HTTP para las comprobaciones activas (rutas, CMS, takeover, Wayback,
cabeceras, buckets). Cada peticion sale con un User-Agent y Accept-Language
elegidos al azar de una lista realista, con una pausa aleatoria previa y un
tope de peticiones simultaneas. Asi no salen todas identicas ni en rafaga.
Las APIs de terceros (VirusTotal, Shodan...) usan su propia autenticacion y no
pasan por aqui.
"""
import random
import threading
import time

import requests

from .ua import ACCEPT_LANGUAGES, USER_AGENTS

MIN_DELAY = 0.4
MAX_DELAY = 1.6
MAX_IN_FLIGHT = 4

_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT)


def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
    }


def request(method: str, url: str, timeout: int = 8, allow_redirects: bool = False,
            stream: bool = False, jitter: bool = True, **kwargs):
    """Peticion con cabeceras aleatorias, pausa previa y tope de concurrencia.
    Devuelve None si falla la conexion."""
    if jitter:
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    headers = random_headers()
    headers.update(kwargs.pop("headers", {}) or {})
    with _slots:
        try:
            return requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects,
                                    stream=stream, headers=headers, **kwargs)
        except requests.RequestException:
            return None


def get(url: str, **kwargs):
    return request("GET", url, **kwargs)


def head(url: str, **kwargs):
    return request("HEAD", url, **kwargs)
