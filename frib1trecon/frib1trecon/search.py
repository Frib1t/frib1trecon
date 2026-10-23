"""
Cliente de busqueda contra una (o varias) instancias SearXNG.

Nunca golpeamos Google/Bing directamente: SearXNG hace de intermediario y
agrega varios motores. Aun asi, aplicamos buenas practicas para no abusar
de tu propia instancia ni de los motores que consulta por detras:

  - User-Agent y Accept-Language aleatorios en cada peticion
  - delay aleatorio (jitter) entre peticiones
  - backoff exponencial + circuit breaker ante fallos/429/403 repetidos
  - rotacion opcional entre varios endpoints SearXNG y/o proxies
"""
import random
import time
from dataclasses import dataclass, field

import requests

from .ua import random_headers


@dataclass
class SearchResult:
    title: str
    url: str
    content: str
    engine: str
    query: str


class TooManyFailures(RuntimeError):
    pass


@dataclass
class SearxngClient:
    endpoints: list[str] = field(default_factory=lambda: ["http://127.0.0.1:8080"])
    proxies: list[str] | None = None
    min_delay: float = 2.5
    max_delay: float = 6.0
    timeout: int = 15
    max_retries: int = 4
    max_consecutive_failures: int = 6

    def __post_init__(self):
        self._endpoint_cycle = list(self.endpoints)
        random.shuffle(self._endpoint_cycle)
        self._idx = 0
        self._consecutive_failures = 0

    def _next_endpoint(self) -> str:
        ep = self._endpoint_cycle[self._idx % len(self._endpoint_cycle)]
        self._idx += 1
        return ep

    def _next_proxy(self):
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def _jitter_sleep(self, base: float | None = None):
        low = base if base is not None else self.min_delay
        high = (base * 1.8) if base is not None else self.max_delay
        time.sleep(random.uniform(low, high))

    def search(self, query: str, categories: str | None = None) -> list[SearchResult]:
        """Lanza una consulta y devuelve resultados. Lista vacia si fallan todos los reintentos."""
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            endpoint = self._next_endpoint()
            params = {"q": query, "format": "json"}
            if categories:
                params["categories"] = categories

            try:
                resp = requests.get(
                    f"{endpoint.rstrip('/')}/search",
                    params=params,
                    headers=random_headers(),
                    proxies=self._next_proxy(),
                    timeout=self.timeout,
                )
                if resp.status_code == 429 or resp.status_code == 403:
                    last_error = f"HTTP {resp.status_code}"
                    self._consecutive_failures += 1
                    self._backoff_and_check(attempt)
                    continue

                resp.raise_for_status()
                data = resp.json()
                self._consecutive_failures = 0

                results = [
                    SearchResult(
                        title=item.get("title", ""),
                        url=item.get("url", ""),
                        content=item.get("content", ""),
                        engine=item.get("engine", "unknown"),
                        query=query,
                    )
                    for item in data.get("results", [])
                ]

                self._jitter_sleep()
                return results

            except (requests.RequestException, ValueError) as exc:
                last_error = str(exc)
                self._consecutive_failures += 1
                self._backoff_and_check(attempt)
                continue

        print(f"[!] Fallo consultando '{query}' tras {self.max_retries} intentos ({last_error})")
        return []

    def _backoff_and_check(self, attempt: int):
        if self._consecutive_failures >= self.max_consecutive_failures:
            raise TooManyFailures(
                f"{self._consecutive_failures} fallos consecutivos: "
                "revisa que SearXNG este arriba (docker compose ps) o baja el ritmo."
            )
        backoff = (2 ** attempt) + random.uniform(0, 1.5)
        time.sleep(backoff)
