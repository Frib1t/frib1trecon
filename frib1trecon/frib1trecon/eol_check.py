"""
Comprobacion de fin de soporte (EOL, "end of life") de tecnologias
detectadas: cruza producto + version contra la API publica y gratuita de
endoflife.date (sin api key) para saber si esa version ya no recibe
parches de seguridad del fabricante.
"""
import datetime

import requests

EOL_API = "https://endoflife.date/api/{product}.json"
HTTP_TIMEOUT = 15

# Nombres de producto tal como los devuelve el fingerprinting (whatweb,
# minusculas) -> slug real de endoflife.date.
PRODUCT_SLUG_MAP = {
    "apache": "apache", "apache httpd": "apache", "nginx": "nginx",
    "openssh": "openssh", "php": "php", "mysql": "mysql",
    "postgresql": "postgresql", "microsoft-iis": "iis", "iis": "iis",
    "wordpress": "wordpress", "openssl": "openssl", "exim": "exim",
    "postfix": "postfix", "windows server": "windows-server",
    "ubuntu": "ubuntu", "debian": "debian", "drupal": "drupal",
    "joomla": "joomla", "python": "python", "nodejs": "nodejs",
    "node.js": "nodejs", "django": "django", "laravel": "laravel",
    "redis": "redis", "mongodb": "mongodb", "mariadb": "mariadb",
    "tomcat": "tomcat", "jquery": "jquery",
}


def check_eol(product: str, version: str, timeout: int = HTTP_TIMEOUT) -> dict | None:
    """Busca el ciclo de vida de `product`/`version` en endoflife.date.
    Devuelve None si el producto no esta mapeado, no hay version, o la
    API no responde/no tiene ese ciclo (best-effort, nunca lanza
    excepcion para no romper el resto del escaneo)."""
    slug = PRODUCT_SLUG_MAP.get(product.lower().strip()) if product else None
    if not slug or not version:
        return None
    try:
        r = requests.get(EOL_API.format(product=slug), timeout=timeout)
        if r.status_code != 200:
            return None
        cycles = r.json()
    except (requests.RequestException, ValueError):
        return None

    major_minor = ".".join(version.split(".")[:2])
    for cycle in cycles:
        cycle_name = str(cycle.get("cycle"))
        if version.startswith(cycle_name) or major_minor.startswith(cycle_name):
            eol = cycle.get("eol")
            # "eol" es `false` (sin fecha de EOL comprometida) o una fecha
            # "YYYY-MM-DD" (puede ser futura: significa "dejara de tener
            # soporte en esa fecha", NO que ya lo haya perdido). Solo es
            # EOL de verdad si esa fecha ya ha pasado.
            is_eol = False
            if isinstance(eol, str):
                try:
                    is_eol = datetime.date.fromisoformat(eol) <= datetime.date.today()
                except ValueError:
                    is_eol = True
            elif eol is True:
                is_eol = True
            return {
                "product": product, "version": version, "cycle": cycle_name,
                "eol_date": eol, "is_eol": is_eol, "latest": cycle.get("latest"),
            }
    return None
