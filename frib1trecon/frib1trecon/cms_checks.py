"""
Comprobaciones especificas de CMS: WordPress, Drupal, Joomla y Liferay.

Basadas en las comprobaciones de los repositorios de referencia (wp_recon,
Liferayrc): solo peticiones GET/HEAD de lectura a rutas publicas conocidas.
Ninguna prueba de explotacion ni fuerza bruta de credenciales.

Cada comprobacion distingue soft-404: si el servidor responde 200 a cualquier
ruta, se compara el cuerpo contra una ruta inexistente y se descarta.
"""
import hashlib
import random
import re
import string

import requests

from . import http_client

TIMEOUT = 8
UA = {"User-Agent": "Mozilla/5.0"}
IP_INTERNA = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")


def _get(url: str, allow_redirects: bool = False, method: str = "GET"):
    return http_client.request(method, url, timeout=TIMEOUT, allow_redirects=allow_redirects)


def _baseline(base: str):
    """Firma de una pagina inexistente (soft-404)."""
    rnd = "no-existe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    r = _get(f"{base}/{rnd}")
    if r is None:
        return None
    return r.status_code, hashlib.sha256(r.content or b"").hexdigest()


def _is_soft404(r, baseline) -> bool:
    if baseline is None or r is None:
        return False
    return r.status_code == 200 and baseline[0] == 200 and baseline[1] == hashlib.sha256(r.content or b"").hexdigest()


def _check(base, path, baseline, pattern=None, method="GET"):
    """Devuelve la respuesta si la ruta existe de verdad (200, no soft-404, firma valida)."""
    r = _get(f"{base}{path}", method=method)
    if r is None or r.status_code != 200 or _is_soft404(r, baseline):
        return None
    if pattern and not re.search(pattern, r.text or "", flags=re.MULTILINE | re.IGNORECASE):
        return None
    return r


# ---------------------------------------------------------------- WordPress

def wordpress(base: str) -> dict:
    """{'techs': {nombre: version}, 'hits': [(path, descripcion, detalle)]}"""
    techs, hits = {}, []
    baseline = _baseline(base)

    r = _check(base, "/wp-json/wp/v2/users", baseline, pattern=r'"slug"')
    if r:
        slugs = re.findall(r'"slug":"([^"]*)"', r.text)
        hits.append(("/wp-json/wp/v2/users", "Enumeracion de usuarios WordPress (REST API)",
                     f"usuarios: {', '.join(slugs)}"))

    for n in range(1, 4):
        r = _get(f"{base}/?author={n}")
        if r is not None and r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            m = re.search(r"/author/([^/]+)/?", loc)
            if m:
                hits.append((f"/?author={n}", "Enumeracion de usuarios WordPress (?author=)", f"slug: {m.group(1)}"))

    r = _check(base, "/readme.html", baseline, pattern=r"WordPress")
    if r:
        m = re.search(r"Version\s+(\d+(?:\.\d+)+)", r.text)
        if m:
            techs["WordPress"] = m.group(1)

    r = _check(base, "/license.txt", baseline, pattern=r"wordpress")
    if r and "WordPress" not in techs:
        techs.setdefault("WordPress", "")

    r = _check(base, "/wp-json/oembed/1.0/embed?url=" + base + "/", baseline, pattern=r"provider_name|html")
    if r:
        hits.append(("/wp-json/oembed/1.0/embed", "oEmbed accesible (posible SSRF si no esta restringido)", "respuesta 200"))

    r = _check(base, "/wp-json/wp/v2/pages", baseline, pattern=r'"id"')
    if r:
        ips = sorted(set(IP_INTERNA.findall(r.text)))
        if ips:
            hits.append(("/wp-json/wp/v2/pages", "IPs internas en el contenido publico", ", ".join(ips)))

    for path in ("/wp-cli.phar", "/tools/wp-cli.phar", "/bin/wp-cli.phar"):
        r = _get(f"{base}{path}", method="GET")
        if r is not None and r.status_code == 200 and not _is_soft404(r, baseline) and r.content[:2] == b"PK":
            hits.append((path, "wp-cli.phar expuesto", "binario accesible"))
            break

    r = _check(base, "/wp-sitemap-users-1.xml", baseline, pattern=r"<urlset|<sitemapindex")
    if r:
        hits.append(("/wp-sitemap-users-1.xml", "Sitemap de usuarios WordPress", "listado de autores publico"))
    return {"techs": techs, "hits": hits}


# ---------------------------------------------------------------- Drupal

def drupal(base: str) -> dict:
    techs, hits = {}, []
    baseline = _baseline(base)
    for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
        r = _check(base, path, baseline, pattern=r"Drupal")
        if r:
            m = re.search(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", r.text)
            if m:
                techs["Drupal"] = m.group(1)
                break
    if "Drupal" not in techs:
        techs.setdefault("Drupal", "")

    for path, desc, pattern in (
        ("/update.php", "update.php accesible", r"Drupal|update"),
        ("/core/install.php", "Instalador de Drupal accesible", r"Drupal|install"),
        ("/install.php", "Instalador de Drupal accesible", r"Drupal|install"),
        ("/user/login", "Login de Drupal accesible", r"user-login|Log in|Iniciar"),
    ):
        r = _check(base, path, baseline, pattern=pattern)
        if r:
            hits.append((path, desc, "respuesta 200"))

    r = _check(base, "/jsonapi", baseline, pattern=r"jsonapi")
    if r:
        hits.append(("/jsonapi", "JSON:API de Drupal publica", "respuesta 200"))

    r = _check(base, "/sites/default/files/", baseline, pattern=r"Index of|<title>Index")
    if r:
        hits.append(("/sites/default/files/", "Listado de directorio de ficheros de Drupal", "Index of"))
    return {"techs": techs, "hits": hits}


# ---------------------------------------------------------------- Joomla

def joomla(base: str) -> dict:
    techs, hits = {}, []
    baseline = _baseline(base)

    r = _check(base, "/administrator/manifests/files/joomla.xml", baseline, pattern=r"<version>")
    if r:
        m = re.search(r"<version>\s*(\d+(?:\.\d+)+)\s*</version>", r.text)
        techs["Joomla"] = m.group(1) if m else ""

    r = _check(base, "/README.txt", baseline, pattern=r"Joomla")
    if r and "Joomla" not in techs:
        m = re.search(r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)", r.text)
        techs["Joomla"] = m.group(1) if m else ""

    if "Joomla" not in techs and _check(base, "/media/system/js/", baseline, pattern=None):
        techs["Joomla"] = ""

    r = _check(base, "/administrator/", baseline, pattern=r"Joomla")
    if r:
        hits.append(("/administrator/", "Panel de administracion de Joomla accesible", "login visible"))

    for path in ("/configuration.php~", "/configuration.php.bak", "/configuration.php.old"):
        r = _check(base, path, baseline, pattern=r"\$(password|user|db)\s*=")
        if r:
            hits.append((path, "Copia de configuration.php de Joomla (credenciales de BD)", "fichero accesible"))
            break
    return {"techs": techs, "hits": hits}


# ---------------------------------------------------------------- Liferay

LIFERAY_PATHS = [
    ("/api/jsonws", r"JSON Web Services|jsonws", "API JSON de Liferay (jsonws)"),
    ("/o/graphql", r"graphql|GraphQL", "GraphQL de Liferay"),
    ("/o/api", r"swagger|openapi|API", "API explorer de Liferay"),
    ("/c/portal/license", r"License|license", "Informacion de licencia y servidor de Liferay"),
    ("/web/guest", None, "Perfil invitado de Liferay"),
    ("/group/control_panel/manage", r"Control Panel|Panel de control|Login", "Panel de control de Liferay"),
]


def liferay(base: str) -> dict:
    hits = []
    baseline = _baseline(base)
    for path, pattern, desc in LIFERAY_PATHS:
        r = _check(base, path, baseline, pattern=pattern)
        if r:
            hits.append((path, desc, "respuesta 200"))
    return {"techs": {}, "hits": hits}


# ---------------------------------------------------------------- orquestacion

CHECKS = {
    "WordPress": wordpress,
    "Drupal": drupal,
    "Joomla": joomla,
    "Liferay": liferay,
}


def run_cms_checks(domain: str, detected: dict) -> dict:
    """Ejecuta las comprobaciones de cada CMS detectado (nombre base, sin plugins).
    Devuelve {'techs': {...}, 'hits': [(cms, path, desc, detalle)]}."""
    base = None
    for scheme in ("https", "http"):
        candidate = f"{scheme}://{domain}"
        if http_client.get(candidate, timeout=TIMEOUT, allow_redirects=True) is not None:
            base = candidate
            break
    if base is None:
        return {"techs": {}, "hits": []}

    techs, hits = {}, []
    names = {name.split(" ")[0] for name in detected}
    for cms, fn in CHECKS.items():
        if cms not in names:
            continue
        result = fn(base)
        techs.update({k: v for k, v in result["techs"].items() if k not in techs or not techs[k]})
        hits.extend((cms, path, desc, detail) for path, desc, detail in result["hits"])
    return {"techs": techs, "hits": hits}
