"""
Identificacion de CMS desde la pagina principal (HTML): tipo, version, y en
WordPress los plugins y temas con su version (ruta wp-content/plugins/<nombre>/
y parametro ?ver=). Solo lee la pagina principal; no prueba rutas.
"""
import re

import requests

from . import http_client

TIMEOUT = 15
PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_.\-]+)/[^\"'\s<>]*?(?:\?ver=([0-9][0-9a-zA-Z.\-]*))?[\"'\s>]")
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9_.\-]+)/[^\"'\s<>]*?(?:\?ver=([0-9][0-9a-zA-Z.\-]*))?[\"'\s>]")
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)


def _fetch_home(domain: str) -> str | None:
    for scheme in ("https", "http"):
        r = http_client.get(f"{scheme}://{domain}", timeout=TIMEOUT, allow_redirects=True)
        if r is not None and r.status_code < 500 and r.text:
            return r.text
    return None


def _clean_ver(ver: str) -> str:
    """El ?ver= de WordPress a veces es una marca de tiempo (p.ej. 1787314609), no una version."""
    return "" if re.fullmatch(r"\d{7,}", ver or "") else ver


def _split_generator(text: str) -> tuple[str, str]:
    m = re.match(r"(.+?)\s+v?(\d+(?:\.\d+)+)", text)
    if m:
        return m.group(1).strip(), m.group(2)
    return text.strip(), ""


def detect_cms(domain: str) -> dict[str, str]:
    """{tecnologia: version} con CMS, plugins y temas detectados en la pagina principal."""
    html = _fetch_home(domain)
    if not html:
        return {}
    techs: dict[str, str] = {}

    gen = GENERATOR_RE.search(html)
    if gen:
        name, version = _split_generator(gen.group(1))
        if name:
            techs[name] = version

    if "/wp-content/" in html or "/wp-includes/" in html:
        techs.setdefault("WordPress", "")
        for name, ver in PLUGIN_RE.findall(html):
            techs.setdefault(f"WordPress plugin {name}", _clean_ver(ver))
        for name, ver in THEME_RE.findall(html):
            techs.setdefault(f"WordPress tema {name}", _clean_ver(ver))
    if "/media/system/js/" in html or "/components/com_" in html:
        techs.setdefault("Joomla", "")
    if "/sites/default/files" in html or "Drupal.settings" in html:
        techs.setdefault("Drupal", "")
    if "liferay" in html.lower():
        techs.setdefault("Liferay", "")
    return techs
