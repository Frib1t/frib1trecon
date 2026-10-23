"""
Fingerprinting de tecnologias web sobre la pagina principal del objetivo:
identifica CMS, framework, servidor web,
librerias JS... con su version, para despues cruzarlas contra bases de
CVEs/exploits (frib1trecon.vuln_lookup), igual que se hace con el software
detectado en metadatos de documentos.

No reinventa el fingerprinting: usa `whatweb` (ya viene en Kali, se
instala con `apt install whatweb` en Debian/Ubuntu) y parsea su salida
JSON. Aggression nivel 1 (el mas discreto, solo la pagina principal, sin
seguir enlaces ni forzar peticiones extra) para mantener la misma
filosofia pasiva/educada del resto de la herramienta.
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

WHATWEB_BIN = shutil.which("whatweb")

# plugins de WhatWeb que son metadatos/cabeceras genericas, no "software
# con version" (asi no se busca un CVE para "Country" o "Title")
_IGNORE_PLUGINS = {
    "Country", "IP", "Title", "UncommonHeaders", "Via-Proxy",
    "X-Frame-Options", "Strict-Transport-Security", "PoweredBy",
    "Open-Graph-Protocol", "Script", "HTML5", "Modernizr", "Email",
    "Cookies", "MetaGenerator", "X-Powered-By", "Frame", "Meta-Author",
    "HttpOnly", "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy",
}


def fingerprint_url(url: str, timeout: int = 20) -> dict[str, str]:
    """Devuelve {tecnologia: version} para una URL. Dict vacio si whatweb
    no esta instalado, la peticion falla, o no se detecta nada con
    version (sin version no hay nada que buscar en una base de CVEs)."""
    if not WHATWEB_BIN:
        return {}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = Path(f.name)
    try:
        subprocess.run(
            [WHATWEB_BIN, "--no-errors", "-a", "1", f"--log-json={out_path}", url],
            capture_output=True, timeout=timeout,
        )
        data = json.loads(out_path.read_text() or "[]")
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError, ValueError):
        return {}
    finally:
        out_path.unlink(missing_ok=True)

    techs: dict[str, str] = {}
    for result in data:
        for plugin, info in (result.get("plugins") or {}).items():
            if plugin in _IGNORE_PLUGINS or not isinstance(info, dict):
                continue
            versions = info.get("version")
            if versions:
                techs[plugin] = versions[0]
    return techs
