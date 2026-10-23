"""
Extraccion de metadatos de documentos publicados:
  - exiftool como motor principal (cubre pdf/office/imagenes/etc.)
  - fallback con librerias Python si exiftool no esta disponible
  - para ficheros sensibles (sql/log/env/bak) se hace un grep de patrones
    de credenciales en vez de metadatos estructurados
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

EXIFTOOL_BIN = shutil.which("exiftool")
TRUFFLEHOG_BIN = shutil.which("trufflehog")

INTERESTING_TAGS = [
    "Author", "Creator", "LastModifiedBy", "Producer", "Software",
    "Application", "Company", "CreateDate", "ModifyDate", "Title",
    "Manufacturer", "Model", "Category", "Manager", "HyperlinkBase",
    "Template", "LastPrinted", "RevisionNumber", "TotalEditTime",
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*")
UNIX_HOME_PATH_RE = re.compile(r"/(?:home|Users)/[^/\s\"'<>]+(?:/[^/\s\"'<>]+)*")

# rutas UNC tipo \\SERVIDOR\recurso\...: el nombre que sigue a las dos
# barras es un equipo/servidor real de la red interna (hallazgo clasico al
# analizar documentos de Office: revela el nombre del fileserver, del
# dominio de Windows, etc. Se trata como "equipo" y no como "ruta").
UNC_PATH_RE = re.compile(r"\\\\([A-Za-z0-9_.-]+)\\[^\s\"'<>]*")

_HTML_BLOCK_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(raw_text: str) -> str:
    """Quita <script>/<style> y el resto de etiquetas para poder buscar
    emails en el texto visible de una pagina web descargada."""
    text = _HTML_BLOCK_RE.sub(" ", raw_text)
    return _HTML_TAG_RE.sub(" ", text)

SECRET_PATTERNS = {
    # sin \b delante de la palabra clave a proposito: variables de entorno
    # reales suelen ir como DB_PASSWORD=, AWS_API_KEY=, MY_SECRET=... y el
    # guion bajo no cuenta como limite de palabra en regex, asi que un \b
    # ahi dejaba pasar exactamente el caso mas comun en ficheros .env/.log/.sql.
    # El ["']? tras la palabra clave es para JSON/YAML: {"password": "x"}
    # tiene una comilla de cierre entre la palabra y los dos puntos, que sin
    # eso rompia la coincidencia (\s* no salta comillas).
    "password": re.compile(r"(?i)(pass(word)?|passwd|pwd)[\"']?\s*[:=]\s*[\"']?\S+"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?\S+"),
    "aws_key": re.compile(r"(?i)aws_(access_key_id|secret_access_key)[\"']?\s*[:=]\s*[\"']?\S+"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "db_conn": re.compile(r"(?i)(mysql|postgres(ql)?|mongodb)://\S+:\S+@\S+"),
    "generic_secret": re.compile(r"(?i)(secret|token)[\"']?\s*[:=]\s*[\"']?\S+"),
    # exposicion de infraestructura interna (IP/puerto/endpoints): no es
    # una "credencial" en si misma pero es igual de valioso, revela
    # topologia de red que no deberia ser publica
    "ip_address": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"),
}

# nombres de fichero que son sospechosos por si solos, aunque el contenido
# no se pueda leer (binario, repo privado que redirige a login, etc.)
SUSPICIOUS_FILENAME_RE = re.compile(
    r"(?i)(private|secret|credential|password|\.pem$|\.key$|id_rsa|\.pfx$|\.p12$|wp-config)"
)

# extensiones que vale la pena bajar y analizar si aparecen listadas en un
# directorio abierto (Apache/Nginx autoindex), aunque el nombre del fichero
# en si no sea sospechoso (ver SUSPICIOUS_FILENAME_RE)
_INTERESTING_LISTING_EXT_RE = re.compile(
    r"\.(txt|sql|env|bak|zip|tar|gz|7z|rar|pem|key|cfg|conf|ini|log|json|"
    r"yml|yaml|db|sqlite|csv|xls|xlsx|doc|docx|pdf)$",
    re.IGNORECASE,
)

MAX_SCAN_BYTES = 2 * 1024 * 1024  # no escanear ficheros de log gigantes enteros


def is_interesting_listing_entry(name: str) -> bool:
    """True si un fichero listado en un directorio abierto merece
    descargarse y analizarse (nombre sospechoso o extension de las que
    suelen llevar credenciales/config/backups)."""
    return bool(SUSPICIOUS_FILENAME_RE.search(name) or _INTERESTING_LISTING_EXT_RE.search(name))


_DIR_LISTING_LINK_RE = re.compile(r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_DIR_LISTING_SKIP_TEXT = {
    "parent directory", "..", "name", "last modified", "size", "description",
}


def parse_directory_listing(html: str, base_url: str) -> list[dict]:
    """Parsea los enlaces de un listado de directorio Apache/Nginx
    (autoindex): descarta el enlace a "Parent Directory", los de
    ordenacion de columnas (?C=N;O=D) y duplicados. Devuelve
    [{"name": ..., "url": ...}, ...] con URLs ya resueltas (absolutas)."""
    from urllib.parse import urljoin

    entries = []
    seen = set()
    for href, text in _DIR_LISTING_LINK_RE.findall(html):
        href = href.strip()
        text = _HTML_TAG_RE.sub(" ", text).strip()
        if not href or href.startswith(("?", "#")) or href in ("/", "../"):
            continue
        if text.lower() in _DIR_LISTING_SKIP_TEXT:
            continue
        full_url = urljoin(base_url, href)
        if full_url in seen or full_url.rstrip("/") == base_url.rstrip("/"):
            continue
        seen.add(full_url)
        entries.append({"name": text or href, "url": full_url})
    return entries


def extract_office_metadata(path: Path) -> dict:
    """Metadatos via exiftool. Devuelve dict vacio si no esta disponible o falla."""
    if not EXIFTOOL_BIN:
        return _fallback_metadata(path)

    try:
        out = subprocess.run(
            [EXIFTOOL_BIN, "-json", "-a", "-G0:1", str(path)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        data = json.loads(out.stdout)
        if not data:
            return {}
        raw = data[0]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return _fallback_metadata(path)

    result = {}
    for tag in INTERESTING_TAGS:
        for key, val in raw.items():
            short_key = key.split(":")[-1]
            if short_key == tag and val:
                result[tag] = val
                break
    return result


def extract_gps(path: Path) -> str | None:
    """Coordenadas GPS embebidas en una imagen (EXIF), si las tiene: fotos
    corporativas subidas sin limpiar metadatos que revelan la ubicacion
    exacta donde se tomaron. Devuelve "lat,lon" en grados decimales, o
    None si no hay exiftool o la imagen no tiene GPS."""
    if not EXIFTOOL_BIN:
        return None
    try:
        out = subprocess.run(
            # -n: valores numericos (grados decimales con signo N/S/E/W ya
            # aplicado) en vez del formato "12 deg 34' 56.78\" N" por defecto
            [EXIFTOOL_BIN, "-json", "-n", "-GPSLatitude", "-GPSLongitude", str(path)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        data = json.loads(out.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None
    if not data:
        return None
    lat, lon = data[0].get("GPSLatitude"), data[0].get("GPSLongitude")
    if lat is None or lon is None:
        return None
    return f"{lat},{lon}"


def _fallback_metadata(path: Path) -> dict:
    """Sin exiftool: extraccion basica segun extension usando libs Python."""
    ext = path.suffix.lower()
    try:
        if ext == ".pdf":
            from pypdf import PdfReader
            meta = PdfReader(str(path)).metadata or {}
            return {
                "Author": meta.get("/Author"),
                "Creator": meta.get("/Creator"),
                "Producer": meta.get("/Producer"),
                "CreateDate": meta.get("/CreationDate"),
                "ModifyDate": meta.get("/ModDate"),
                "Title": meta.get("/Title"),
            }
        if ext == ".docx":
            import docx
            props = docx.Document(str(path)).core_properties
            return {
                "Author": props.author,
                "LastModifiedBy": props.last_modified_by,
                "CreateDate": str(props.created) if props.created else None,
                "ModifyDate": str(props.modified) if props.modified else None,
                "Title": props.title,
            }
        if ext == ".xlsx":
            import openpyxl
            props = openpyxl.load_workbook(str(path), read_only=True).properties
            return {
                "Author": props.creator,
                "LastModifiedBy": props.lastModifiedBy,
                "CreateDate": str(props.created) if props.created else None,
                "ModifyDate": str(props.modified) if props.modified else None,
                "Title": props.title,
            }
        if ext == ".pptx":
            from pptx import Presentation
            props = Presentation(str(path)).core_properties
            return {
                "Author": props.author,
                "LastModifiedBy": props.last_modified_by,
                "CreateDate": str(props.created) if props.created else None,
                "ModifyDate": str(props.modified) if props.modified else None,
                "Title": props.title,
            }
    except Exception:
        return {}
    return {}


def find_internal_paths(meta: dict) -> list[str]:
    """Busca rutas de Windows/Unix filtradas en los valores de metadatos
    (plantillas, HyperlinkBase, Manager...)."""
    found = set()
    for val in meta.values():
        if not val:
            continue
        text = str(val)
        found.update(WINDOWS_PATH_RE.findall(text))
        found.update(UNIX_HOME_PATH_RE.findall(text))
    return sorted(found)


def find_computer_names(*texts: str) -> list[str]:
    """Busca nombres de equipo/servidor en rutas UNC (\\\\SERVIDOR\\recurso)
    dentro de uno o varios textos (metadatos + contenido del documento)."""
    found = set()
    for text in texts:
        if text:
            found.update(UNC_PATH_RE.findall(str(text)))
    return sorted(found)


def extract_text(path: Path, max_chars: int = 300_000) -> str:
    """Extrae texto plano de un documento para buscar emails/usuarios.
    Best-effort: si el formato no se puede parsear, devuelve cadena vacia."""
    ext = path.suffix.lower()
    try:
        if ext in (".sql", ".log", ".env", ".bak", ".csv"):
            with open(path, "rb") as f:
                return f.read(max_chars).decode("utf-8", errors="ignore")

        if ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            return text[:max_chars]

        if ext == ".docx":
            import docx
            doc = docx.Document(str(path))
            return "\n".join(p.text for p in doc.paragraphs)[:max_chars]

        if ext == ".xlsx":
            import openpyxl
            wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
            chunks = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    chunks.append(" ".join(str(c) for c in row if c is not None))
                    if sum(len(c) for c in chunks) > max_chars:
                        break
            return "\n".join(chunks)[:max_chars]

        if ext == ".pptx":
            from pptx import Presentation
            prs = Presentation(str(path))
            chunks = []
            for slide in prs.slides:
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        chunks.append(shape.text_frame.text)
            return "\n".join(chunks)[:max_chars]

        # generico: paginas web (sin extension o .html/.htm) u otros
        # formatos de texto no contemplados arriba
        with open(path, "rb") as f:
            raw = f.read(max_chars * 4)  # margen extra: las etiquetas se descartan
        return _strip_html(raw.decode("utf-8", errors="ignore"))[:max_chars]
    except Exception:
        return ""


# "John/Jane Doe" es el placeholder universal en formularios, plantillas y,
# sobre todo, herramientas de generacion de patrones de email (prospeo.io,
# hunter.io y similares muestran "jdoe@dominio.com" como EJEMPLO del
# formato, no como empleado real) -> se descartan siempre, no son datos.
PLACEHOLDER_LOCAL_PARTS = {
    "doe", "jdoe", "johndoe", "j.doe", "john.doe",
    "janedoe", "j.anedoe", "jane.doe",
}


def scan_for_emails(text: str, domain: str | None = None) -> list[str]:
    """Devuelve emails encontrados en `text`, priorizando los del dominio objetivo."""
    found = {
        e for e in EMAIL_RE.findall(text)
        if e.split("@", 1)[0].lower() not in PLACEHOLDER_LOCAL_PARTS
    }
    if domain:
        internal = {e for e in found if e.lower().endswith(f"@{domain.lower()}")}
        if internal:
            return sorted(internal)
    return sorted(found)


def scan_text_for_secrets(text: str) -> list[str]:
    """Devuelve los tipos de patron de credencial encontrados en un texto
    arbitrario (fragmento de busqueda, pagina descargada, fichero...)."""
    found = []
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            found.append(label)
    return found


def scan_for_secrets(path: Path) -> list[str]:
    """Igual que scan_text_for_secrets pero leyendo un fichero del disco."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_SCAN_BYTES)
        text = raw.decode("utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text_for_secrets(text)


def scan_file_with_trufflehog(path: Path, timeout: int = 30) -> list[str]:
    """Si TruffleHog esta instalado, lo usa para una deteccion de secretos
    mucho mas precisa que nuestras regex: cientos de detectores especificos
    (AWS, Stripe, Slack, GitHub...) y verificacion activa (comprueba si una
    clave encontrada realmente funciona contra el servicio correspondiente).
    Si no esta instalado, devuelve lista vacia sin fallar (instalacion:
    https://github.com/trufflesecurity/trufflehog#installation)."""
    if not TRUFFLEHOG_BIN:
        return []
    try:
        out = subprocess.run(
            [TRUFFLEHOG_BIN, "filesystem", str(path), "--json", "--no-update"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return []

    found = set()
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = data.get("DetectorName")
        if not detector:
            continue
        found.add(f"trufflehog:{detector}" + (" (verificado)" if data.get("Verified") else ""))
    return sorted(found)
