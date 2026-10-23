"""Descarga de ficheros encontrados, con limites de tamano y UA aleatorio."""
import hashlib
import random
import time
from pathlib import Path

import requests

from .ua import random_headers

MAX_BYTES = 25 * 1024 * 1024  # 25 MB por fichero, evita descargas gigantes


def download(url: str, dest_dir: Path, min_delay=1.5, max_delay=4.0) -> Path | None:
    """Descarga `url` a `dest_dir`. Devuelve la ruta local o None si falla."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = hashlib.sha1(url.encode()).hexdigest()[:16]
    suffix = Path(url.split("?")[0]).suffix or ""
    local_path = dest_dir / f"{name}{suffix}"

    if local_path.exists():
        return local_path

    try:
        with requests.get(
            url, headers=random_headers(), stream=True, timeout=20
        ) as resp:
            if resp.status_code != 200:
                return None
            content_length = int(resp.headers.get("Content-Length", 0) or 0)
            if content_length and content_length > MAX_BYTES:
                return None

            written = 0
            with open(local_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    written += len(chunk)
                    if written > MAX_BYTES:
                        f.close()
                        local_path.unlink(missing_ok=True)
                        return None
                    f.write(chunk)
    except requests.RequestException:
        return None
    finally:
        time.sleep(random.uniform(min_delay, max_delay))

    return local_path
