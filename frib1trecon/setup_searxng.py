#!/usr/bin/env python3
"""
Arranca SearXNG una vez para que genere su settings.yml por defecto,
lo parchea para habilitar el formato JSON (necesario para que
frib1trecon pueda consultar resultados programaticamente) y reinicia
el contenedor.

Uso:
    python3 setup_searxng.py
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).parent
SETTINGS_PATH = ROOT / "searxng" / "settings.yml"

# SearXNG solo trae activados por defecto Brave, DuckDuckGo y "Google CSE"
# (que sin una API key propia se agota casi al instante). Con solo 2-3
# motores reales, un escaneo de 28 dorks los deja suspendidos por
# rate-limit enseguida. Activamos motores adicionales que no dependen de
# scraping directo de Google/Bing (por eso no activamos esos dos) para
# tener mas margen y que, si uno se satura, los demas sigan respondiendo.
EXTRA_ENGINES = ["yahoo", "qwant", "mwmbl", "yep", "yandex"]


def _docker_prefix():
    """Antepone sudo si el usuario aun no tiene permisos sobre el socket docker
    (p.ej. justo despues de anadirlo al grupo docker, antes de relogear)."""
    if os.environ.get("FRIB1TRECON_DOCKER_SUDO"):
        return ["sudo"]
    probe = subprocess.run(["docker", "ps"], capture_output=True)
    if probe.returncode != 0:
        return ["sudo"]
    return []


DOCKER = _docker_prefix() + ["docker"]

# el contenedor corre como este UID:GID (ver docker-compose.yml) para que
# settings.yml se cree ya con los permisos del usuario anfitrion y nunca
# haga falta un "sudo chown" despues de arrancarlo.
os.environ["FRIB1TRECON_UID"] = str(os.getuid())
os.environ["FRIB1TRECON_GID"] = str(os.getgid())


def run(cmd):
    full = DOCKER + cmd
    print(f"$ {' '.join(full)}")
    subprocess.run(full, cwd=ROOT, check=True)


def wait_for_settings(timeout=60):
    print("Esperando a que SearXNG genere settings.yml ...")
    start = time.time()
    while not SETTINGS_PATH.exists():
        if time.time() - start > timeout:
            print("ERROR: no aparecio settings.yml a tiempo.", file=sys.stderr)
            sys.exit(1)
        time.sleep(1)
    # dar un margen para que termine de escribir el fichero
    time.sleep(2)


def ensure_writable(path: Path):
    """Con el contenedor fijado a nuestro propio UID:GID (ver
    docker-compose.yml) esto normalmente ya esta en orden desde el primer
    arranque. El chown de respaldo solo hace falta si la carpeta searxng/
    quedo de una ejecucion anterior a este cambio, con otro propietario."""
    if os.access(path, os.W_OK):
        return
    uid, gid = os.getuid(), os.getgid()
    print(f"Ajustando permisos de {path} (chown {uid}:{gid}, necesita sudo)...")
    result = subprocess.run(["sudo", "-n", "chown", "-R", f"{uid}:{gid}", str(path.parent)],
                             capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: no se pudo ajustar el propietario de {path.parent} "
              f"(sudo no disponible sin contraseña en este contexto).", file=sys.stderr)
        print(f"Ejecuta esto una vez a mano y vuelve a lanzar el instalador:\n"
              f"    sudo chown -R {uid}:{gid} {path.parent}", file=sys.stderr)
        sys.exit(1)


def patch_settings():
    ensure_writable(SETTINGS_PATH)
    with open(SETTINGS_PATH, "r") as f:
        data = yaml.safe_load(f)

    search = data.setdefault("search", {})
    formats = search.setdefault("formats", ["html"])
    if "json" not in formats:
        formats.append("json")

    # instancia de uso personal/local: no necesitamos el limitador de
    # peticiones publico, y sin el, json funciona sin bloqueos internos
    server = data.setdefault("server", {})
    server["limiter"] = False
    server["image_proxy"] = False

    # activar motores de reserva (mergea por "name" con los defaults de
    # SearXNG gracias a use_default_settings: true)
    engines = data.setdefault("engines", [])
    existing_names = {e.get("name") for e in engines}
    for name in EXTRA_ENGINES:
        if name not in existing_names:
            engines.append({"name": name, "disabled": False})

    with open(SETTINGS_PATH, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)

    print(f"settings.yml parcheado: formats+=json, limiter=false, "
          f"engines+={EXTRA_ENGINES}")


def ensure_host_dir():
    """Crea ./searxng ANTES de "docker compose up" si no existe. Si se deja
    que Docker la cree solo (al montarla como volumen), la crea como root,
    y SearXNG (que corre dentro del contenedor con nuestro UID, ver
    docker-compose.yml) no puede escribir settings.yml ahi -> "Permission
    denied" y wait_for_settings() nunca encuentra el fichero. Creandola
    aqui, con el usuario normal que ejecuta este script, el volumen ya
    existe con el propietario correcto cuando Docker la monta."""
    searxng_dir = ROOT / "searxng"
    if not searxng_dir.exists():
        searxng_dir.mkdir(parents=True)


def main():
    ensure_host_dir()
    run(["compose", "up", "-d"])
    wait_for_settings()
    patch_settings()
    run(["compose", "restart", "searxng"])
    print("\nListo. Prueba: curl 'http://127.0.0.1:8080/search?q=test&format=json'")


if __name__ == "__main__":
    main()
