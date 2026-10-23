#!/usr/bin/env bash
# install.sh - instala dependencias, levanta SearXNG y ejecuta frib1trecon.
# Pensado para poder copiar la carpeta frib1trecon/ a otra maquina Debian/Kali
# y con un solo comando dejarlo todo listo:
#
#   ./install.sh site.com
#
# Es idempotente: si vuelves a ejecutarlo en la misma maquina, se salta lo
# que ya este instalado/configurado.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { echo -e "\033[1;36m[install]\033[0m $*"; }
warn() { echo -e "\033[1;33m[install]\033[0m $*"; }
die()  { echo -e "\033[1;31m[install]\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Comprobar/instalar paquetes del sistema (solo distros basadas en apt)
# ---------------------------------------------------------------------------
if ! command -v apt-get >/dev/null 2>&1; then
    die "Este instalador solo soporta distros basadas en apt (Debian/Kali/Ubuntu). Instala manualmente: docker, docker-compose-v2, python3-venv, exiftool."
fi

NEEDED_PKGS=()
command -v docker      >/dev/null 2>&1 || NEEDED_PKGS+=(docker.io)
docker compose version >/dev/null 2>&1 || NEEDED_PKGS+=(docker-compose-v2)
command -v python3     >/dev/null 2>&1 || NEEDED_PKGS+=(python3)
python3 -c "import venv" 2>/dev/null   || NEEDED_PKGS+=(python3-venv)
command -v pip3        >/dev/null 2>&1 || NEEDED_PKGS+=(python3-pip)
command -v exiftool    >/dev/null 2>&1 || NEEDED_PKGS+=(libimage-exiftool-perl)
command -v curl        >/dev/null 2>&1 || NEEDED_PKGS+=(curl)

# graphviz (diagrama de red), exploitdb/searchsploit (busqueda local de
# exploits) y whatweb (fingerprinting de tecnologias web): opcionales,
# van en un array aparte y se instalan con su
# propia llamada a apt-get, para que si alguno no existe en los repos de
# esta distro (p.ej. Debian estable sin repos non-free) NO aborte el resto
# de la instalacion (set -e abortaria todo si fueran parte de NEEDED_PKGS).
# frib1trecon funciona igual sin ellos, solo con menos resultados en las
# funciones de vulnerabilidades/diagrama de red.
NEEDED_OPTIONAL_PKGS=()
command -v dot          >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(graphviz)
command -v searchsploit >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(exploitdb)
command -v whatweb      >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(whatweb)
command -v nmap         >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(nmap)
command -v pdflatex     >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(texlive-latex-base texlive-latex-extra)
command -v whois        >/dev/null 2>&1 || NEEDED_OPTIONAL_PKGS+=(whois)

if [ ${#NEEDED_PKGS[@]} -gt 0 ]; then
    log "Faltan paquetes: ${NEEDED_PKGS[*]}"
    log "Instalando (necesita sudo)..."
    sudo apt-get update -qq
    sudo apt-get install -y "${NEEDED_PKGS[@]}"
else
    log "Todos los paquetes del sistema ya estan instalados."
fi

if [ ${#NEEDED_OPTIONAL_PKGS[@]} -gt 0 ]; then
    log "Instalando paquetes opcionales: ${NEEDED_OPTIONAL_PKGS[*]}..."
    sudo apt-get update -qq || true
    if ! sudo apt-get install -y "${NEEDED_OPTIONAL_PKGS[@]}"; then
        warn "No se pudieron instalar algunos paquetes opcionales (${NEEDED_OPTIONAL_PKGS[*]})."
        warn "frib1trecon funciona igual sin ellos, solo con menos resultados en vulnerabilidades/diagrama de red."
    fi
fi

# Arrancar el demonio docker si hace falta
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable --now docker >/dev/null 2>&1 || warn "No se pudo habilitar el servicio docker via systemctl (¿estas en un contenedor/WSL?)."
fi

# ---------------------------------------------------------------------------
# 1b. TruffleHog (opcional pero recomendado): verificacion de leaks mucho
# mas precisa que las regex propias. Se instala en ~/.local/bin, SIN sudo
# (no hace falta root para ejecutarlo, y asi no hay que correr un script
# remoto como root). Si ~/.local/bin no esta en tu PATH, añadelo a tu
# .bashrc/.zshrc: export PATH="$HOME/.local/bin:$PATH"
# ---------------------------------------------------------------------------
if command -v trufflehog >/dev/null 2>&1; then
    log "TruffleHog ya esta instalado ($(trufflehog --version 2>&1 | head -1))."
else
    log "Instalando TruffleHog en ~/.local/bin (sin sudo)..."
    mkdir -p "$HOME/.local/bin"
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "$HOME/.local/bin" >/dev/null 2>&1; then
        log "TruffleHog instalado."
    else
        warn "No se pudo instalar TruffleHog automaticamente. frib1trecon funciona igual sin el"
        warn "(usa sus propias regex), pero con menos precision verificando leaks."
    fi
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) warn "~/.local/bin no esta en tu PATH. Añade esto a tu ~/.bashrc o ~/.zshrc:" ;;
    esac
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) warn '    export PATH="$HOME/.local/bin:$PATH"' ;;
    esac
fi

# ---------------------------------------------------------------------------
# 2. Meter al usuario en el grupo docker para no depender de sudo en el futuro
# ---------------------------------------------------------------------------
NEEDS_RELOGIN=0
if ! id -nG "$USER" | grep -qw docker; then
    log "Añadiendo $USER al grupo docker..."
    sudo usermod -aG docker "$USER"
    NEEDS_RELOGIN=1
fi

# Mientras el grupo no se aplique (requiere cerrar sesion), usamos sudo docker
# de forma transparente en esta misma ejecucion.
if docker ps >/dev/null 2>&1; then
    DOCKER_SUDO=""
else
    DOCKER_SUDO="sudo"
fi
export FRIB1TRECON_DOCKER_SUDO="$DOCKER_SUDO"

# ---------------------------------------------------------------------------
# 3. Entorno virtual de Python + dependencias
# ---------------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    log "Creando entorno virtual Python..."
    python3 -m venv .venv
fi

log "Instalando dependencias Python (requirements.txt)..."
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

# ---------------------------------------------------------------------------
# 3b. Interfaz web (frib1trecon-web/), si existe junto a esta carpeta: mismo
# proceso, su propio venv, para que un unico install.sh deje listas la CLI
# y la web sin pasos manuales aparte.
# ---------------------------------------------------------------------------
WEB_DIR="$SCRIPT_DIR/../frib1trecon-web"
if [ -d "$WEB_DIR" ]; then
    log "Preparando frib1trecon-web..."
    if [ ! -d "$WEB_DIR/.venv" ]; then
        python3 -m venv "$WEB_DIR/.venv"
    fi
    "$WEB_DIR/.venv/bin/pip" install -q --upgrade pip
    "$WEB_DIR/.venv/bin/pip" install -q -r "$WEB_DIR/requirements.txt"
    log "frib1trecon-web listo: cd ../frib1trecon-web && .venv/bin/python app.py"
else
    warn "No se encontro frib1trecon-web/ junto a esta carpeta, se omite (solo se prepara la CLI)."
fi

# ---------------------------------------------------------------------------
# 4. Levantar SearXNG (si no esta ya arriba) y habilitar formato JSON
#
# El contenedor se llama siempre "frib1trecon-searxng" (nombre fijo, ver
# docker-compose.yml) sea cual sea la copia de frib1trecon/ desde la que
# se ejecute este install.sh. Si tienes mas de una copia del proyecto en
# la misma maquina (p.ej. tu carpeta de trabajo y una carpeta "subida/"
# para GitHub), ambas COMPARTEN ese unico contenedor/instancia de
# SearXNG al ejecutar su install.sh - es lo esperado (un solo buscador,
# no hace falta duplicarlo), pero significa que la carpeta ./searxng/ de
# la copia que NO se ejecuto en ultimo lugar se queda vacia (el bind
# mount del contenedor apunta a la ultima que lo arranco). No afecta al
# funcionamiento: la CLI y la web de CADA copia usan su propio venv, y
# ambas hablan con el mismo SearXNG en http://127.0.0.1:8080 igual.
# ---------------------------------------------------------------------------
log "Comprobando/arrancando SearXNG..."
.venv/bin/python setup_searxng.py

# ---------------------------------------------------------------------------
# 5. Verificacion final: que todo lo instalado funciona DE VERDAD, no solo
# que el paso de instalacion no fallo (p.ej. SearXNG puede estar arriba
# pero no responder aun a busquedas en formato JSON).
# ---------------------------------------------------------------------------
log "Verificando que todo funciona..."

SEARXNG_OK=0
for _ in 1 2 3 4 5; do
    if curl -sSf "http://127.0.0.1:8080/search?q=test&format=json" >/dev/null 2>&1; then
        SEARXNG_OK=1
        break
    fi
    sleep 2
done
if [ "$SEARXNG_OK" -eq 1 ]; then
    log "  [OK] SearXNG responde a busquedas en formato JSON."
else
    warn "  [FALLO] SearXNG no responde en http://127.0.0.1:8080. Revisa 'docker ps' y los logs"
    warn "          del contenedor (docker logs frib1trecon-searxng)."
fi

if .venv/bin/python -c "import requests, rich, yaml, pypdf, docx, openpyxl, pptx, dns.resolver, matplotlib, PIL" 2>/dev/null; then
    log "  [OK] Dependencias Python de la CLI importan correctamente."
else
    warn "  [FALLO] Alguna dependencia Python de la CLI no importa. Revisa 'requirements.txt'."
fi

if [ -d "$WEB_DIR" ] && "$WEB_DIR/.venv/bin/python" -c "import flask" 2>/dev/null; then
    log "  [OK] frib1trecon-web puede importar Flask."
elif [ -d "$WEB_DIR" ]; then
    warn "  [FALLO] frib1trecon-web no puede importar Flask."
fi

log "  Herramientas opcionales (mejoran precision, no son obligatorias):"
command -v trufflehog  >/dev/null 2>&1 && log "    [OK] TruffleHog"       || warn "    [--] TruffleHog no disponible (verificacion de leaks solo con regex propias)"
command -v dot         >/dev/null 2>&1 && log "    [OK] graphviz (dot)"   || warn "    [--] graphviz no disponible (no se generara red.png, solo red.dot)"
command -v searchsploit >/dev/null 2>&1 && log "    [OK] searchsploit (ExploitDB local)" || warn "    [--] searchsploit no disponible (busqueda de vulnerabilidades solo via NVD/Sploitus)"
command -v whatweb      >/dev/null 2>&1 && log "    [OK] whatweb (fingerprinting de tecnologias web)" || warn "    [--] whatweb no disponible (no se detectaran tecnologias web ni se buscaran sus CVEs)"
command -v nmap         >/dev/null 2>&1 && log "    [OK] nmap (escaneo de puertos y versiones de servicios)" || warn "    [--] nmap no disponible (la categoria 'ports' no funcionara)"
command -v pdflatex     >/dev/null 2>&1 && log "    [OK] pdflatex (compila cyber_health_check.pdf desde el .tex)" || warn "    [--] pdflatex no disponible (se genera igual cyber_health_check.tex, pero sin compilar a PDF)"
command -v whois        >/dev/null 2>&1 && log "    [OK] whois (datos de registro del dominio)" || warn "    [--] whois no disponible (la seccion WHOIS del informe saldra vacia, el resto de DNS funciona igual)"

# ---------------------------------------------------------------------------
# 6. Ejecutar frib1trecon con los argumentos recibidos (si los hay)
# ---------------------------------------------------------------------------
if [ "$NEEDS_RELOGIN" -eq 1 ]; then
    warn "Se te ha añadido al grupo 'docker'. Cierra sesion y vuelve a entrar (o ejecuta 'newgrp docker')"
    warn "para no necesitar sudo en las proximas ejecuciones. Por ahora esta ejecucion sigue con sudo."
fi

if [ "$#" -eq 0 ]; then
    log "Instalacion completa."
    echo ""
    log "=== COMO USARLO ==="
    echo ""
    log "1) Escanear un dominio (linea de comandos). Desde la carpeta frib1trecon/:"
    echo "     ./install.sh dominio.com --all --recursive"
    echo "   Sin --all solo corre lo basico (documentos, DNS, TLS...). Mas opciones: .venv/bin/python -m frib1trecon.cli --help"
    echo ""
    if [ -d "$WEB_DIR" ]; then
        log "2) Interfaz web. install.sh NO la arranca solo; hay que lanzarla a mano:"
        echo "     cd \"$(cd "$WEB_DIR" && pwd)\""
        echo "     .venv/bin/python app.py"
        echo "   Despues abre en el navegador:  http://127.0.0.1:5000"
        echo "   Deja esa terminal abierta mientras la uses; para pararla pulsa Ctrl+C."
        echo ""
    fi
    log "SearXNG (el buscador que usa la herramienta) se ha levantado en Docker: http://127.0.0.1:8080"
    exit 0
fi

log "Lanzando frib1trecon contra: $1"
.venv/bin/python -m frib1trecon.cli "$@"
