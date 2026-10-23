"""
Escaneo de puertos TCP abiertos y deteccion de version/scripts de servicios
con nmap, en dos fases:

  1. Descubrimiento: barrido SYN (-sS) a los 65535 puertos TCP (-p-), sin
     deteccion de servicio todavia, para ver rapido cuales estan abiertos.
     -sS necesita privilegios de raw socket (root o el binario con
     cap_net_raw via setcap, como viene nmap en Kali por defecto); si no
     estan disponibles, nmap rechaza el -sS explicito y se reintenta con
     -sT (connect scan, mas lento pero funciona sin privilegios especiales
     en cualquier entorno).
  2. Version/scripts: -sCV (script scan default + deteccion de version)
     SOLO sobre los puertos que salieron abiertos en la fase 1 — al ser
     pocos puertos, esta fase es rapida aunque sea mucho mas pesada que la
     anterior por puerto escaneado.

ACTIVO: envia trafico directo al objetivo (no es consulta a terceros). Corre
por defecto (categoria "ports" en VALID_CATEGORIES) para dar el informe mas
completo posible; solo debe usarse contra dominios propios o con
autorizacion — si no la tenes, exclui "ports" explicitamente con
--categories (CLI) o desmarcando el checkbox correspondiente (web).
"""
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

NMAP_BIN = shutil.which("nmap")
# -p- a los 65535 puertos puede tardar bastante si nmap cae a -sT (connect
# scan) por falta de privilegios SYN; la fase de version es sobre un puñado
# de puertos nomas, asi que necesita mucho menos margen.
NMAP_DISCOVERY_TIMEOUT = 1800
NMAP_VERSION_TIMEOUT = 300
# 5000 paquetes/s contra UN SOLO host puede leerse como un intento de DoS
# (o directamente saturar su pila de red) y disparar cualquier IDS/IPS en
# el camino. 1000 sigue siendo agresivo para un full port scan pero es un
# piso mucho mas razonable para un pentest autorizado contra un host.
NMAP_MIN_RATE = 1000
_PRIVILEGE_ERROR_MARKERS = ("requires root", "raw socket", "cap_net_raw", "requires special privileges")


def resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _run_nmap_xml(args: list[str], timeout: int) -> ET.Element:
    proc = subprocess.run([NMAP_BIN, *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        stderr_low = proc.stderr.lower()
        if "-ss" in " ".join(args).lower() and any(m in stderr_low for m in _PRIVILEGE_ERROR_MARKERS):
            # sin privilegios para SYN scan: reintentamos el mismo comando
            # con -sT (connect scan), que no necesita raw sockets.
            fallback_args = ["-sT" if a == "-sS" else a for a in args]
            proc = subprocess.run([NMAP_BIN, *fallback_args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap fallo (codigo {proc.returncode}): {proc.stderr.strip()[:200]}")
    return ET.fromstring(proc.stdout)


def _discover_open_ports(ip: str) -> list[int]:
    """Fase 1: que puertos TCP (de los 65535) estan abiertos, sin version."""
    root = _run_nmap_xml(
        ["-p-", "-n", "-sS", "-Pn", "--min-rate", str(NMAP_MIN_RATE), "--open", "-oX", "-", ip],
        timeout=NMAP_DISCOVERY_TIMEOUT,
    )
    ports = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            ports.append(int(port.get("portid")))
    return sorted(ports)


def scan_services(ip: str) -> list[dict]:
    """Puertos TCP abiertos (barrido completo de los 65535) con
    servicio/producto/version/scripts por defecto segun nmap."""
    if not NMAP_BIN:
        raise RuntimeError("nmap no esta instalado")

    open_ports = _discover_open_ports(ip)
    if not open_ports:
        return []

    ports_arg = ",".join(str(p) for p in open_ports)
    root = _run_nmap_xml(
        ["-p", ports_arg, "-n", "-sCV", "-Pn", "--open", "-oX", "-", ip],
        timeout=NMAP_VERSION_TIMEOUT,
    )

    services = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        services.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "service": svc.get("name", "") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
            "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
        })
    return services


CRITICIDAD_BY_PORT = {
    21: "medium", 23: "high", 25: "low", 110: "medium", 139: "high", 143: "low",
    445: "high", 1433: "high", 1521: "high", 3306: "high", 3389: "high",
    5432: "high", 5900: "high", 6379: "high", 9200: "high", 27017: "high",
    22: "low", 53: "low", 587: "low", 993: "low", 995: "low",
}


def criticidad(port: int) -> str:
    return CRITICIDAD_BY_PORT.get(port, "info")


SERVER_PRODUCT_NAMES = {
    "apache": "Apache httpd", "nginx": "nginx", "microsoft-iis": "Microsoft IIS httpd",
    "openresty": "OpenResty", "lighttpd": "lighttpd", "litespeed": "LiteSpeed",
}


def server_header_version(domain: str, port: int, https: bool, timeout: int = 8) -> tuple[str, str] | None:
    """Producto y version de la cabecera Server (p.ej. 'Apache/2.4.41 (Ubuntu)').
    Se pide el dominio para respetar el virtual hosting. No valida certificados:
    solo se leen cabeceras."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    scheme = "https" if https else "http"
    from . import http_client
    r = http_client.head(f"{scheme}://{domain}:{port}/", timeout=timeout, verify=False)
    if r is None:
        return None
    server = r.headers.get("Server", "")
    m = re.match(r"([A-Za-z\-]+)/(\d+(?:\.\d+)+)", server)
    if not m:
        return None
    name = SERVER_PRODUCT_NAMES.get(m.group(1).lower(), m.group(1))
    return name, m.group(2)
