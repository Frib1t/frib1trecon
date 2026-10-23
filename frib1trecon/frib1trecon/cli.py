#!/usr/bin/env python3
"""
frib1trecon - herramienta de reconocimiento OSINT para Linux: dorking +
metadatos, sin scrapear Google directamente (usa SearXNG como
intermediario).

Uso basico:
    python3 -m frib1trecon.cli site.com

Requiere una instancia SearXNG corriendo con formato JSON habilitado
(ver setup_searxng.py / install.sh en la raiz del proyecto).
"""
import argparse
import datetime
import os
import shutil
import sys
from pathlib import Path

from rich.prompt import Confirm, Prompt

from .engine import VALID_CATEGORIES, normalize_domain, run_scan_recursive
from .report_export import export_all
from .report import (
    Finding, console, print_documents_table, print_email_osint_table,
    print_emails_paths_table, print_external_osint_table, print_org_chart_table,
    print_dns_table, print_platform_table, print_risk_score, print_sensitive_table, print_summary,
    print_ports_table, print_tech_table, print_tls_table, print_typosquat_table, print_vuln_table,
)

EXIT_OK = 0
EXIT_LEAK_FOUND = 1
EXIT_ERROR = 2

HELP_EPILOG = """
ejemplos:
  python3 -m frib1trecon.cli site.com
      Analisis completo (TODAS las categorias, incluido nmap activo contra
      el objetivo): pregunta si quieres guardar los documentos.

  python3 -m frib1trecon.cli site.com --yes
      Igual, pero sin preguntar nada (usa los valores por defecto).

  python3 -m frib1trecon.cli site.com --no-download
      Solo lista las URLs encontradas, sin descargar ni analizar nada
      (el modo mas rapido y discreto).

  python3 -m frib1trecon.cli site.com --no-save-docs
      Extrae metadatos y emails pero no deja los ficheros en disco.

  python3 -m frib1trecon.cli site.com --min-delay 5 --max-delay 12
      Va mas despacio entre peticiones (nunca baja de 1.5s aunque pidas menos).

  python3 -m frib1trecon.cli site.com --categories leak,sensitive
      Restringe el analisis a solo esas categorias (en vez de todas, que
      es lo que se corre por defecto sin --categories).

  python3 -m frib1trecon.cli site.com --yes --quiet --fail-on-leak
      Para cron/CI: sin preguntas, sin ruido en pantalla, y codigo de
      salida 1 si aparece algun leak/credencial (0 si no, 2 si hubo error).

  python3 -m frib1trecon.cli site.com --all
      Igual que sin flags: todas las categorias (se mantiene por
      compatibilidad, ya no agrega nada que no corra por defecto).

  python3 -m frib1trecon.cli site.com --categories external --ghw-key ... --vt-key ...
      Solo fuentes externas: Shodan, crt.sh y Certspotter (gratis, hosts/
      puertos/subdominios) y, si pones --ghw-key/--intelx-key/
      --dnsdumpster-key/--vt-key/--abuseipdb-key (o las variables de
      entorno GHW_API_KEY/INTELX_API_KEY/DNSDUMPSTER_API_KEY/VT_API_KEY/
      ABUSEIPDB_API_KEY), tambien GrayHatWarfare, IntelX, DNSDumpster,
      y reputacion del dominio/IP via VirusTotal/AbuseIPDB. Ninguna api
      key se guarda en el codigo: son siempre parametros/variables de
      entorno que pone quien ejecuta el escaneo.

  python3 -m frib1trecon.cli site.com --recursive
      Lo mas completo: ademas de todas las categorias sobre el dominio,
      descubre subdominios (crt.sh/Shodan) y relanza un escaneo mas
      ligero (documentos/sensibles/leaks) contra cada uno, hasta 10 por
      defecto (--max-subdomains). Aumenta mucho el tiempo total: cada
      subdominio son ~26 dorks mas.

  python3 -m frib1trecon.cli site.com --categories document,vuln
      Fingerprinting de tecnologias web sobre la pagina principal del
      dominio (CMS, framework, servidor, librerias JS...) y busca
      CVEs/exploits conocidos (NVD + ExploitDB local + Sploitus) para
      cada una, ademas de para el software/version detectado en
      metadatos de documentos (p.ej. "Apache 2.2.3").

  python3 -m frib1trecon.cli site.com --exclude-categories ports
      Todo EXCEPTO el escaneo activo de puertos (nmap) — usar si el
      dominio no esta autorizado para trafico activo directo.

que encuentra: postura DNS y WHOIS (NS/MX/TXT/CAA, autenticacion de correo
SPF/DKIM/DMARC, DNSSEC, intento de transferencia de zona AXFR, datos de
registro) y postura TLS/HTTPS y cabeceras de seguridad web (certificado:
emisor/caducidad/cifrado, soporte de protocolos obsoletos TLSv1.0/1.1,
cabeceras HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/
Permissions-Policy y flags Secure/HttpOnly de cookies) activas por
defecto, documentos ofimaticos con sus metadatos
(pdf/xlsx/xls/docx/doc/csv/pptx/jpg/jpeg/png/tiff) incluyendo rutas internas, equipos/
servidores filtrados y coordenadas GPS si la imagen las tenia embebidas,
ficheros sensibles (sql/log/env/bak/txt) indexados en buscadores y rutas habituales que
pueden exponerse (.env, .git/config, copias de BD, phpinfo, paneles...), ficheros con
pinta de password/claves olvidados, menciones en Drive/Docs/S3/Dropbox/
Pastebin/Trello/OneDrive/Notion/Play Store/App Store, posibles leaks en
GitHub/GitLab/Ghostbin/JSFiddle/StackOverflow/directorios abiertos (estos
ultimos descargados de verdad: se parsea el listado real de ficheros y se
analizan los que tengan pinta sensible)/paneles de admin (verificados en
local con TruffleHog si esta instalado, no solo por la busqueda), emails
corporativos mencionados en la web abierta, empleados en LinkedIn
agrupados en un organigrama aproximado, hosts/puertos expuestos en
Shodan, infraestructura cloud conocida (AWS/Azure/GCP/...) detectada en
local sobre todo lo anterior, y si das las api keys, ficheros en buckets
S3/Azure/GCP (GrayHatWarfare), menciones en leaks/darkweb (IntelX), y
reputacion del dominio/IP — motores que lo marcan malicioso, reportes de
botnet/spam/abuso (VirusTotal + AbuseIPDB), tecnologias web detectadas
(CMS, framework, servidor, librerias JS...) y CVEs/exploits conocidos
tanto de esas tecnologias como del software detectado en los documentos
(NVD + ExploitDB local + Sploitus), puertos TCP abiertos y version de
cada servicio via nmap -sT -sV (ACTIVO: trafico directo al objetivo;
excluible con --exclude-categories ports) con sus propios CVEs/EOL, y
typosquatting (variantes tipograficas del dominio estilo dnstwist, mas
lento: 1000+ resoluciones DNS) y domain squatting (mismo nombre en
otros TLDs + combosquatting con palabras de phishing como login/secure/
verify) realmente registradas segun DNS. TODO lo anterior corre por
defecto; usar --categories o --exclude-categories para acotar.

codigos de salida: 0 = ok, 1 = se encontro un leak y se paso --fail-on-leak,
2 = error (SearXNG no responde / motores saturados / excepcion).

salida: frib1trecon_output/<dominio>/ con informe.txt (legible), informe.docx
(Word), informe.xlsx (todos los metadatos en hojas separadas), cyber_health_check.docx
(informe ejecutivo de postura de seguridad), resultados.json/.csv (datos en
bruto), maltego.csv (para importar como entidades en Maltego), red.dot/.png
(diagrama de red: dominio -> subdominios -> IPs/cloud/software vulnerable,
necesita graphviz instalado para el .png, el .dot siempre se genera) y
documentos/ (si decidiste guardarlos). Con --recursive, ese mismo
informe.txt/.xlsx/.docx/cyber_health_check.docx de la carpeta del dominio ya
incluye el dominio + todos los subdominios juntos (un unico informe
completo, no uno aparte "maestro"); cada subdominio ademas conserva su
propia carpeta completa con su propio informe en subdominios/<subdominio>/.

requiere: una instancia SearXNG arriba. Si es la primera vez, ejecuta antes
"./install.sh" (instala todo e incluye un primer analisis) o, si ya tienes
todo instalado, solo "python3 setup_searxng.py". Mas detalle en README.txt.
"""


def parse_categories(value: str) -> set[str]:
    cats = {c.strip().lower() for c in value.split(",") if c.strip()}
    invalid = cats - VALID_CATEGORIES
    if invalid:
        raise argparse.ArgumentTypeError(
            f"categoria(s) invalida(s): {', '.join(sorted(invalid))}. "
            f"Validas: {', '.join(sorted(VALID_CATEGORIES))}"
        )
    return cats


def run_wizard() -> list[str]:
    """Modo asistente: solo se dispara si se ejecuta sin NINGUN argumento en
    una terminal interactiva (ver parse_args). Construye una lista de
    argumentos equivalente a los flags normales y la devuelve para que
    p.parse_args() la procese igual que si vinieran de la linea de
    comandos - cero logica de validacion/defaults duplicada: lo que no se
    pregunta aqui simplemente no se incluye, y argparse aplica su propio
    valor por defecto de siempre (incluidas las api keys por variable de
    entorno)."""
    console.print(
        "\n[bold]frib1trecon - modo asistente[/bold] (sin argumentos: pregunta paso a paso)\n"
        "[dim]Pulsa Enter para aceptar el valor por defecto en cada pregunta. Para saltarte "
        "esto, pasa el dominio y flags directamente (ver --help).[/dim]\n"
    )
    domain = ""
    while not domain:
        domain = Prompt.ask("[bold]Dominio objetivo[/bold] (ej. site.com)").strip()
    argv = [domain]

    if not Confirm.ask(
        "¿Analisis completo (todas las categorias, incluido el escaneo activo de puertos con nmap)?",
        default=True,
    ):
        cats = Prompt.ask(
            f"Categorias a lanzar, separadas por comas\n  Validas: {', '.join(sorted(VALID_CATEGORIES))}",
            default="document,sensitive,leak,email,dns,tls",
        ).strip()
        if cats:
            argv += ["--categories", cats]

    if Confirm.ask("¿Seguir tambien los subdominios descubiertos (--recursive)?", default=False):
        argv.append("--recursive")
        max_sub = Prompt.ask("Maximo de subdominios a seguir", default="10").strip()
        if max_sub:
            argv += ["--max-subdomains", max_sub]

    logos = Prompt.ask(
        "Carpeta con logos para personalizar el informe (portada/cliente/pentester.png) "
        "[Enter para ninguno]", default=""
    ).strip()
    if logos:
        argv += ["--logos-dir", logos]

    out_dir = Prompt.ask("Carpeta de salida", default="./frib1trecon_output").strip()
    if out_dir and out_dir != "./frib1trecon_output":
        argv += ["--out-dir", out_dir]

    if Confirm.ask(
        "¿Quieres introducir alguna api key de fuentes externas ahora? "
        "(Shodan/Censys/FOFA/HIBP/VirusTotal/AbuseIPDB/OTX/DomScan/GrayHatWarfare/IntelX/"
        "DNSDumpster - se puede dejar en blanco y usarlas luego por variable de entorno)",
        default=False,
    ):
        key_flags = [
            ("--shodan-key", "Shodan"), ("--ghw-key", "GrayHatWarfare"), ("--intelx-key", "IntelX"),
            ("--dnsdumpster-key", "DNSDumpster"), ("--vt-key", "VirusTotal"),
            ("--abuseipdb-key", "AbuseIPDB"), ("--censys-id", "Censys (API ID)"),
            ("--censys-secret", "Censys (API secret)"), ("--fofa-email", "FOFA (email)"),
            ("--fofa-key", "FOFA (API key)"), ("--hibp-key", "HaveIBeenPwned"),
            ("--domscan-key", "DomScan"), ("--otx-key", "OTX AlienVault"),
        ]
        for flag, label in key_flags:
            val = Prompt.ask(f"  {label} [Enter para saltar]", default="").strip()
            if val:
                argv += [flag, val]

    console.print(f"\n[dim]Equivalente a: frib1trecon {' '.join(argv)}[/dim]\n")
    return argv


def parse_args():
    p = argparse.ArgumentParser(
        description="frib1trecon - herramienta de reconocimiento OSINT para Linux: dorking + "
                     "metadatos + leaks OSINT, sin scrapear Google directamente (usa SearXNG "
                     "como intermediario).",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", help="Dominio objetivo, ej. site.com (tambien acepta pegar la URL "
                                   "completa, ej. https://site.com/alguna/ruta: se extrae solo el "
                                   "hostname)")
    p.add_argument("--searxng", action="append", default=None,
                    help="URL de instancia SearXNG (repetible para varias). Por defecto http://127.0.0.1:8080")
    p.add_argument("--proxy", action="append", default=None,
                    help="Proxy HTTP(S) a rotar, ej. http://127.0.0.1:9050 (repetible)")
    p.add_argument("--min-delay", type=float, default=2.5, help="Delay minimo entre consultas (s)")
    p.add_argument("--max-delay", type=float, default=6.0, help="Delay maximo entre consultas (s)")

    p.add_argument("--categories", type=parse_categories, default=None,
                    help=f"Por defecto se lanzan TODAS las categorias ({', '.join(sorted(VALID_CATEGORIES))}), "
                         "incluido 'ports' (nmap, ACTIVO: envia trafico directo al objetivo) y 'typosquat' "
                         "(mas lento, 1000+ resoluciones DNS). Pasar esta lista separada por comas restringe "
                         "el escaneo a SOLO esas categorias (util para un analisis rapido/acotado). Para "
                         "excluir puntualmente alguna sin enumerar el resto, usar --exclude-categories.")
    p.add_argument("--exclude-categories", type=parse_categories, default=None,
                    help="Lista separada por comas de categorias a excluir del set completo por defecto, "
                         "ej. --exclude-categories ports para no tocar nmap si el dominio no esta "
                         "autorizado para escaneo activo. Ignorado si se pasa --categories.")
    p.add_argument("--all", action="store_true",
                    help="Compatibilidad con versiones anteriores: ya no hace falta, todas las categorias "
                         "se lanzan por defecto. Las protecciones anti-bloqueo (User-Agent aleatorio, "
                         "delays, backoff) ya estan siempre activas en cada peticion.")

    save_group = p.add_mutually_exclusive_group()
    save_group.add_argument("--save-docs", dest="save_docs", action="store_true", default=None,
                             help="Guardar los documentos descargados en la carpeta de salida")
    save_group.add_argument("--no-save-docs", dest="save_docs", action="store_false",
                             help="Descartar los documentos tras extraer los metadatos (no ocupan disco)")

    p.add_argument("--no-download", action="store_true",
                    help="No descargar ni analizar ficheros, solo listar URLs encontradas (mas rapido y discreto)")
    p.add_argument("--skip-download", dest="no_download", action="store_true", help=argparse.SUPPRESS)  # alias

    p.add_argument("-y", "--yes", action="store_true",
                    help="No preguntar nada de forma interactiva (usa valores por defecto: guardar documentos)")
    p.add_argument("--out-dir", default="./frib1trecon_output",
                    help="Carpeta base de salida; se creara out-dir/<dominio>/ (por defecto ./frib1trecon_output)")
    p.add_argument("--logos-dir", default=os.environ.get("LOGOS_DIR"),
                    help="Carpeta con logos para personalizar el cyber_health_check.docx/.tex: "
                         "portada.{png,jpg} (imagen de portada), cliente.{png,jpg} (logo del "
                         "cliente, esquina superior derecha de cada pagina) y pentester.{png,jpg} "
                         "(tu logo, esquina superior izquierda). Cualquiera que falte simplemente "
                         "no aparece. Por defecto, variable de entorno LOGOS_DIR.")
    p.add_argument("--no-latex-pdf", dest="latex_pdf", action="store_false", default=True,
                    help="No compilar el cyber_health_check.pdf desde el .tex generado (solo "
                         "requiere que pdflatex este instalado; si no lo esta, esto no hace falta, "
                         "el .tex se genera siempre y se puede compilar donde se quiera).")

    p.add_argument("--fail-on-leak", action="store_true",
                    help="Salir con codigo 1 si se encuentra algun leak/credencial (util para scripts/CI)")

    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true",
                            help="Sin progreso en pantalla: solo avisos, leaks encontrados y el resumen final")
    verbosity.add_argument("-v", "--verbose", action="store_true",
                            help="Ademas del progreso normal, muestra los candidatos descartados tras verificarlos en local")

    p.add_argument("--log-file", default=None,
                    help="Guardar tambien un log de texto plano (sin colores) en esta ruta")

    rec = p.add_argument_group("recursividad por subdominios")
    rec.add_argument("--recursive", action="store_true",
                      help="Tras descubrir subdominios (crt.sh/Shodan, categoria 'external', ya "
                           "activa por defecto salvo que se excluya con --categories/"
                           "--exclude-categories), relanza un escaneo mas ligero contra cada uno "
                           "(1 solo nivel de profundidad, no se siguen sub-subdominios).")
    rec.add_argument("--recursive-categories", type=parse_categories, default=None,
                      help="Categorias a usar en los subdominios (por defecto: "
                           "document,sensitive,leak; 'email'/'people'/'external'/'vuln' no se "
                           "repiten ahi salvo que los pidas explicitamente).")
    rec.add_argument("--max-subdomains", type=int, default=10,
                      help="Maximo de subdominios a escanear con --recursive (por defecto 10, "
                           "para no disparar el tiempo total).")

    ext = p.add_argument_group(
        "fuentes externas (categoria 'external', activa por defecto; las keys son opcionales)")
    ext.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"),
                      help="API key de Shodan (opcional: InternetDB funciona sin key). "
                           "Por defecto, variable de entorno SHODAN_API_KEY.")
    ext.add_argument("--ghw-key", default=os.environ.get("GHW_API_KEY"),
                      help="API key de GrayHatWarfare (buckets S3/Azure/GCP expuestos). "
                           "Por defecto, variable de entorno GHW_API_KEY.")
    ext.add_argument("--intelx-key", default=os.environ.get("INTELX_API_KEY"),
                      help="API key de IntelX (leaks/pastes/darkweb/phonebook). "
                           "Por defecto, variable de entorno INTELX_API_KEY.")
    ext.add_argument("--dnsdumpster-key", default=os.environ.get("DNSDUMPSTER_API_KEY"),
                      help="API key de DNSDumpster (subdominios, fuente adicional a crt.sh/"
                           "Certspotter que ya se consultan siempre y son gratis). "
                           "Por defecto, variable de entorno DNSDUMPSTER_API_KEY.")
    ext.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"),
                      help="API key de VirusTotal (reputacion del dominio/IP: motores que lo "
                           "marcan malicioso, categorias detectadas; hay tier gratuito). "
                           "Por defecto, variable de entorno VT_API_KEY.")
    ext.add_argument("--censys-id", default=os.environ.get("CENSYS_API_ID"),
                     help="Censys API ID (hosts y puertos por dominio). Va junto a --censys-secret.")
    ext.add_argument("--censys-secret", default=os.environ.get("CENSYS_API_SECRET"),
                     help="Censys API secret.")
    ext.add_argument("--fofa-email", default=os.environ.get("FOFA_EMAIL"),
                     help="Email de la cuenta FOFA (va junto a --fofa-key).")
    ext.add_argument("--fofa-key", default=os.environ.get("FOFA_API_KEY"),
                     help="API key de FOFA (hosts y puertos por dominio).")
    ext.add_argument("--hibp-key", default=os.environ.get("HIBP_API_KEY"),
                     help="API key de Have I Been Pwned: busca los correos encontrados en brechas.")
    ext.add_argument("--domscan-key", default=os.environ.get("DOMSCAN_API_KEY"),
                     help="API key de DomScan: selectores DKIM del dominio.")
    ext.add_argument("--otx-key", default=os.environ.get("OTX_API_KEY"),
                     help="API key de AlienVault OTX (gratuita): DNS pasivo, subdominios e IPs "
                          "que OTX ha visto resolver historicamente para el dominio.")
    ext.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY"),
                      help="API key de AbuseIPDB (reputacion de la IP: reportes de "
                           "botnet/spam/escaneos/fuerza bruta; hay tier gratuito). "
                           "Por defecto, variable de entorno ABUSEIPDB_API_KEY.")

    if len(sys.argv) == 1 and sys.stdin.isatty():
        return p.parse_args(run_wizard())
    return p.parse_args()


def resolve_save_docs(args) -> bool:
    if args.no_download:
        return False
    if args.save_docs is not None:
        return args.save_docs
    if args.yes or not sys.stdin.isatty():
        return True
    return Confirm.ask(
        "[bold]¿Quieres guardar los documentos descargados en disco?[/bold] "
        "(si dices que no, solo se guardan sus metadatos)",
        default=True,
    )


def is_high_severity(f: Finding) -> bool:
    """Leak confirmado, credencial encontrada, o bucket de almacenamiento
    en la nube expuesto publicamente (GrayHatWarfare) - todo esto merece
    resaltarse en vivo y contar para --fail-on-leak."""
    return f.category in ("leak", "bucket") or bool(f.secrets)


def format_event_plain(evt: dict) -> str | None:
    """Version sin markup de rich, para el --log-file."""
    t = evt["type"]
    if t == "dork_start":
        return f"[{evt['index']}/{evt['total']}] {evt['name']}: {evt['query']}"
    if t == "dork_results":
        return f"  -> {evt['count']} resultado(s)"
    if t == "processing":
        return f"    descargando/analizando: {evt['url']}"
    if t == "discarded":
        return f"    descartado ({evt['category']}): {evt['url']} -- {evt['reason']}"
    if t == "external_start":
        return f"consultando fuente externa: {evt['source']}"
    if t == "recursive_plan":
        return f"subdominios a escanear ({evt['count']}): {', '.join(evt['subdomains'])}"
    if t == "recursive_start":
        return f"=== escaneando subdominio: {evt['domain']} ==="
    if t == "recursive_none":
        return "no se encontraron subdominios para escanear recursivamente"
    if t == "recursive_error":
        return f"error escaneando subdominio {evt['domain']}: {evt['reason']}"
    if t == "finding":
        f: Finding = evt["finding"]
        if is_high_severity(f):
            return f"    [LEAK] {f.url}"
        return None
    if t == "aborted":
        return f"ABORTADO: {evt['reason']}"
    if t == "warning":
        return f"AVISO: {evt['message']}"
    if t == "done":
        return "--- escaneo finalizado ---"
    return None


def make_console_reporter(quiet: bool, verbose: bool, log_fh, state: dict):
    """Callback de progreso: imprime cada evento en pantalla al vuelo (para
    que nunca parezca que el programa se ha quedado colgado), respetando
    --quiet/--verbose, y opcionalmente lo vuelca tambien a --log-file.
    `state` es un dict compartido con el llamador para comunicar hacia
    afuera si hubo un aborto (necesario para decidir el codigo de salida)."""
    def on_event(evt):
        t = evt["type"]

        if log_fh:
            line = format_event_plain(evt)
            if line is not None:
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] {line}", file=log_fh, flush=True)

        if t == "aborted":
            state["aborted"] = evt["reason"]
            console.print(f"[bold red]Abortando:[/bold red] {evt['reason']}")
            return
        if t == "warning":
            console.print(f"[bold yellow]Aviso:[/bold yellow] {evt['message']}")
            return
        if t == "recursive_plan":
            console.print(f"\n[bold cyan]Subdominios a escanear ({evt['count']}):[/bold cyan] "
                           f"{', '.join(evt['subdomains'])}")
            return
        if t == "recursive_start":
            console.print(f"\n[bold magenta]═══ Escaneando subdominio: {evt['domain']} ═══[/bold magenta]")
            return
        if t == "recursive_none":
            console.print("[dim]No se encontraron subdominios para escanear recursivamente.[/dim]")
            return
        if t == "recursive_error":
            console.print(f"[bold yellow]Aviso:[/bold yellow] fallo en {evt['domain']}: {evt['reason']}")
            return
        if t == "finding":
            f: Finding = evt["finding"]
            if is_high_severity(f):
                console.print(f"    [bold red]![/bold red] posible leak: {f.url}")
            return

        if quiet:
            return  # el resto del progreso (dork_start/results/processing/discarded) se omite

        if t == "dork_start":
            console.print(f"[dim]({evt['index']}/{evt['total']})[/dim] {evt['name']}: "
                           f"[italic]{evt['query']}[/italic]")
        elif t == "dork_results":
            console.print(f"  -> {evt['count']} resultado(s)")
        elif t == "processing":
            console.print(f"    [dim]descargando/analizando:[/dim] {evt['url']}")
        elif t == "external_start":
            console.print(f"[dim]>[/dim] Consultando fuente externa: [italic]{evt['source']}[/italic]")
        elif t == "discarded" and verbose:
            console.print(f"    [dim]descartado ({evt['category']}): {evt['url']} -- {evt['reason']}[/dim]")

    return on_event


def run(args) -> int:
    domain = normalize_domain(args.domain)
    if domain != args.domain:
        console.print(f"[dim]Dominio normalizado: {args.domain!r} -> {domain}[/dim]")
    out_dir = Path(args.out_dir) / domain
    out_dir.mkdir(parents=True, exist_ok=True)

    save_docs = resolve_save_docs(args)
    # Por defecto: todo (VALID_CATEGORIES). --categories restringe a un
    # subconjunto puntual; --exclude-categories resta del set completo sin
    # tener que enumerar el resto (ej. sacar solo "ports" si no hay
    # autorizacion para escaneo activo). --all queda como alias legacy.
    if args.categories:
        categories = args.categories
    elif args.exclude_categories:
        categories = VALID_CATEGORIES - args.exclude_categories
    else:
        categories = VALID_CATEGORIES
    external_keys = {
        "shodan": args.shodan_key,
        "grayhatwarfare": args.ghw_key,
        "intelx": args.intelx_key,
        "dnsdumpster": args.dnsdumpster_key,
        "virustotal": args.vt_key,
        "abuseipdb": args.abuseipdb_key,
        "censys": (args.censys_id, args.censys_secret),
        "fofa": (args.fofa_email, args.fofa_key),
        "hibp": args.hibp_key,
        "domscan": args.domscan_key,
        "otx": args.otx_key,
    }

    log_fh = open(args.log_file, "a") if args.log_file else None
    state: dict = {}

    if not args.quiet:
        cats_label = "todas" if categories == VALID_CATEGORIES else ", ".join(sorted(categories))
        extra = f"  [bold cyan]Categorias:[/bold cyan] {cats_label}"
        if args.recursive:
            extra += f"  [bold cyan]Recursivo:[/bold cyan] si (hasta {args.max_subdomains} subdominios)"
        console.print(f"[bold cyan]Objetivo:[/bold cyan] {domain}  "
                       f"[bold cyan]Guardar documentos:[/bold cyan] {'si' if save_docs else 'no'}{extra}\n")

    try:
        results = run_scan_recursive(
            domain, out_dir,
            searxng_endpoints=args.searxng, proxies=args.proxy,
            min_delay=args.min_delay, max_delay=args.max_delay,
            save_docs=save_docs, no_download=args.no_download,
            categories=categories, external_keys=external_keys,
            recursive=args.recursive, recursive_categories=args.recursive_categories,
            max_subdomains=args.max_subdomains,
            on_event=make_console_reporter(args.quiet, args.verbose, log_fh, state),
        )
    finally:
        if log_fh:
            log_fh.close()

    if not args.quiet:
        for host, host_findings in results.items():
            console.print(f"\n[bold cyan]── {host} ──[/bold cyan]")
            print_dns_table(host_findings)
            print_tls_table(host_findings)
            print_documents_table(host_findings)
            print_sensitive_table(host_findings)
            print_platform_table(host_findings)
            print_emails_paths_table(host_findings)
            print_email_osint_table(host_findings)
            print_org_chart_table(host_findings)
            print_external_osint_table(host_findings)
            print_typosquat_table(host_findings)
            print_ports_table(host_findings)
            print_tech_table(host_findings)
            print_vuln_table(host_findings)
    for host_findings in results.values():
        print_risk_score(host_findings)
        print_summary(host_findings)

    # export_all() escribe un unico informe completo por corrida (ver
    # report_export.py): si hay un solo host, igual que siempre; si hay
    # varios (--recursive encontro subdominios), un solo informe combinado
    # en out_dir en vez de informe.* + informe-maestro.* por separado.
    all_findings = export_all(results, domain, out_dir, logos_dir=args.logos_dir, latex_pdf=args.latex_pdf)

    console.print(f"\n[green]Carpeta de salida:[/green] {out_dir}")
    if len(results) > 1:
        console.print(f"  [bold]{len(results)} hosts escaneados[/bold] "
                       f"({domain} + {len(results) - 1} subdominio(s))")
        console.print("  [bold]informe.txt / .xlsx / .docx[/bold] en la carpeta del dominio ya "
                       "incluye TODOS los hosts juntos (columna Host en cada hoja/tabla); cada "
                       "subdominio ademas tiene su propio informe completo en subdominios/<subdominio>/")
    if not args.quiet:
        red_note = "red.dot / red.png / red.json" if shutil.which("dot") else \
            "red.dot / red.json (instala graphviz para tambien generar red.png)"
        if not args.latex_pdf:
            tex_note = "informe.tex / cyber_health_check.tex (sin compilar a PDF, --no-latex-pdf)"
        elif shutil.which("pdflatex"):
            tex_note = "informe.tex/.pdf / cyber_health_check.tex/.pdf"
        else:
            tex_note = "informe.tex / cyber_health_check.tex (sin pdflatex instalado, no se compilo a PDF)"
        console.print("  informe.txt / informe.docx / informe.xlsx / cyber_health_check.docx / "
                       f"{tex_note} / informe.md / cyber_health_check.md (texto en bruto editable) / "
                       f"maltego.csv / resultados.json,csv / {red_note}")
        if save_docs:
            console.print("  - documentos/ (ficheros descargados, por host)")

    if state.get("aborted"):
        return EXIT_ERROR

    leak_found = any(is_high_severity(f) for f in all_findings)
    if args.fail_on_leak and leak_found:
        return EXIT_LEAK_FOUND
    return EXIT_OK


def main():
    try:
        args = parse_args()
        sys.exit(run(args))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - error inesperado: reportar y salir con codigo de error
        console.print(f"[bold red]Error inesperado:[/bold red] {exc}")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
