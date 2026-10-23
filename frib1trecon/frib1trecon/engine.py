"""
Orquestador reutilizable del pipeline de escaneo: genera los dorks, consulta
SearXNG, descarga y analiza los resultados. Lo usan tanto la CLI (cli.py)
como la interfaz web (frib1trecon-web/), para no duplicar la logica.

Emite eventos de progreso via `on_event(dict)` para que quien lo use pueda
mostrar feedback en tiempo real (evita la sensacion de "se ha quedado
colgado" mientras se procesan documentos uno a uno).
"""
import re
import shutil
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from . import dorks as dorks_mod
from .cloud_buckets import scan_cloud_buckets
from .downloader import download
from .external_osint import (
    abuseipdb_report, search_certspotter, search_crtsh, search_dnsdumpster,
    search_grayhatwarfare, search_intelx, search_shodan, search_wayback,
    virustotal_domain_report, virustotal_ip_report,
)
from .metadata import (
    SUSPICIOUS_FILENAME_RE, extract_gps, extract_office_metadata, extract_text,
    find_computer_names, find_internal_paths, is_interesting_listing_entry,
    parse_directory_listing, scan_for_emails, scan_for_secrets,
    scan_file_with_trufflehog, scan_text_for_secrets,
)
from .report import Finding
from .search import SearxngClient, TooManyFailures
from .dns_whois import (
    check_dkim, check_dmarc, check_dnssec, check_spf, check_zone_transfer,
    get_dns_records, whois_lookup,
)
from .eol_check import check_eol
from .fingerprint import fingerprint_url
from .ports_services import resolve_ip, scan_services, server_header_version
from .subdomain_bruteforce import bruteforce_subdomains
from .takeover import check_takeover
from .sensitive_paths import check_sensitive_paths
from .cms_detect import detect_cms
from .waf_detect import detect_waf
from .file_sharing import find_exposed_files
from .keyed_sources import censys_hosts, domscan_dkim, fofa_search, hibp_breaches, otx_passive_dns
from .cms_checks import run_cms_checks
from .wayback_check import check_wayback_live
from .tls_headers import check_tls, check_web_headers
from .typosquatting import (
    fetch_extra_variants, generate_domain_squatting_candidates,
    generate_typosquat_candidates, resolve_candidates,
)
from .vuln_lookup import lookup_vulnerabilities


def normalize_domain(raw: str) -> str:
    """Acepta tanto 'site.com' como una URL completa pegada del navegador
    ('https://site.com/algo', 'http://www.site.com:8080/') y siempre
    devuelve el hostname desnudo en minusculas, sin esquema, sin ruta, sin
    puerto y sin barra final. Error de usuario muy comun (pegar la URL
    entera en vez del dominio) que si no se corrige aqui, en el unico
    punto de entrada, rompe en cascada: DNS/TLS fallan porque intentan
    resolver literalmente 'https://site.com/' como hostname, las dork
    queries salen mal formadas (site:https://site.com/), el escaneo de
    puertos no puede resolver nada, y la carpeta de salida sale con los
    '/' de la URL convertidos en subcarpetas (p.ej. 'https:/site.com/')."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "//" + raw  # para que urlparse reconozca el host aunque no haya esquema
    netloc = urlparse(raw).netloc
    host = netloc.rsplit("@", 1)[-1].rsplit(":", 1)[0]  # quita user:pass@ y :puerto si los hubiera
    return (host or raw.lstrip("/")).strip(".").lower()


def matches_ext(url: str, ext: str) -> bool:
    return url.split("?")[0].lower().endswith(f".{ext}")


GITHUB_BLOB_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")


def fetch_url_for(url: str) -> str:
    """La pagina 'blob' de GitHub (el visor web) es una SPA en React: un
    GET normal solo trae el esqueleto de la pagina (menus, texto de
    marketing de GitHub), nunca el contenido real del fichero. Para poder
    analizar el fichero de verdad hay que pedir la version 'raw'."""
    m = GITHUB_BLOB_RE.match(url)
    if not m:
        return url
    owner, repo, ref, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def url_matches_domain(url: str, domain: str) -> bool:
    """True si el host de `url` es el dominio objetivo o un subdominio suyo.
    Necesario porque el "site:" de los dorks no siempre se respeta (algunos
    motores detras de SearXNG lo tratan como una pista mas, no un filtro
    estricto), y sin esta comprobacion cuelan resultados de otros dominios
    que ni siquiera mencionan el objetivo."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    domain = domain.lower()
    return host == domain or host.endswith(f".{domain}")


def process_result(r, dork, domain, work_dir: Path, save_docs: bool) -> Finding:
    finding = Finding(
        category=dork["category"], dork_name=dork["name"],
        query=dork["query"], url=r.url, engine=r.engine,
        filetype=dork["ext"], title=r.title,
    )

    local_path = download(r.url, work_dir)
    if not local_path:
        finding.note = "descarga fallida"
        return finding

    if dork["category"] == "document":
        meta = extract_office_metadata(local_path)
        finding.author = meta.get("Author")
        finding.last_modified_by = meta.get("LastModifiedBy")
        finding.software = meta.get("Software") or meta.get("Producer") or meta.get("Application")
        finding.company = meta.get("Company")
        finding.manager = meta.get("Manager")
        finding.created = str(meta.get("CreateDate") or "")
        finding.modified = str(meta.get("ModifyDate") or "")
        finding.internal_paths = find_internal_paths(meta)
        finding.secrets = scan_file_with_trufflehog(local_path)
        if dork["ext"] in ("jpg", "jpeg", "png", "tiff"):
            # contenido binario: no tiene sentido tratarlo como texto para
            # buscar emails/rutas (solo ruido), pero si puede llevar GPS
            finding.gps = extract_gps(local_path)
            finding.computers = find_computer_names(*meta.values())
        else:
            text = extract_text(local_path)
            finding.emails = scan_for_emails(text, domain=domain)
            finding.computers = find_computer_names(*meta.values(), text)
    else:  # sensitive
        finding.secrets = scan_for_secrets(local_path)
        finding.secrets += scan_file_with_trufflehog(local_path)
        text = extract_text(local_path)
        finding.emails = scan_for_emails(text, domain=domain)
        finding.computers = find_computer_names(text)

    if save_docs:
        finding.local_path = str(local_path)
    else:
        local_path.unlink(missing_ok=True)

    return finding


def process_email_result(r, dork, domain, work_dir: Path, save_docs: bool, no_download: bool) -> Finding | None:
    """Busca emails del dominio en una mencion encontrada en la web abierta
    (no solo en documentos). Primero mira el fragmento que ya devuelve el
    buscador (gratis); si no vamos en modo --no-download, tambien baja la
    pagina completa y raspa su texto visible en busca de mas direcciones.
    Devuelve None si no se encuentra ningun email (para no llenar el
    informe de paginas que solo mencionan el dominio sin exponer un email).
    """
    emails = set(scan_for_emails(f"{r.title} {r.content}", domain=domain))
    local_path = None

    if not no_download:
        local_path = download(r.url, work_dir)
        if local_path:
            emails.update(scan_for_emails(extract_text(local_path), domain=domain))
            if not save_docs:
                local_path.unlink(missing_ok=True)
                local_path = None

    # esta busqueda es sin site: (abierta a toda la web), y nombres de
    # dominio con palabras comunes (p.ej. "sansebas") hacen que los motores
    # devuelvan paginas de negocios homonimos no relacionados. Si la pagina
    # no tiene NINGUN email realmente @dominio, se descarta entera en vez
    # de reportar emails de terceros sin relacion.
    domain_suffix = f"@{domain.lower()}"
    domain_emails = {e for e in emails if e.lower().endswith(domain_suffix)}
    if not domain_emails:
        return None

    return Finding(
        category="email", dork_name=dork["name"], query=dork["query"],
        url=r.url, engine=r.engine, title=r.title, emails=sorted(domain_emails),
        local_path=str(local_path) if local_path else None,
    )


ADMIN_URL_HINTS = ("admin", "login", "panel", "dashboard", "wp-admin")

# una URL "desnuda" tipo github.com/<usuario> (sin /blob/, /issues/...) es
# un perfil de usuario u organizacion, no un fichero: nunca va a contener
# un patron de credencial, asi que el filtro secret_pattern la descartaba
# siempre aunque el propio nombre de usuario revele un empleado real
# (p.ej. "github.com/usuario-ejemplo"). Se trata aparte como hallazgo
# informativo en vez de tirarla sin mas.
CODE_PROFILE_RE = re.compile(r"^https?://(?:www\.)?(github|gitlab|bitbucket)\.(?:com|org)/([A-Za-z0-9_.-]+)/?$")

# tope de ficheros que se descargan de verdad de un directorio abierto para
# analizarlos (solo los que ya tienen pinta sensible por nombre/extension,
# ver is_interesting_listing_entry): un directorio con cientos de ficheros
# no debe disparar cientos de peticiones sin control
MAX_LISTING_DOWNLOADS = 8


def process_leak_result(r, dork, domain, work_dir: Path, save_docs: bool, no_download: bool) -> Finding | None:
    """Verifica en local si un resultado candidato a 'leak' lo es de
    verdad, en vez de confiar en que el motor de busqueda entendiera bien
    operadores tipo OR/intitle:/inurl:. Devuelve None si no se confirma
    (asi el informe no se llena de ruido generico de la plataforma)."""
    filt = dork.get("leak_filter", "secret_pattern")
    url_lower = r.url.lower()

    if filt in ("url_admin", "index_of"):
        # estos dos dorks usan site:{domain}, asi que el resultado debe
        # estar de verdad en el dominio objetivo (el "site:" no siempre se
        # respeta y cuelan paginas de otros sitios que ni lo mencionan).
        if not url_matches_domain(r.url, domain):
            return None

    if filt == "url_admin":
        if not any(hint in url_lower for hint in ADMIN_URL_HINTS):
            return None
        return Finding(
            category="leak", dork_name=dork["name"], query=dork["query"],
            url=r.url, engine=r.engine, title=r.title,
            note="URL con patron de panel/login de administracion",
        )

    if filt == "index_of":
        # el simple "contiene la frase 'index of'" da muchos falsos
        # positivos (p.ej. "the refractometric index of the pulp..." en un
        # catalogo de productos). Un listado de directorio real de Apache/
        # Nginx tiene el titulo literalmente "Index of /ruta" y suele
        # incluir "Parent Directory" en el cuerpo; exigimos uno de los dos.
        title_lower = (r.title or "").lower().strip()
        content_lower = (r.content or "").lower()
        looks_like_listing = title_lower.startswith("index of") or "parent directory" in content_lower
        if not looks_like_listing:
            return None

        finding = Finding(
            category="leak", dork_name=dork["name"], query=dork["query"],
            url=r.url, engine=r.engine, title=r.title,
            note="directorio abierto (listado de ficheros)",
        )
        if no_download:
            return finding

        index_path = download(r.url, work_dir)
        if not index_path:
            return finding
        try:
            html = index_path.read_text(errors="ignore")
        except OSError:
            html = ""
        if not save_docs:
            index_path.unlink(missing_ok=True)

        entries = parse_directory_listing(html, r.url)
        if not entries:
            return finding

        # de los ficheros listados, solo se descargan y analizan de verdad
        # los que tienen pinta sensible (nombre sospechoso o extension tipo
        # txt/sql/env/bak/...), con un tope para no disparar peticiones sin
        # fin contra un directorio con cientos de ficheros
        interesting = [e for e in entries if is_interesting_listing_entry(e["name"])]
        interesting.sort(key=lambda e: 0 if SUSPICIOUS_FILENAME_RE.search(e["name"]) else 1)
        to_scan = interesting[:MAX_LISTING_DOWNLOADS]

        found_secrets = set()
        scanned_names = []
        for entry in to_scan:
            sub_path = download(entry["url"], work_dir)
            if not sub_path:
                continue
            scanned_names.append(entry["name"])
            found_secrets.update(scan_for_secrets(sub_path))
            found_secrets.update(scan_file_with_trufflehog(sub_path))
            if not save_docs:
                sub_path.unlink(missing_ok=True)

        names_preview = ", ".join(e["name"] for e in entries[:30])
        more = f" (+{len(entries) - 30} mas)" if len(entries) > 30 else ""
        note_lines = [f"directorio abierto, {len(entries)} fichero(s): {names_preview}{more}"]
        if interesting:
            scanned_note = f" (analizados: {', '.join(scanned_names)})" if scanned_names else ""
            note_lines.append(f"{len(interesting)} con nombre/extension sensible{scanned_note}")
        finding.note = "\n".join(note_lines)
        finding.secrets = sorted(found_secrets)
        return finding

    # "secret_pattern" (por defecto): exigir un patron de credencial real,
    # no solo que la plataforma+dominio aparezcan en la busqueda.
    page_text = f"{r.title} {r.content}"
    secrets = set(scan_text_for_secrets(page_text))
    local_path = None
    if not no_download:
        # paginas "blob" de GitHub: pedir la version raw, si no el contenido
        # real del fichero nunca se ve (ver fetch_url_for)
        local_path = download(fetch_url_for(r.url), work_dir)
        if local_path:
            downloaded_text = extract_text(local_path)
            page_text += f" {downloaded_text}"
            secrets.update(scan_text_for_secrets(downloaded_text))
            secrets.update(scan_file_with_trufflehog(local_path))
            if not save_docs:
                local_path.unlink(missing_ok=True)
                local_path = None

    # el dork busca site:plataforma "dominio" por relevancia, no por
    # coincidencia exacta: el motor a veces devuelve paginas que no
    # contienen el dominio literalmente (solo "parecen" relevantes). Si el
    # secreto encontrado esta en una pagina asi, puede pertenecer a otra
    # persona/proyecto sin relacion real con el objetivo -> se marca para
    # que se revise a mano en vez de darlo por hecho.
    domain_mentioned = domain.lower() in page_text.lower()

    if not secrets and SUSPICIOUS_FILENAME_RE.search(urlparse(r.url).path):
        # el contenido no dio ningun patron (puede que no se haya podido
        # descargar/leer), pero el propio nombre del fichero ya es sospechoso
        # (private.json, id_rsa, wp-config...): se reporta igual, marcado
        # aparte, para que se revise a mano.
        return Finding(
            category="leak", dork_name=dork["name"], query=dork["query"],
            url=r.url, engine=r.engine, title=r.title,
            note="nombre de fichero sospechoso (revisar a mano)",
            local_path=str(local_path) if local_path else None,
        )

    if not secrets:
        # no es un leak de credenciales, pero si es un perfil de
        # usuario/organizacion cuyo nombre coincide con la empresa, es
        # OSINT valido por si mismo (cuenta de un posible empleado) y no
        # deberia tirarse sin mas
        m = CODE_PROFILE_RE.match(r.url)
        if m:
            platform, slug = m.groups()
            domain_keyword = domain.split(".")[0].lower()
            if domain_keyword in slug.lower():
                return Finding(
                    category="platform", dork_name=f"Cuenta de {platform} (posible empleado)",
                    query=dork["query"], url=r.url, engine=r.engine, title=r.title,
                    note=f"usuario/organizacion '{slug}' coincide con el nombre de la empresa",
                )
        return None

    return Finding(
        category="leak", dork_name=dork["name"], query=dork["query"],
        url=r.url, engine=r.engine, title=r.title, secrets=sorted(secrets),
        local_path=str(local_path) if local_path else None,
        note=(
            "" if domain_mentioned else
            f"AVISO: '{domain}' no aparece literalmente en esta pagina, puede "
            "ser una mencion incidental de otro proyecto/persona sin relacion "
            "con el objetivo; revisar a mano si el secreto pertenece de verdad"
        ),
    )


LINKEDIN_TITLE_RE = re.compile(
    r"^(?P<name>[^|\-]+?)\s*(?:[-–]\s*(?P<role>[^|\-]+?))?\s*(?:[-–]\s*(?P<company>[^|\-]+?))?\s*\|\s*LinkedIn",
    re.IGNORECASE,
)
ROLE_AT_RE = re.compile(r"^(?P<role>.+?)\s+(?:at|en|chez)\s+(?P<company>.+?)(?:[.·]|$)", re.IGNORECASE)

# nivel de seniority aproximado, solo por palabras clave del puesto, para
# agrupar el organigrama. No es una jerarquia real (LinkedIn no expone
# relaciones de jefatura en los resultados de busqueda publicos).
SENIORITY_KEYWORDS = [
    ("1-direccion", ("ceo", "cto", "cfo", "coo", "chief", "founder", "fundador",
                      "director", "presidente", "president", "vp ", "vicepresidente")),
    ("2-mandos", ("manager", "gerente", "jefe", "jefa", "head of", "lead", "responsable",
                   "coordinador", "coordinator", "supervisor")),
]


ROLE_KEYWORDS = (
    "manager", "director", "engineer", "developer", "analyst", "consultant",
    "specialist", "coordinator", "officer", "president", "ceo", "cto", "cfo",
    "coo", "head of", "lead", "chief", "founder", "owner", "assistant",
    "representative", "executive", "intern", "vp ", "técnico", "tecnico",
    "gerente", "responsable", "jefe", "jefa", "ingeniero", "ingeniera",
    "desarrollador", "desarrolladora", "analista", "consultor", "consultora",
    "especialista", "coordinador", "coordinadora", "presidente", "fundador",
    "fundadora", "propietario", "propietaria", "asistente", "representante",
    "ejecutivo", "ejecutiva", "becario", "becaria", "auxiliar",
)


def _looks_like_role(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in ROLE_KEYWORDS)


def parse_linkedin_result(title: str, content: str) -> tuple[str | None, str | None, str | None]:
    """Extrae nombre, puesto Y empresa de un resultado de busqueda de
    LinkedIn. Best-effort: el formato del snippet varia, asi que esto es
    heuristico, no un parser garantizado. La empresa es la clave para
    poder verificar despues que la persona de verdad trabaja en el
    dominio objetivo, en vez de solo mencionarlo de pasada."""
    title = title or ""
    m = LINKEDIN_TITLE_RE.match(title)
    name = role = company = None
    if m:
        name = (m.group("name") or "").strip() or None
        role = (m.group("role") or "").strip() or None
        company = (m.group("company") or "").strip() or None
    if not name:
        parts = re.split(r"\s*[|–-]\s*", title, maxsplit=1)
        candidate = parts[0].strip() if parts else ""
        name = candidate or None

    # ambiguedad clasica: "Nombre - X | LinkedIn" con un solo segmento extra
    # puede ser "Nombre - Puesto" (sin empresa en el titulo) o
    # "Nombre - Empresa" (sin puesto en el titulo). El regex siempre lo
    # mete en "role" por ser el primer grupo opcional; si ese texto NO
    # tiene pinta de puesto (no contiene ninguna palabra clave de cargo),
    # es mas probable que sea el nombre de la empresa.
    if role and not company and not _looks_like_role(role):
        company = role
        role = None

    m2 = ROLE_AT_RE.match(content or "")
    if m2:
        if not role:
            role = m2.group("role").strip()
        if not company:
            company = m2.group("company").strip()
    return name, role, company


def company_matches_domain(company: str | None, domain: str) -> bool:
    """True si el nombre de empresa extraido del perfil parece
    corresponder al dominio objetivo (comparando con el nombre del dominio
    sin el TLD, p.ej. 'biosabor.com' -> 'biosabor'). Si no hay empresa
    extraida, devuelve None-like (no hay nada que verificar, no es ni
    confirmacion ni contradiccion)."""
    if not company:
        return None
    company_lower = company.lower()
    domain_keyword = domain.split(".")[0].lower()
    return domain_keyword in company_lower or company_lower in domain_keyword


def guess_seniority(role: str | None) -> str:
    role_lower = (role or "").lower()
    for label, keywords in SENIORITY_KEYWORDS:
        if any(kw in role_lower for kw in keywords):
            return label
    return "3-resto"


def process_people_result(r, dork, domain) -> Finding | None:
    """Convierte un resultado de busqueda en LinkedIn en un Finding de
    categoria 'people', si se puede extraer un nombre de persona creible
    Y la empresa del perfil (cuando se puede leer) coincide con el dominio
    objetivo. No se descarga la pagina de LinkedIn (requiere login para
    casi todo el contenido y hacerlo seria scraping activo contra sus
    protecciones; nos quedamos con el fragmento que ya da el buscador).

    Antes solo exigiamos que el dominio apareciera en algun sitio del
    resultado, lo que colaba gente que trabaja en otra empresa distinta y
    solo mencionaba el dominio de pasada (visto en pruebas reales: un
    empleado de Holcim España salio como si fuera de la empresa objetivo).
    Ahora, si se puede leer el nombre de la empresa en el perfil, se
    descarta explicitamente cuando no coincide con el dominio."""
    name, role, company = parse_linkedin_result(r.title, r.content)
    if not name or len(name.split()) < 2 or any(ch.isdigit() for ch in name):
        return None

    match = company_matches_domain(company, domain)
    if match is False:
        return None  # se pudo leer la empresa y es claramente otra distinta

    role = role or "(puesto no detectado)"
    note = "" if match else "empresa sin confirmar en el fragmento (no descartar a ciegas)"
    return Finding(
        category="people", dork_name=dork["name"], query=dork["query"],
        url=r.url, engine=r.engine, title=r.title, note=note,
        person_name=name, role=role, seniority=guess_seniority(role),
    )


def run_external_osint(domain: str, api_keys: dict, emit) -> list[Finding]:
    """Consulta fuentes OSINT externas (no son dorks de SearXNG, son APIs
    dedicadas). Shodan InternetDB es gratis y no necesita key; GrayHatWarfare
    e IntelX solo se consultan si hay una api_key en `api_keys`."""
    findings: list[Finding] = []
    api_keys = api_keys or {}

    emit({"type": "external_start", "source": "Shodan"})
    for h in search_shodan(domain, api_keys.get("shodan")):
        ip = h.get("_ip", "")
        ports = ", ".join(str(p) for p in h.get("ports", []) or [])
        hostnames = ", ".join(h.get("hostnames", []) or [])
        vulns = ", ".join(h.get("vulns", []) or [])
        findings.append(Finding(
            category="shodan", dork_name=f"Shodan ({h.get('_source', '')})", query=domain,
            url=f"https://www.shodan.io/host/{ip}", title=ip,
            note=f"puertos: {ports or '-'} | hostnames: {hostnames or '-'} | vulns: {vulns or '-'}",
            computers=sorted(set(h.get("hostnames", []) or [])),
        ))

    vt_key = api_keys.get("virustotal")
    abuseipdb_key = api_keys.get("abuseipdb")
    if vt_key or abuseipdb_key:
        try:
            ip = socket.gethostbyname(domain)
        except OSError:
            ip = None

        if vt_key:
            emit({"type": "external_start", "source": "VirusTotal"})
            vt_domain = virustotal_domain_report(domain, vt_key)
            if vt_domain:
                cats = ", ".join(vt_domain["categories"]) or "-"
                findings.append(Finding(
                    category="reputation", dork_name="VirusTotal (reputacion dominio)", query=domain,
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    title=f"{vt_domain['malicious']}/{vt_domain['malicious'] + vt_domain['suspicious'] + vt_domain['harmless'] + vt_domain['undetected']} motores marcan malicioso",
                    note=f"malicioso={vt_domain['malicious']} sospechoso={vt_domain['suspicious']} "
                         f"limpio={vt_domain['harmless']} reputacion comunidad={vt_domain['reputation']} "
                         f"categorias={cats}",
                ))
            if ip:
                vt_ip = virustotal_ip_report(ip, vt_key)
                if vt_ip:
                    findings.append(Finding(
                        category="reputation", dork_name="VirusTotal (reputacion IP)", query=domain,
                        url=f"https://www.virustotal.com/gui/ip-address/{ip}", title=ip,
                        note=f"malicioso={vt_ip['malicious']} sospechoso={vt_ip['suspicious']} "
                             f"limpio={vt_ip['harmless']} AS={vt_ip['as_owner'] or '-'} "
                             f"pais={vt_ip['country'] or '-'}",
                    ))

        if abuseipdb_key and ip:
            emit({"type": "external_start", "source": "AbuseIPDB"})
            abuse = abuseipdb_report(ip, abuseipdb_key)
            if abuse:
                findings.append(Finding(
                    category="reputation", dork_name="AbuseIPDB (reputacion IP)", query=domain,
                    url=f"https://www.abuseipdb.com/check/{ip}", title=ip,
                    note=f"confianza de abuso={abuse['abuse_confidence_score']}% "
                         f"({abuse['total_reports']} reporte(s)) | ISP={abuse['isp'] or '-'} "
                         f"| tipo de uso={abuse['usage_type'] or '-'} "
                         f"| pais={abuse['country_code'] or '-'} "
                         f"| ultimo reporte={abuse['last_reported_at'] or '-'}",
                ))

    emit({"type": "external_start", "source": "Buckets cloud activos (S3/GCS/Azure, sin api key)"})
    bucket_scan = scan_cloud_buckets(domain)
    for b in bucket_scan["findings"]:
        # solo los PUBLICOS (listado abierto) se reportan como "bucket":
        # esa categoria se trata como leak critico en todo el pipeline
        # (--fail-on-leak, contadores). Un bucket que solo "existe pero es
        # privado" (nombre comun ya registrado por otra cuenta cualquiera
        # en el namespace global de AWS/GCS) no es una vulnerabilidad del
        # dominio analizado y generaria muchisimo ruido/falsos positivos
        # de severidad si se incluyera aqui.
        if b["severity"] != "critical":
            continue
        findings.append(Finding(
            category="bucket", dork_name=f"Bucket activo ({b['provider']})", query=domain,
            url=b["url"], title=b["status"],
            note=f"nombre candidato={b['name']}",
        ))

    ghw_key = api_keys.get("grayhatwarfare")
    if ghw_key:
        emit({"type": "external_start", "source": "GrayHatWarfare"})
        for f in search_grayhatwarfare(domain, ghw_key):
            findings.append(Finding(
                category="bucket", dork_name="GrayHatWarfare", query=domain,
                url=f.get("url", ""), title=f.get("filename"),
                note=f"bucket={f.get('bucket', '-')} tipo={f.get('type', '-')} "
                     f"tamano={f.get('size', '?')}B",
            ))

    intelx_key = api_keys.get("intelx")
    if intelx_key:
        emit({"type": "external_start", "source": "IntelX"})
        data = search_intelx(domain, intelx_key)
        for rec in data["records"]:
            findings.append(Finding(
                category="intelx", dork_name="IntelX (leaks/pastes/darkweb)", query=domain,
                url="", title=rec.get("name") or rec.get("systemid", ""),
                note=f"bucket={rec.get('bucket', '-')} fecha={rec.get('date', '-')}",
            ))
        for sel in data["selectors"]:
            value = sel.get("selectorvalue", "")
            if not value:
                continue
            finding = Finding(
                category="intelx", dork_name="IntelX (phonebook)", query=domain,
                url="", title=value,
                note=f"tipo={sel.get('selectortypeh', sel.get('selectortype', '-'))}",
            )
            if "@" in value:
                finding.emails = [value]
            findings.append(finding)

    # subdominios: se consultan varias fuentes independientes y se juntan,
    # porque crt.sh en concreto se cae/satura a menudo (visto repetidamente
    # en pruebas reales) y conviene no depender de una sola.
    emit({"type": "external_start", "source": "crt.sh (Certificate Transparency)"})
    subs_crtsh = set(search_crtsh(domain))

    emit({"type": "external_start", "source": "Certspotter"})
    subs_certspotter = set(search_certspotter(domain))

    dnsdumpster_key = api_keys.get("dnsdumpster")
    subs_dnsdumpster = set()
    if dnsdumpster_key:
        emit({"type": "external_start", "source": "DNSDumpster"})
        subs_dnsdumpster = set(search_dnsdumpster(domain, dnsdumpster_key))

    emit({"type": "external_start", "source": "Fuerza bruta DNS de subdominios (sin api key)"})
    subs_brute = set(bruteforce_subdomains(domain))

    otx_key = api_keys.get("otx")
    subs_otx: set[str] = set()
    if otx_key:
        emit({"type": "external_start", "source": "OTX AlienVault (DNS pasivo)"})
        subs_otx, _otx_ips = otx_passive_dns(domain, otx_key)

    subdomains = sorted(subs_crtsh | subs_certspotter | subs_dnsdumpster | subs_brute | subs_otx)
    censys_keys = api_keys.get("censys")
    if censys_keys and censys_keys[0] and censys_keys[1]:
        emit({"type": "external_start", "source": "Censys (hosts y puertos)"})
        for h in censys_hosts(domain, censys_keys[0], censys_keys[1]):
            findings.append(Finding(
                category="shodan", dork_name="Censys (host/puertos)", query=domain,
                url=f"https://search.censys.io/hosts/{h['ip']}", title=h["ip"],
                note=f"puertos: {', '.join(str(p) for p in h['ports']) or '-'}",
            ))
    fofa_keys = api_keys.get("fofa")
    if fofa_keys and fofa_keys[0] and fofa_keys[1]:
        emit({"type": "external_start", "source": "FOFA"})
        for row in fofa_search(domain, fofa_keys[0], fofa_keys[1]):
            findings.append(Finding(
                category="shodan", dork_name="FOFA (host/puerto)", query=domain,
                url=f"http://{row['ip']}:{row['port']}", title=row["ip"],
                note=f"host: {row['host']} | puerto: {row['port']}",
            ))

    vt_key_all = api_keys.get("virustotal")
    abuse_key_all = api_keys.get("abuseipdb")
    if (vt_key_all or abuse_key_all) and subdomains:
        main_ip = None
        try:
            main_ip = socket.gethostbyname(domain)
        except OSError:
            pass
        sub_ips = {}
        for sub in subdomains:
            try:
                ip_sub = socket.gethostbyname(sub)
            except OSError:
                continue
            if ip_sub != main_ip:
                sub_ips.setdefault(ip_sub, sub)
        for ip_sub, sub in sorted(sub_ips.items()):
            emit({"type": "external_start", "source": f"Reputacion IP {ip_sub} ({sub})"})
            if vt_key_all:
                vt_ip = virustotal_ip_report(ip_sub, vt_key_all)
                if vt_ip:
                    findings.append(Finding(
                        category="reputation", dork_name="VirusTotal (reputacion IP)", query=sub,
                        url=f"https://www.virustotal.com/gui/ip-address/{ip_sub}", title=ip_sub,
                        note=f"malicioso={vt_ip['malicious']} sospechoso={vt_ip['suspicious']} "
                             f"limpio={vt_ip['harmless']} AS={vt_ip['as_owner'] or '-'} "
                             f"pais={vt_ip['country'] or '-'} | subdominio={sub}",
                    ))
            if abuse_key_all:
                abuse = abuseipdb_report(ip_sub, abuse_key_all)
                if abuse:
                    findings.append(Finding(
                        category="reputation", dork_name="AbuseIPDB (reputacion IP)", query=sub,
                        url=f"https://www.abuseipdb.com/check/{ip_sub}", title=ip_sub,
                        note=f"confianza de abuso={abuse['abuse_confidence_score']}% "
                             f"({abuse['total_reports']} reporte(s)) | ISP={abuse['isp'] or '-'} "
                             f"| tipo de uso={abuse['usage_type'] or '-'} "
                             f"| pais={abuse['country_code'] or '-'} | subdominio={sub}",
                    ))
    emit({"type": "external_start", "source": "Subdomain takeover (CNAME a proveedores)"})
    for t in check_takeover(subdomains):
        findings.append(Finding(
            category="leak", dork_name=f"Subdomain takeover ({t['provider']})", query=domain,
            url=f"https://{t['subdomain']}", title="Posible subdomain takeover",
            note=f"CNAME -> {t['cname']}: el recurso del proveedor ya no existe; cualquiera "
                 f"que lo reclame puede servir contenido bajo {t['subdomain']}",
        ))
    if subdomains:
        sources = []
        if subs_brute:
            sources.append(f"fuerza bruta:{len(subs_brute)}")
        if subs_otx:
            sources.append(f"OTX:{len(subs_otx)}")
        if subs_crtsh:
            sources.append(f"crt.sh:{len(subs_crtsh)}")
        if subs_certspotter:
            sources.append(f"Certspotter:{len(subs_certspotter)}")
        if subs_dnsdumpster:
            sources.append(f"DNSDumpster:{len(subs_dnsdumpster)}")
        preview = ", ".join(subdomains[:60])
        if len(subdomains) > 60:
            preview += f" ... (+{len(subdomains) - 60} mas, ver resultados.json)"
        findings.append(Finding(
            category="subdomains", dork_name=f"Subdominios ({' + '.join(sources)})", query=domain,
            url=f"https://crt.sh/?q=%.{domain}", title=f"{len(subdomains)} subdominio(s) unicos",
            note=preview, computers=subdomains,
        ))

    emit({"type": "external_start", "source": "Wayback Machine"})
    archived = search_wayback(domain)
    for url in archived:
        findings.append(Finding(
            category="wayback", dork_name="Wayback Machine (URL archivada)", query=domain,
            url=url, title=url,
            note="URL ya no enlazada pero archivada; revisar si sigue siendo accesible",
        ))
    for url, status, params in check_wayback_live(archived):
        findings.append(Finding(
            category="wayback", dork_name="Wayback: URL viva con parametro sensible", query=domain,
            url=url, title=f"HTTP {status}",
            note=f"Parametros sensibles en la query: {', '.join(params)}. Probar manualmente (no es una vulnerabilidad confirmada).",
        ))

    emit({"type": "external_start", "source": "Ficheros compartidos expuestos (Wayback + urlscan.io)"})
    for hit in find_exposed_files(domain):
        findings.append(Finding(
            category="leak", dork_name="Fichero compartido expuesto (historico + en vivo)", query=domain,
            url=hit["url"], title="Accesible ahora mismo",
            note="Encontrado en el archivo historico de la web (Wayback/urlscan.io) y "
                 "confirmado accesible hoy.",
        ))

    return findings


# patrones de hostnames/URLs que identifican a un proveedor cloud conocido.
# Se comprueban contra TODO lo que el escaneo ya ha recopilado (hostnames de
# Shodan/crt.sh/Certspotter, URLs de Wayback, rutas UNC de documentos,
# buckets de GrayHatWarfare...) - es analisis local, no hace peticiones
# nuevas a ningun sitio.
CLOUD_PATTERNS = {
    "AWS": re.compile(
        r"amazonaws\.com|\.s3[.-]|s3-website|cloudfront\.net|elasticbeanstalk\.com|"
        r"elb\.amazonaws|execute-api\.[a-z0-9-]+\.amazonaws",
        re.IGNORECASE,
    ),
    "Azure": re.compile(
        r"azure\.com|azurewebsites\.net|cloudapp\.azure\.com|blob\.core\.windows\.net|"
        r"azureedge\.net|azurefd\.net|database\.windows\.net|trafficmanager\.net",
        re.IGNORECASE,
    ),
    "Google Cloud": re.compile(
        r"googleusercontent\.com|appspot\.com|run\.app|storage\.googleapis\.com|"
        r"cloudfunctions\.net|\.gcp\.",
        re.IGNORECASE,
    ),
    "DigitalOcean": re.compile(r"digitaloceanspaces\.com|ondigitalocean\.app", re.IGNORECASE),
    "Cloudflare": re.compile(r"cloudflare\.com|cloudflare\.net|\.workers\.dev", re.IGNORECASE),
    "Heroku": re.compile(r"herokuapp\.com|herokudns\.com", re.IGNORECASE),
    "Akamai": re.compile(r"akamai(edge|hd|ized)?\.net", re.IGNORECASE),
    "Fastly": re.compile(r"fastly\.net|fastlylb\.net", re.IGNORECASE),
}


def detect_cloud_infrastructure(findings: list[Finding]) -> list[Finding]:
    """Agrupa por proveedor cloud (AWS/Azure/GCP/...) todos los hostnames y
    URLs que el escaneo ya ha recopilado de cualquier fuente (Shodan,
    crt.sh/Certspotter, Wayback, buckets, rutas en documentos...). No hace
    ninguna peticion nueva: es analisis local sobre datos ya obtenidos."""
    hits: dict[str, set[str]] = {}

    def check(text: str | None):
        if not text:
            return
        for provider, pattern in CLOUD_PATTERNS.items():
            if pattern.search(text):
                hits.setdefault(provider, set()).add(text)

    for f in findings:
        for host in f.computers:
            check(host)
        if f.url:
            host = urlparse(f.url).hostname
            check(host or f.url)

    cloud_findings = []
    for provider, matches in sorted(hits.items()):
        sample = sorted(matches)
        cloud_findings.append(Finding(
            category="cloud", dork_name=f"Infraestructura cloud: {provider}", query="",
            url="", title=f"{len(sample)} recurso(s) de {provider}",
            note=", ".join(sample[:40]) + (f" ... (+{len(sample) - 40} mas)" if len(sample) > 40 else ""),
            computers=sample,
        ))
    return cloud_findings


def detect_web_technologies(domain: str, on_event=None) -> list[Finding]:
    """Fingerprinting de tecnologias web sobre la pagina principal del
    dominio: identifica CMS/framework/servidor/librerias JS con su
    version. Un Finding por tecnologia detectada
    (categoria "tech"), independientemente de si tiene vulnerabilidades
    conocidas o no -> eso lo cruza despues detect_known_vulnerabilities,
    igual que ya hace con el software de los documentos."""
    emit = on_event or (lambda e: None)
    emit({"type": "fingerprint_start", "domain": domain})
    techs: dict[str, str] = {}
    for scheme in ("https", "http"):
        techs = fingerprint_url(f"{scheme}://{domain}")
        if techs:
            break
    for name, version in detect_cms(domain).items():
        if not any(k.lower() == name.lower() for k in techs):
            techs[name] = version
        elif version and not techs.get(name):
            techs[name] = version
    cms_result = run_cms_checks(domain, techs)
    for name, version in cms_result["techs"].items():
        if not any(k.lower() == name.lower() for k in techs):
            techs[name] = version
        elif version and not techs.get(name):
            techs[name] = version
    out = [
        Finding(category="tech", dork_name=f"Tecnologia detectada: {tech}",
                query="", url=f"https://{domain}", title=version)
        for tech, version in sorted(techs.items())
    ]
    for cms, path, desc, detail in cms_result["hits"]:
        out.append(Finding(
            category="sensitive", dork_name=f"{cms}: {path}", query=domain,
            url=f"https://{domain}{path}", title=desc, note=detail,
        ))
    return out


def _cve_finding(software: str, results: list[dict]) -> Finding:
    lines = []
    for r in results[:15]:
        score = f" ({r['score']})" if r.get("score") is not None else ""
        url_part = f" - {r['url']}" if r.get("url") else ""
        lines.append(f"[{r['source']}] {r['id']}{score}: {r['summary']}{url_part}")
    return Finding(
        category="vuln", dork_name=f"Vulnerabilidades conocidas: {software}", query="",
        url="", title=f"{len(results)} resultado(s)", note="\n".join(lines),
    )


def _eol_finding(product: str, version: str) -> Finding | None:
    eol_info = check_eol(product, version)
    if not eol_info or not eol_info["is_eol"]:
        return None
    return Finding(
        category="vuln", dork_name=f"Fin de soporte (EOL): {product}", query="",
        url=f"https://endoflife.date/{product.lower()}",
        title=f"EOL desde {eol_info['eol_date']}",
        note=f"version detectada={version} | ciclo={eol_info['cycle']} | "
             f"ultima version del ciclo={eol_info['latest'] or '-'} | "
             f"ya no recibe parches de seguridad del fabricante",
    )


def detect_known_vulnerabilities(findings: list[Finding], on_event=None) -> list[Finding]:
    """Para cada software/version distinto detectado en metadatos de
    documentos (p.ej. "Microsoft Word 2010", "Apache 2.2.3") y en el
    fingerprinting web (categoria "tech", p.ej. "WordPress 5.8"), busca
    CVEs/exploits conocidos en NVD + ExploitDB local + Sploitus. Opt-in
    (categoria "vuln") porque hace peticiones de red adicionales por cada
    software distinto encontrado."""
    emit = on_event or (lambda e: None)
    doc_software = sorted({f.software for f in findings if f.category == "document" and f.software})
    tech_software = sorted({
        f"{f.dork_name.replace('Tecnologia detectada: ', '')} {f.title}"
        for f in findings if f.category == "tech" and f.title
    })
    software_set = doc_software + tech_software

    vuln_findings = []
    for software in software_set:
        emit({"type": "vuln_lookup", "software": software})
        results = lookup_vulnerabilities(software)
        if results:
            vuln_findings.append(_cve_finding(software, results))

    # Fin de soporte (EOL): solo sobre tecnologias del fingerprinting web
    # (categoria "tech") — los productos de endoflife.date son software
    # de servidor/infraestructura, no aplicaciones de escritorio como las
    # detectadas en metadatos de documentos.
    for f in findings:
        if f.category != "tech" or not f.title:
            continue
        product = f.dork_name.replace("Tecnologia detectada: ", "")
        emit({"type": "vuln_lookup", "software": f"EOL: {product} {f.title}"})
        eol = _eol_finding(product, f.title)
        if eol:
            vuln_findings.append(eol)

    return vuln_findings


MAX_SERVICES_TO_LOOKUP = 10


def run_ports_checks(domain: str, on_event=None) -> list[Finding]:
    """Puertos TCP abiertos del objetivo (nmap, barrido completo -p- de los
    65535 + -sCV sobre los que salgan abiertos) y, para los servicios con
    producto+version identificados, CVEs/PoCs conocidos (NVD + ExploitDB +
    Sploitus) y fin de soporte (EOL). ACTIVO: envia trafico directo al
    objetivo. Corre por defecto (VALID_CATEGORIES); solo debe excluirse con
    --categories (CLI) o desmarcando el checkbox (web) si el dominio no
    esta autorizado para un escaneo activo."""
    emit = on_event or (lambda e: None)
    emit({"type": "external_start", "source": "Escaneo de puertos y servicios (nmap, ACTIVO)"})
    findings = []

    ip = resolve_ip(domain)
    if not ip:
        findings.append(Finding(
            category="ports", dork_name="Escaneo de puertos", query="", url=f"https://{domain}",
            title="No se pudo resolver el dominio", note="-",
        ))
        return findings

    try:
        services = scan_services(ip)
    except RuntimeError as exc:
        findings.append(Finding(
            category="ports", dork_name="Escaneo de puertos", query="", url=f"tcp://{ip}",
            title="No se pudo escanear", note=str(exc),
        ))
        return findings

    for svc in services:
        if svc["service"].startswith("http") and not svc["version"]:
            hdr = server_header_version(domain, svc["port"], https="https" in svc["service"] or svc["port"] in (443, 8443))
            if hdr:
                svc["product"], svc["version"] = hdr
                svc["extrainfo"] = (svc["extrainfo"] + " " if svc["extrainfo"] else "") + "(version desde cabecera Server)"

    if not services:
        findings.append(Finding(
            category="ports", dork_name="Puertos abiertos", query="", url=f"tcp://{ip}",
            title="Ninguno en los 65535 puertos TCP", note=f"IP escaneada: {ip}",
        ))
        return findings

    for s in services:
        version_txt = " ".join(x for x in (s["product"], s["version"]) if x) or "-"
        findings.append(Finding(
            category="ports", dork_name=f"Puerto {s['port']}/{s['protocol']} ({s['service'] or '?'})",
            query="", url=f"tcp://{ip}:{s['port']}", title=version_txt,
            note=s["extrainfo"] or f"IP: {ip}",
        ))

    identified = [s for s in services if s["product"] and s["version"]]
    for s in identified[:MAX_SERVICES_TO_LOOKUP]:
        software = f"{s['product']} {s['version']}"
        emit({"type": "vuln_lookup", "software": f"{software} (puerto {s['port']})"})
        results = lookup_vulnerabilities(software)
        if results:
            findings.append(_cve_finding(f"{software} (puerto {s['port']})", results))
        eol = _eol_finding(s["product"], s["version"])
        if eol:
            findings.append(eol)

    return findings


def run_dns_whois_checks(domain: str, on_event=None) -> list[Finding]:
    """Postura DNS y WHOIS del dominio: registros NS/MX/TXT/CAA,
    autenticacion de correo (SPF/DKIM/DMARC), DNSSEC, intento de
    transferencia de zona (AXFR) y datos de registro WHOIS. Categoria
    "dns", activa por defecto (gratis, rapido, sin api keys, no depende
    de los dorks/SearXNG). Si un NS permite AXFR se reporta como "leak"
    en vez de "dns": expone toda la zona de un tiron, es un hallazgo tan
    serio como cualquier otro leak y debe contar igual para
    --fail-on-leak."""
    emit = on_event or (lambda e: None)
    emit({"type": "dns_whois_start", "domain": domain})
    findings = []

    records = get_dns_records(domain)
    ns_list = ", ".join(records["NS"]) or "-"
    mx_list = ", ".join(records["MX"]) or "-"
    caa_list = ", ".join(records["CAA"]) or "-"
    txt_count = len(records["TXT"])
    findings.append(Finding(
        category="dns", dork_name="Registros DNS (NS/MX/TXT/CAA)", query="",
        url="", title=f"{len(records['NS'])} NS, {len(records['MX'])} MX, {txt_count} TXT",
        note=f"NS: {ns_list}\nMX: {mx_list}\nCAA: {caa_list}\nTXT: {txt_count} registro(s)",
        computers=list(records["NS"]),
    ))

    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    mail_issues = list(spf["issues"]) + list(dmarc["issues"])
    dkim_note = (f"Selectores DKIM detectados: {', '.join(dkim['selectors_found'])}"
                 if dkim["selectors_found"] else
                 "Sin selectores DKIM comunes detectados (no exhaustivo: solo "
                 "prueba los proveedores de correo mas habituales)")
    findings.append(Finding(
        category="dns", dork_name="Autenticacion de correo (SPF/DKIM/DMARC)", query="",
        url="", title=f"{len(mail_issues)} problema(s) detectado(s)" if mail_issues else "Sin problemas detectados",
        note="\n".join([
            f"SPF: {'presente' if spf['present'] else 'AUSENTE'}" + (f" — {spf['record']}" if spf['record'] else ""),
            f"DMARC: {'presente' if dmarc['present'] else 'AUSENTE'}" + (f" — {dmarc['record']}" if dmarc['record'] else ""),
            dkim_note,
            *mail_issues,
        ]),
    ))

    dnssec = check_dnssec(domain)
    findings.append(Finding(
        category="dns", dork_name="DNSSEC", query="",
        url="", title="Habilitado" if dnssec["enabled"] else "No habilitado",
        note=dnssec["details"] or "-",
    ))

    axfr = check_zone_transfer(domain, records["NS"])
    if axfr["vulnerable_ns"]:
        findings.append(Finding(
            category="leak", dork_name="Transferencia de zona DNS (AXFR) permitida", query="",
            url="", title=f"{len(axfr['vulnerable_ns'])} servidor(es) vulnerable(s)",
            note=(f"Nameservers que permiten AXFR (exponen TODA la zona DNS de un "
                  f"tiron): {', '.join(axfr['vulnerable_ns'])}. "
                  f"Testeados: {', '.join(axfr['tested_ns']) or '-'}"),
            computers=list(axfr["vulnerable_ns"]),
        ))
    else:
        findings.append(Finding(
            category="dns", dork_name="Transferencia de zona (AXFR)", query="",
            url="", title="Correctamente denegada en todos los NS testeados",
            note=f"Nameservers testeados: {', '.join(axfr['tested_ns']) or '-'}",
        ))

    w = whois_lookup(domain)
    if any(w.values()):
        findings.append(Finding(
            category="dns", dork_name="WHOIS", query="",
            url="", title=w["registrar"] or "-",
            note="\n".join([
                f"Registrador: {w['registrar'] or '-'}",
                f"Creado: {w['creation_date'] or '-'}",
                f"Expira: {w['expiry_date'] or '-'}",
                f"Ultima actualizacion: {w['updated_date'] or '-'}",
                f"Organizacion registrante: {w['registrant_org'] or '- (probablemente redactado por GDPR/privacidad)'}",
                f"Pais registrante: {w['registrant_country'] or '-'}",
                f"Nameservers (WHOIS): {', '.join(w['nameservers']) or '-'}",
            ]),
        ))

    return findings


def run_tls_headers_checks(domain: str, on_event=None) -> list[Finding]:
    """Postura TLS/HTTPS (certificado, protocolos obsoletos) y cabeceras
    de seguridad HTTP (HSTS/CSP/X-Frame-Options/...) de la pagina
    principal del dominio. Categoria "tls", activa por defecto (gratis,
    rapido, sin api keys: una conexion TLS y un GET normal)."""
    emit = on_event or (lambda e: None)
    emit({"type": "tls_start", "domain": domain})
    findings = []

    tls = check_tls(domain)
    if tls["reachable"]:
        cert = tls["certificate"]
        san_preview = ", ".join(cert["san"][:10]) + (f" (+{len(cert['san']) - 10} mas)" if len(cert["san"]) > 10 else "")
        findings.append(Finding(
            category="tls", dork_name="Certificado TLS", query="",
            url=f"https://{domain}",
            title=f"Expira en {cert['days_left']} dias" if cert["days_left"] is not None else "-",
            note="\n".join([
                f"Emisor: {cert['issuer'] or '-'}",
                f"CN: {cert['subject_cn'] or '-'}",
                f"Caducidad: {cert['not_after'] or '-'}",
                f"Cifrado: {cert['cipher_suite'] or '-'} ({cert['tls_version_negotiated'] or '-'})",
                f"SAN: {san_preview or '-'}",
                *tls["issues"],
            ]),
        ))
    else:
        findings.append(Finding(
            category="tls", dork_name="Certificado TLS", query="",
            url=f"https://{domain}", title="No se pudo conectar por HTTPS",
            note="\n".join(tls["issues"]) or "-",
        ))

    headers = check_web_headers(domain)
    if headers["reachable"]:
        missing = ", ".join(f"{m['header']} ({m['criticidad']})" for m in headers["missing"])
        note_lines = [
            f"Presentes: {', '.join(headers['headers_present']) or '-'}",
            f"Ausentes: {missing or '-'}",
        ]
        if headers["server_banner"]:
            note_lines.append(f"Server: {headers['server_banner']}")
        if headers["cookies_issues"]:
            note_lines.append(f"Cookies sin flags de seguridad: {'; '.join(headers['cookies_issues'])}")
        findings.append(Finding(
            category="tls", dork_name="Cabeceras de seguridad HTTP", query="",
            url=headers["final_url"] or f"https://{domain}",
            title=f"{len(headers['missing'])} cabecera(s) ausente(s)" if headers["missing"] else "Todas presentes",
            note="\n".join(note_lines),
        ))

    emit({"type": "external_start", "source": "Deteccion de WAF / CDN (2 peticiones)"})
    waf = detect_waf(domain)
    if waf is not None:
        findings.append(Finding(
            category="tls", dork_name="WAF / CDN de proteccion", query="", url=f"https://{domain}",
            title=", ".join(waf["proveedores"]) or ("WAF no identificado" if waf["bloqueo_probado"] else "Ninguno detectado"),
            note=f"Respuesta normal: HTTP {waf['status_normal']} | "
                 f"respuesta a patron de prueba: HTTP {waf['status_prueba']} | "
                 f"bloqueo ante patron de prueba: {'si' if waf['bloqueo_probado'] else 'no'}",
        ))

    return findings


def run_typosquat_checks(domain: str, on_event=None) -> list[Finding]:
    """Typosquatting (variantes tipograficas estilo dnstwist: omision,
    repeticion, transposicion, teclas adyacentes, homoglifos...) y domain
    squatting clasico (mismo nombre en otros TLDs + combosquatting con
    palabras de phishing como "login"/"secure"/"verify"). Resuelve
    cientos de variantes por DNS en paralelo para ver cuales estan
    registradas de verdad. A diferencia de "dns"/"tls" esto hace 1000+
    resoluciones DNS y puede tardar varios minutos; sigue en
    VALID_CATEGORIES (corre por defecto) pero es la categoria mas lenta,
    por si se necesita excluirla con --categories para un escaneo rapido."""
    emit = on_event or (lambda e: None)
    findings = []

    emit({"type": "external_start", "source": "Domain squatting (generando y resolviendo variantes)"})
    squat_candidates = generate_domain_squatting_candidates(domain)
    squat_alive = resolve_candidates(squat_candidates)
    findings.append(Finding(
        category="typosquat", dork_name="Domain squatting (otros TLDs / combosquatting)",
        query="", url=f"https://{domain}",
        title=f"{len(squat_alive)} de {len(squat_candidates)} variantes registradas",
        note="\n".join(f"{a['domain']} -> {a['ip']}" for a in squat_alive) or "Ninguna variante registrada.",
    ))

    emit({"type": "external_start", "source": "Typosquatting (generando y resolviendo variantes)"})
    typo_candidates = generate_typosquat_candidates(domain)
    extra_variants = fetch_extra_variants(domain)
    combined_typo = list(dict.fromkeys(
        typo_candidates + [v for v in extra_variants if v not in squat_candidates]
    ))
    typo_alive = resolve_candidates(combined_typo)
    findings.append(Finding(
        category="typosquat", dork_name="Typosquatting (variantes tipograficas)",
        query="", url=f"https://{domain}",
        title=f"{len(typo_alive)} de {len(combined_typo)} variantes registradas",
        note="\n".join(f"{a['domain']} -> {a['ip']}" for a in typo_alive) or "Ninguna variante registrada.",
    ))

    return findings


DEFAULT_CATEGORIES = {"document", "sensitive", "platform", "leak", "email", "dns", "tls"}
ALL_CATEGORIES = DEFAULT_CATEGORIES | {"people", "external", "vuln", "typosquat"}
# "ports" (nmap) envia trafico activo directo al objetivo. Sigue siendo su
# propia categoria (para poder excluirla explicitamente con --categories si
# un dominio no esta autorizado para escaneo activo), pero ya forma parte de
# VALID_CATEGORIES == el default real: tanto CLI como web la corren salvo
# que se pida lo contrario con --categories/categorias restringidas.
ACTIVE_CATEGORIES = {"ports"}
VALID_CATEGORIES = ALL_CATEGORIES | ACTIVE_CATEGORIES


def run_keyed_checks(domain: str, findings: list[Finding], api_keys: dict, emit) -> list[Finding]:
    """HIBP (brechas de cada correo encontrado) y DomScan (selectores DKIM).
    Solo corren si hay clave; sin clave no hacen ninguna peticion."""
    out = []
    api_keys = api_keys or {}
    hibp_key = api_keys.get("hibp")
    if hibp_key:
        emails = sorted({e for f in findings for e in f.emails})[:50]
        if emails:
            emit({"type": "external_start", "source": f"HIBP ({len(emails)} correo(s))"})
        for email in emails:
            names = hibp_breaches(email, hibp_key)
            if names is None:
                emit({"type": "warning", "message": "HIBP: clave no valida o limite alcanzado, se omite"})
                break
            if names:
                out.append(Finding(
                    category="leak", dork_name="HIBP (cuenta en brechas)", query=email,
                    url="https://haveibeenpwned.com", title=f"{len(names)} brecha(s)",
                    note=f"correo: {email}", secrets=[f"brecha: {n}" for n in names[:10]],
                ))
    domscan_key = api_keys.get("domscan")
    if domscan_key:
        emit({"type": "external_start", "source": "DomScan (DKIM)"})
        selectors = domscan_dkim(domain, domscan_key)
        if selectors is not None:
            out.append(Finding(
                category="dns", dork_name="DKIM (DomScan)", query=domain,
                url=f"https://{domain}", title=f"{len(selectors)} selector(es)",
                note=", ".join(selectors) or "Ninguno encontrado",
            ))
    return out


def run_scan(
    domain: str,
    out_dir: Path,
    *,
    searxng_endpoints=None,
    proxies=None,
    min_delay: float = 2.5,
    max_delay: float = 6.0,
    save_docs: bool = True,
    no_download: bool = False,
    categories: set[str] | None = None,
    external_keys: dict | None = None,
    on_event=None,
) -> list[Finding]:
    """Ejecuta todos los dorks para `domain` y devuelve la lista de Findings.

    categories: si se da, restringe la corrida a solo esas categorias
    (subconjunto de VALID_CATEGORIES) — util para un escaneo rapido/
    acotado. None/vacio = VALID_CATEGORIES, es decir TODO, incluyendo
    "ports" (nmap activo contra el objetivo): se prioriza informacion
    completa por defecto; usar categories explicito cuando se quiera
    menos.

    external_keys: dict opcional con api keys para fuentes externas, ej.
    {"shodan": "...", "grayhatwarfare": "...", "intelx": "..."}. Solo se
    usan si la categoria "external" esta activa. Shodan funciona igual sin
    key (usa InternetDB, que es gratis); las otras dos se omiten sin key.

    on_event(evt: dict) se llama con, entre otros:
      {"type": "dork_start", "name", "query", "index", "total"}
      {"type": "dork_results", "count"}
      {"type": "processing", "url"}          -> justo antes de descargar/analizar un fichero
      {"type": "finding", "finding": Finding} -> cada vez que se cierra un resultado
      {"type": "discarded", "category", "url", "reason"} -> candidato a leak/email descartado tras verificar en local
      {"type": "aborted", "reason"}
      {"type": "warning", "message"}
      {"type": "done"}
    """
    def emit(evt):
        if on_event:
            on_event(evt)

    # Suelo de seguridad: por debajo de esto, motores como Brave/DuckDuckGo
    # empiezan a devolver "too many requests" / "access denied" y SearXNG
    # los suspende (a veces durante horas), justo el problema que esta
    # herramienta intenta evitar. Nunca se salta este minimo, ni siquiera
    # si lo piden la CLI o la web con un valor mas bajo.
    MIN_SAFE_DELAY = 1.5
    if min_delay < MIN_SAFE_DELAY:
        emit({"type": "warning",
              "message": f"min_delay={min_delay}s es demasiado agresivo, "
                          f"se sube a {MIN_SAFE_DELAY}s para no saturar los motores"})
        min_delay = MIN_SAFE_DELAY
    if max_delay < min_delay + 0.5:
        max_delay = min_delay + 0.5

    docs_dir = out_dir / "documentos"
    work_dir = docs_dir if save_docs else Path(tempfile.mkdtemp(prefix="frib1trecon_"))

    client = SearxngClient(
        endpoints=searxng_endpoints or ["http://127.0.0.1:8080"],
        proxies=proxies, min_delay=min_delay, max_delay=max_delay,
    )

    active_categories = categories if categories else VALID_CATEGORIES
    dork_list = dorks_mod.build_dorks(domain)
    dork_list = [d for d in dork_list if d["category"] in active_categories]
    findings: list[Finding] = []

    # no depende de SearXNG/dorks, se ejecuta aparte y primero: es rapido
    # (un puñado de consultas DNS + whois) y gratis (sin api keys)
    if "dns" in active_categories:
        for finding in run_dns_whois_checks(domain, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    # tampoco depende de SearXNG: una conexion TLS + un GET normal
    if "tls" in active_categories:
        for finding in run_tls_headers_checks(domain, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    if "sensitive" in active_categories:
        emit({"type": "external_start", "source": "Rutas sensibles habituales (HTTP GET)"})
        for hit in check_sensitive_paths(domain):
            finding = Finding(
                category="sensitive", dork_name=f"Ruta sensible: {hit['path']}", query=domain,
                url=hit["url"], title=hit["label"],
                note=f"Extracto: {hit['snippet']}", secrets=hit["secrets"],
            )
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    # tampoco depende de SearXNG, pero es mucho mas lento (1000+
    # resoluciones DNS)
    if "typosquat" in active_categories:
        for finding in run_typosquat_checks(domain, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    if "ports" in active_categories:
        for finding in run_ports_checks(domain, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    try:
        for i, dork in enumerate(dork_list, start=1):
            emit({"type": "dork_start", "name": dork["name"], "query": dork["query"],
                  "index": i, "total": len(dork_list)})
            try:
                results = client.search(dork["query"])
            except TooManyFailures as exc:
                emit({"type": "aborted", "reason": str(exc)})
                break

            emit({"type": "dork_results", "count": len(results)})

            for r in results:
                if dork["category"] in ("document", "sensitive"):
                    if dork["ext"] and not matches_ext(r.url, dork["ext"]):
                        continue
                    if no_download:
                        finding = Finding(
                            category=dork["category"], dork_name=dork["name"],
                            query=dork["query"], url=r.url, engine=r.engine,
                            filetype=dork["ext"], title=r.title, note="no descargado (--no-download)",
                        )
                    else:
                        emit({"type": "processing", "url": r.url})
                        finding = process_result(r, dork, domain, work_dir, save_docs)
                    findings.append(finding)
                    emit({"type": "finding", "finding": finding})
                elif dork["category"] == "email":
                    if not no_download:
                        emit({"type": "processing", "url": r.url})
                    finding = process_email_result(r, dork, domain, work_dir, save_docs, no_download)
                    if finding:
                        findings.append(finding)
                        emit({"type": "finding", "finding": finding})
                    else:
                        emit({"type": "discarded", "category": "email", "url": r.url,
                              "reason": "no se encontro ningun email en el fragmento/pagina"})
                elif dork["category"] == "leak":
                    if not no_download and dork.get("leak_filter", "secret_pattern") == "secret_pattern":
                        emit({"type": "processing", "url": r.url})
                    finding = process_leak_result(r, dork, domain, work_dir, save_docs, no_download)
                    if finding:
                        findings.append(finding)
                        emit({"type": "finding", "finding": finding})
                    else:
                        emit({"type": "discarded", "category": "leak", "url": r.url,
                              "reason": "no se confirmo el patron esperado (leak_filter="
                                        f"{dork.get('leak_filter', 'secret_pattern')})"})
                elif dork["category"] == "people":
                    finding = process_people_result(r, dork, domain)
                    if finding:
                        findings.append(finding)
                        emit({"type": "finding", "finding": finding})
                    else:
                        emit({"type": "discarded", "category": "people", "url": r.url,
                              "reason": "no se pudo extraer nombre/puesto del fragmento"})
                else:  # platform
                    expected_host = dork.get("platform_host")
                    actual_host = (urlparse(r.url).hostname or "").lower()
                    dork_name = dork["name"]
                    if expected_host and not (
                        actual_host == expected_host or actual_host.endswith(f".{expected_host}")
                    ):
                        # el buscador no respeto el site: pedido. En vez de
                        # tirar el resultado (puede ser valioso, p.ej. una
                        # app en Play Store encontrada via el dork de Google
                        # Drive), si la URL real pertenece a OTRA plataforma
                        # conocida se reetiqueta correctamente; solo se
                        # descarta si no coincide con ninguna plataforma
                        # reconocida (ahi si es ruido irrelevante).
                        reclassified = None
                        for known_host, label in dorks_mod.PLATFORM_HOST_LABELS.items():
                            if actual_host == known_host or actual_host.endswith(f".{known_host}"):
                                reclassified = label
                                break
                        if not reclassified:
                            emit({"type": "discarded", "category": "platform", "url": r.url,
                                  "reason": f"el buscador ignoro site:{expected_host}, "
                                            f"la URL real es de '{actual_host}' (plataforma no reconocida)"})
                            continue
                        dork_name = f"Mencion en {reclassified}"
                    finding = Finding(
                        category=dork["category"], dork_name=dork_name,
                        query=dork["query"], url=r.url, engine=r.engine, title=r.title,
                    )
                    findings.append(finding)
                    emit({"type": "finding", "finding": finding})
    finally:
        if not save_docs and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

    if "external" in active_categories:
        for finding in run_external_osint(domain, external_keys, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    # analisis local (sin peticiones nuevas) de todo lo recopilado en busca
    # de infraestructura cloud conocida (AWS/Azure/GCP/...)
    for finding in detect_cloud_infrastructure(findings):
        findings.append(finding)
        emit({"type": "finding", "finding": finding})

    if "vuln" in active_categories:
        for finding in detect_web_technologies(domain, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})
        for finding in detect_known_vulnerabilities(findings, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    if "external" in active_categories:
        for finding in run_keyed_checks(domain, findings, external_keys, emit):
            findings.append(finding)
            emit({"type": "finding", "finding": finding})

    emit({"type": "done"})
    return findings


def extract_subdomains(findings: list[Finding], domain: str) -> list[str]:
    """Subdominios descubiertos via crt.sh y los hostnames de Shodan,
    excluyendo el propio dominio y su www. (serian redundantes con el
    escaneo principal). Base de la recursividad: --recursive."""
    subs = set()
    for f in findings:
        if f.category in ("subdomains", "shodan"):
            subs.update(f.computers)
    domain_lower = domain.lower()
    subs = {s.lower() for s in subs if s}
    subs.discard(domain_lower)
    subs.discard(f"www.{domain_lower}")
    # solo subdominios de verdad del dominio objetivo (Shodan a veces
    # devuelve hostnames de otros clientes del mismo servidor compartido)
    subs = {s for s in subs if s.endswith(f".{domain_lower}")}
    return sorted(subs)


def run_scan_recursive(
    domain: str,
    out_dir: Path,
    *,
    searxng_endpoints=None,
    proxies=None,
    min_delay: float = 2.5,
    max_delay: float = 6.0,
    save_docs: bool = True,
    no_download: bool = False,
    categories: set[str] | None = None,
    external_keys: dict | None = None,
    recursive: bool = False,
    recursive_categories: set[str] | None = None,
    max_subdomains: int = 10,
    on_event=None,
) -> dict[str, list[Finding]]:
    """Escanea `domain` y, si recursive=True y se descubren subdominios
    (necesita la categoria "external" activa, via --all o --categories
    external), relanza un escaneo mas ligero contra cada uno (hasta
    max_subdomains). Un solo nivel de profundidad: los subdominios de los
    subdominios no se vuelven a seguir, para no disparar el tiempo total.

    Devuelve {host: [Finding, ...]}, con `domain` siempre como primera
    clave.
    """
    def emit(evt):
        if on_event:
            on_event(evt)

    results: dict[str, list[Finding]] = {}

    main_findings = run_scan(
        domain, out_dir,
        searxng_endpoints=searxng_endpoints, proxies=proxies,
        min_delay=min_delay, max_delay=max_delay,
        save_docs=save_docs, no_download=no_download,
        categories=categories, external_keys=external_keys,
        on_event=on_event,
    )
    results[domain] = main_findings

    if not recursive:
        return results

    visited = {domain.lower(), f"www.{domain}".lower()}
    subs = [s for s in extract_subdomains(main_findings, domain) if s not in visited]
    subs = subs[:max_subdomains]

    if not subs:
        emit({"type": "recursive_none"})
        return results

    sub_categories = recursive_categories or {"document", "sensitive", "leak"}
    emit({"type": "recursive_plan", "count": len(subs), "subdomains": subs})

    for sub in subs:
        if sub in visited:
            continue
        visited.add(sub)
        emit({"type": "recursive_start", "domain": sub})
        sub_out = out_dir / "subdominios" / sub
        try:
            sub_findings = run_scan(
                sub, sub_out,
                searxng_endpoints=searxng_endpoints, proxies=proxies,
                min_delay=min_delay, max_delay=max_delay,
                save_docs=save_docs, no_download=no_download,
                categories=sub_categories, external_keys=None,
                on_event=on_event,
            )
        except Exception as exc:  # noqa: BLE001 - un subdominio roto no debe tirar todo el escaneo
            emit({"type": "recursive_error", "domain": sub, "reason": str(exc)})
            continue
        results[sub] = sub_findings

    return results
