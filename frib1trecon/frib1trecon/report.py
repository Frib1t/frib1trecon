"""Modelo de resultados + tablas rich + exportacion TXT/CSV/JSON/Excel."""
import csv
import json
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
DOT_BIN = shutil.which("dot")
FDP_BIN = shutil.which("fdp")


def _graphviz_engine(node_count: int) -> str | None:
    """Elige el motor de layout de Graphviz segun el tamano del grafo.
    `dot` (jerarquico, rankdir=LR) da el flujo claro dominio->subdominio->
    ... que queremos para grafos pequenos, pero con muchos nodos colgando
    del mismo padre (p.ej. 50 personas de LinkedIn) los apila en una sola
    columna muy alta y estrecha: ilegible y no cabe en una pagina aunque
    se reescale. `fdp` (basado en fuerzas) reparte los nodos en 2D, dando
    una imagen mucho mas compacta y cuadrada para esos casos."""
    name = "dot" if node_count <= 25 else "fdp"
    picked = shutil.which(name)
    return picked or DOT_BIN or FDP_BIN


@dataclass
class Finding:
    category: str            # document | sensitive | platform | leak
    dork_name: str
    query: str
    url: str
    engine: str = ""
    filetype: str | None = None
    author: str | None = None
    last_modified_by: str | None = None
    software: str | None = None
    created: str | None = None
    modified: str | None = None
    title: str | None = None
    manager: str | None = None
    company: str | None = None
    secrets: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    internal_paths: list[str] = field(default_factory=list)
    computers: list[str] = field(default_factory=list)
    local_path: str | None = None
    note: str = ""
    # coordenadas GPS embebidas en una imagen ("lat,lon"), si las tenia
    gps: str | None = None
    # categoria "people" (LinkedIn): datos de la persona encontrada
    person_name: str | None = None
    role: str | None = None
    seniority: str | None = None
    # host real que produjo este hallazgo (dominio o subdominio con --recursive);
    # vacio en un escaneo normal de un solo host, relleno por cli.py cuando
    # hay varios hosts para poder construir el informe maestro consolidado
    host: str = ""


def print_documents_table(findings: list[Finding]):
    docs = [f for f in findings if f.category == "document"]
    if not docs:
        return
    table = Table(title="Documentos con metadatos", show_lines=False)
    for col in ["Tipo", "Autor", "Ult. modif. por", "Software", "Creado", "Modificado", "GPS", "URL"]:
        table.add_column(col, overflow="fold")
    for f in docs:
        table.add_row(
            f.filetype or "-", f.author or "-", f.last_modified_by or "-",
            f.software or "-", f.created or "-", f.modified or "-", f.gps or "-", f.url,
            style="bold yellow" if f.gps else None,
        )
    console.print(table)


def print_sensitive_table(findings: list[Finding]):
    sens = [f for f in findings if f.category == "sensitive"]
    if not sens:
        return
    table = Table(title="Ficheros sensibles (sql/log/env/bak)", show_lines=False)
    for col in ["Tipo", "Patrones detectados", "URL"]:
        table.add_column(col, overflow="fold")
    for f in sens:
        style = "bold red" if f.secrets else None
        table.add_row(f.filetype or "-", ", ".join(f.secrets) or "-", f.url, style=style)
    console.print(table)


def print_platform_table(findings: list[Finding]):
    plat = [f for f in findings if f.category in ("platform", "leak")]
    if not plat:
        return
    table = Table(title="Menciones en plataformas externas / posibles leaks (OSINT)", show_lines=False)
    for col in ["Categoria", "Dork", "Detalle", "URL"]:
        table.add_column(col, overflow="fold")
    for f in plat:
        style = "bold red" if f.category == "leak" else None
        detalle = leak_detail(f)
        table.add_row(f.category, f.dork_name, detalle, f.url, style=style)
    console.print(table)


def print_emails_paths_table(findings: list[Finding]):
    """Emails/rutas/equipos encontrados DENTRO de documentos (metadatos + texto)."""
    rows = [f for f in findings if f.category != "email" and (f.emails or f.internal_paths or f.computers)]
    if not rows:
        return
    table = Table(title="Emails, rutas internas y equipos detectados en documentos", show_lines=False)
    for col in ["URL", "Emails", "Rutas internas", "Equipos/Servidores"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.url, ", ".join(f.emails) or "-", ", ".join(f.internal_paths) or "-",
                       ", ".join(f.computers) or "-")
    console.print(table)


def print_email_osint_table(findings: list[Finding]):
    """Emails recopilados de fuentes publicas en la web abierta (no solo
    documentos): pagina donde aparecio + email(s) encontrados."""
    rows = [f for f in findings if f.category == "email"]
    if not rows:
        return
    table = Table(title="Emails recopilados de fuentes publicas (OSINT)", show_lines=False)
    for col in ["Emails", "Encontrado en", "URL"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(", ".join(f.emails) or "-", f.dork_name, f.url)
    console.print(table)


SENIORITY_LABELS = {
    "1-direccion": "Direccion",
    "2-mandos": "Mandos intermedios",
    "3-resto": "Resto de empleados",
}


def org_chart_rows(findings: list[Finding]) -> list[Finding]:
    """Personas encontradas en LinkedIn, ordenadas por nivel de seniority
    (aproximado por palabras clave del puesto) y luego por nombre. Esto es
    la base tanto de la tabla en pantalla como de la hoja de Excel."""
    people = [f for f in findings if f.category == "people" and f.person_name]
    return sorted(people, key=lambda f: (f.seniority or "3-resto", f.person_name or ""))


def confianza_empresa(f: Finding) -> str:
    """'Confirmada' si se pudo leer el nombre de la empresa en el perfil y
    coincidia con el dominio objetivo; 'Sin confirmar' si no se pudo leer
    la empresa en el fragmento (no implica que sea falso, solo que no se
    pudo verificar). Los que claramente eran de otra empresa ya se
    descartan antes de llegar aqui, en engine.process_people_result."""
    return "Sin confirmar" if f.note else "Confirmada"


def leak_detail(f: Finding) -> str:
    """Texto de la columna 'Detalle' para hallazgos leak/platform: muestra
    los secretos encontrados y, si ademas hay una nota (p.ej. el aviso de
    que la mencion del dominio en la pagina puede ser incidental), la
    concatena en vez de ocultarla detras de los secretos."""
    if f.secrets and f.note:
        return f"{', '.join(f.secrets)} | {f.note}"
    if f.secrets:
        return ", ".join(f.secrets)
    return f.note or "-"


_TLS_CERT_ISSUE_MARKERS = (
    "EXPIRADO", "expira en", "Cifrado debil", "todavia acepta",
    "invalido/no confiable", "No se pudo establecer conexion TLS",
)


def _risk_flag_leaks(findings: list[Finding]) -> bool:
    return any(f.secrets or f.category in ("leak", "bucket") for f in findings)


def _risk_flag_dns_email(findings: list[Finding]) -> bool:
    for f in findings:
        if f.category == "leak" and "AXFR" in f.dork_name:
            return True
        if f.category != "dns":
            continue
        if f.dork_name.startswith("Autenticacion de correo") and f.title != "Sin problemas detectados":
            return True
        if f.dork_name == "DNSSEC" and f.title == "No habilitado":
            return True
    return False


def _risk_flag_tls_web(findings: list[Finding]) -> bool:
    for f in findings:
        if f.category != "tls":
            continue
        if f.dork_name == "Cabeceras de seguridad HTTP" and f.title != "Todas presentes":
            return True
        if f.dork_name == "Certificado TLS":
            if f.title == "No se pudo conectar por HTTPS":
                return True
            if any(marker in (f.note or "") for marker in _TLS_CERT_ISSUE_MARKERS):
                return True
    return False


def _risk_flag_vuln(findings: list[Finding]) -> bool:
    return any(f.category == "vuln" for f in findings)


def _risk_flag_reputation(findings: list[Finding]) -> bool:
    for f in findings:
        if f.category != "reputation":
            continue
        m = re.search(r"malicioso=(\d+)", f.note or "")
        if m and int(m.group(1)) > 0:
            return True
        m2 = re.search(r"confianza de abuso=(\d+)%", f.note or "")
        if m2 and int(m2.group(1)) >= 50:
            return True
    return False


def _risk_flag_squatting(findings: list[Finding]) -> bool:
    return any(
        f.category == "typosquat" and f.note and f.note != "Ninguna variante registrada."
        for f in findings
    )


def _risk_flag_identity(findings: list[Finding]) -> bool:
    return any(f.category in ("email", "people") for f in findings)


# (clave, etiqueta, peso, funcion de deteccion). Pesos adaptados del modelo
# de 6 categorias del toolkit de referencia (Compromised Systems/Security
# Controls/Exposure Management/Technology & Vuln/Identity/Brand Reputation)
# a las categorias reales que frib1trecon puede detectar. Cada categoria es
# binaria: si CUALQUIER hallazgo la marca como "a revisar", se suma el peso
# COMPLETO al riesgo total (no es proporcional a cuantos hallazgos haya,
# es presencia/ausencia), igual que el modelo original.
RISK_STRUCTURE = [
    ("leaks", "Leaks y credenciales expuestas (ficheros/buckets/secretos)", 25.0, _risk_flag_leaks),
    ("dns_email", "Seguridad DNS y email (SPF/DKIM/DMARC/DNSSEC/AXFR)", 15.0, _risk_flag_dns_email),
    ("tls_web", "Seguridad TLS y cabeceras web", 15.0, _risk_flag_tls_web),
    ("vuln", "CVEs conocidos y software sin soporte (EOL)", 15.0, _risk_flag_vuln),
    ("reputation", "Reputacion maliciosa (VirusTotal/AbuseIPDB)", 15.0, _risk_flag_reputation),
    ("squatting", "Typosquatting / domain squatting registrado", 10.0, _risk_flag_squatting),
    ("identity", "Exposicion de identidad (emails/personas publicas)", 5.0, _risk_flag_identity),
]


def risk_level_for(score: float) -> tuple[str, str]:
    """Umbrales sobre el riesgo (numero alto = peor): 0-20 bajo, 20-40
    medio, 40-65 alto, 65+ critico. Mismos umbrales que el toolkit de
    referencia."""
    if score < 20:
        return "low", "Riesgo bajo"
    if score < 40:
        return "medium", "Riesgo medio"
    if score < 65:
        return "high", "Riesgo alto"
    return "critical", "Riesgo critico"


def compute_risk_score(findings: list[Finding]) -> dict:
    """Nivel de riesgo general (0-100) calculado sobre los hallazgos de
    un escaneo: suma los pesos de cada categoria de riesgo que tenga
    algun hallazgo que la dispare. No pretende ser un CVSS exacto, es una
    señal rapida de "por donde mirar primero" — el detalle real esta en
    las tablas/secciones especificas de cada categoria."""
    breakdown = []
    total = 0.0
    for key, label, weight, flag_fn in RISK_STRUCTURE:
        triggered = flag_fn(findings)
        if triggered:
            total += weight
        breakdown.append({"key": key, "label": label, "weight": weight, "triggered": triggered})
    level, level_label = risk_level_for(total)
    return {"score": total, "level": level, "level_label": level_label, "breakdown": breakdown}


def print_risk_score(findings: list[Finding]):
    risk = compute_risk_score(findings)
    score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")
    color = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}[risk["level"]]
    console.print(f"\n[{color}]NIVEL DE RIESGO: {risk['level_label'].upper()} ({score_txt}%)[/{color}]")
    table = Table(title="Desglose del nivel de riesgo", show_lines=False)
    for col in ["Categoria de riesgo", "Peso", "Estado"]:
        table.add_column(col)
    for item in risk["breakdown"]:
        estado = "[bold red]A REVISAR[/bold red]" if item["triggered"] else "[green]OK[/green]"
        table.add_row(item["label"], f"{item['weight']:.2f}".rstrip("0").rstrip("."), estado)
    console.print(table)


def print_org_chart_table(findings: list[Finding]):
    """Organigrama aproximado: NO son relaciones de jefatura reales (LinkedIn
    no las expone en busqueda publica), es un agrupamiento por nivel de
    seniority detectado en el titulo del puesto."""
    people = org_chart_rows(findings)
    if not people:
        return
    table = Table(title="Organigrama aproximado (LinkedIn, por nivel de seniority)", show_lines=False)
    for col in ["Nivel", "Nombre", "Puesto", "Empresa", "LinkedIn"]:
        table.add_column(col, overflow="fold")
    for f in people:
        style = "dim" if f.note else None
        table.add_row(SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name, f.role,
                       confianza_empresa(f), f.url, style=style)
    console.print(table)


def print_external_osint_table(findings: list[Finding]):
    """Hallazgos de fuentes externas: Shodan (hosts/puertos expuestos),
    GrayHatWarfare (ficheros en buckets S3/Azure/GCP), IntelX (leaks/
    pastes/darkweb/phonebook), crt.sh (subdominios por certificados SSL) y
    Wayback Machine (URLs archivadas con pinta de haber sido sensibles).
    Categoria opt-in (--categories external o --all)."""
    rows = [f for f in findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    if not rows:
        return
    table = Table(title="Fuentes externas y Cloud (Shodan / VirusTotal / AbuseIPDB / GrayHatWarfare / IntelX / crt.sh / Wayback / AWS-Azure-GCP...)", show_lines=False)
    for col in ["Fuente", "Detalle", "Info", "URL"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        style = "bold red" if f.category == "bucket" else None
        table.add_row(f.dork_name, f.title or "-", f.note or "-", f.url or "-", style=style)
    console.print(table)


def print_tech_table(findings: list[Finding]):
    """Tecnologias web detectadas en la pagina principal del objetivo: CMS,
    framework, servidor, librerias JS... Categoria opt-in (--categories
    vuln o --all, se fingerprint ademas de buscar vulnerabilidades para
    esas mismas tecnologias)."""
    rows = [f for f in findings if f.category == "tech"]
    if not rows:
        return
    table = Table(title="Tecnologias detectadas", show_lines=False)
    for col in ["Tecnologia", "Version", "URL"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-")
    console.print(table)


def print_dns_table(findings: list[Finding]):
    """Postura DNS y WHOIS: registros NS/MX/TXT/CAA, autenticacion de
    correo (SPF/DKIM/DMARC), DNSSEC, transferencia de zona y datos de
    registro. Categoria activa por defecto."""
    rows = [f for f in findings if f.category == "dns"]
    if not rows:
        return
    table = Table(title="DNS y WHOIS", show_lines=True)
    for col in ["Comprobacion", "Resultado", "Detalle"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name, f.title or "-", f.note or "-")
    console.print(table)


def print_tls_table(findings: list[Finding]):
    """Postura TLS/HTTPS (certificado, protocolos obsoletos) y cabeceras
    de seguridad HTTP. Categoria activa por defecto."""
    rows = [f for f in findings if f.category == "tls"]
    if not rows:
        return
    table = Table(title="TLS y cabeceras de seguridad", show_lines=True)
    for col in ["Comprobacion", "Resultado", "Detalle"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name, f.title or "-", f.note or "-")
    console.print(table)


def print_typosquat_table(findings: list[Finding]):
    """Typosquatting y domain squatting: variantes del dominio realmente
    registradas segun resolucion DNS. Categoria opt-in (--categories
    typosquat o --all)."""
    rows = [f for f in findings if f.category == "typosquat"]
    if not rows:
        return
    table = Table(title="Typosquatting y domain squatting", show_lines=True)
    for col in ["Comprobacion", "Resultado", "Variantes registradas"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name, f.title or "-", f.note or "-")
    console.print(table)


def print_ports_table(findings: list[Finding]):
    """Puertos TCP abiertos y servicios detectados (nmap). Categoria opt-in
    ("ports"): escaneo ACTIVO contra el objetivo."""
    rows = [f for f in findings if f.category == "ports"]
    if not rows:
        return
    table = Table(title="Puertos y servicios (nmap, escaneo activo)", show_lines=True)
    for col in ["Comprobacion", "Resultado", "Detalle"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name, f.title or "-", f.note or "-")
    console.print(table)


def print_vuln_table(findings: list[Finding]):
    """CVEs/exploits conocidos (NVD + ExploitDB local + Sploitus) para el
    software/version detectado en metadatos de documentos. Categoria
    opt-in (--categories vuln o --all)."""
    rows = [f for f in findings if f.category == "vuln"]
    if not rows:
        return
    table = Table(title="Vulnerabilidades conocidas (NVD / ExploitDB / Sploitus)", show_lines=True)
    for col in ["Software", "Resultados"]:
        table.add_column(col, overflow="fold")
    for f in rows:
        table.add_row(f.dork_name.replace("Vulnerabilidades conocidas: ", ""), f.note or "-")
    console.print(table)


def print_summary(findings: list[Finding]):
    authors = {f.author for f in findings if f.author}
    editors = {f.last_modified_by for f in findings if f.last_modified_by}
    software = {f.software for f in findings if f.software}
    emails = {e for f in findings for e in f.emails}
    paths = {p for f in findings for p in f.internal_paths}
    computers = {c for f in findings for c in f.computers}
    people = {f.person_name for f in findings if f.category == "people" and f.person_name}
    leaks = [f for f in findings if f.secrets or f.category in ("leak", "bucket")]
    cloud = [f for f in findings if f.category == "cloud"]
    tech = [f for f in findings if f.category == "tech"]
    vulns = [f for f in findings if f.category == "vuln"]
    dns_checks = [f for f in findings if f.category == "dns"]
    axfr_vulnerable = any("AXFR" in f.dork_name for f in findings if f.category == "leak")
    tls_checks = [f for f in findings if f.category == "tls"]
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]
    typosquat_alive = sum(
        f.note.count("\n") + 1 for f in typosquat_checks
        if f.note and f.note != "Ninguna variante registrada."
    )

    table = Table(title="Resumen")
    table.add_column("Categoria")
    table.add_column("Valores unicos")
    table.add_row("Usuarios/autores", ", ".join(sorted(authors)) or "-")
    table.add_row("Editores (last modified by)", ", ".join(sorted(editors)) or "-")
    table.add_row("Software/aplicaciones", ", ".join(sorted(software)) or "-")
    table.add_row("Emails detectados", ", ".join(sorted(emails)) or "-")
    table.add_row("Rutas internas detectadas", ", ".join(sorted(paths)) or "-")
    table.add_row("Equipos/servidores detectados", ", ".join(sorted(computers)) or "-")
    table.add_row("Comprobaciones DNS/WHOIS realizadas", str(len(dns_checks)))
    table.add_row("Transferencia de zona (AXFR) vulnerable",
                   "SI — critico" if axfr_vulnerable else "No" if dns_checks else "-")
    table.add_row("Comprobaciones TLS/cabeceras realizadas", str(len(tls_checks)))
    table.add_row("Variantes de typosquat/domain squat registradas",
                   str(typosquat_alive) if typosquat_checks else "-")
    table.add_row("Puertos abiertos detectados", str(len(ports_checks)))
    table.add_row("Personas encontradas en LinkedIn", str(len(people)))
    table.add_row("Proveedores cloud detectados", ", ".join(sorted(f.dork_name.split(": ")[-1] for f in cloud)) or "-")
    table.add_row("Tecnologias web detectadas", ", ".join(sorted(f"{f.dork_name.replace('Tecnologia detectada: ', '')} {f.title}" for f in tech)) or "-")
    table.add_row("Software con CVEs/exploits conocidos", str(len(vulns)))
    table.add_row("Ficheros con posibles credenciales/leaks", str(len(leaks)))
    console.print(table)


def export_json(findings: list[Finding], path: Path):
    with open(path, "w") as f:
        json.dump([asdict(x) for x in findings], f, indent=2, ensure_ascii=False)


def export_csv(findings: list[Finding], path: Path):
    if not findings:
        return
    fields = list(asdict(findings[0]).keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["secrets"] = ";".join(row["secrets"])
            row["emails"] = ";".join(row["emails"])
            row["internal_paths"] = ";".join(row["internal_paths"])
            writer.writerow(row)


def export_txt(findings: list[Finding], domain: str, path: Path):
    """Informe legible de un vistazo, para leer sin abrir Excel/JSON."""
    authors = sorted({f.author for f in findings if f.author})
    editors = sorted({f.last_modified_by for f in findings if f.last_modified_by})
    software = sorted({f.software for f in findings if f.software})
    emails = sorted({e for f in findings for e in f.emails})
    paths = sorted({p for f in findings for p in f.internal_paths})
    computers = sorted({c for f in findings for c in f.computers})
    leaks = [f for f in findings if f.secrets or f.category in ("leak", "bucket")]
    docs = [f for f in findings if f.category == "document"]
    sensitive = [f for f in findings if f.category == "sensitive"]
    platform = [f for f in findings if f.category == "platform"]
    email_osint = [f for f in findings if f.category == "email"]
    people = org_chart_rows(findings)
    external = [f for f in findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    vulns = [f for f in findings if f.category == "vuln"]
    dns_checks = [f for f in findings if f.category == "dns"]
    tls_checks = [f for f in findings if f.category == "tls"]
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]

    risk = compute_risk_score(findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")

    lines = []
    lines.append("=" * 70)
    lines.append(f" INFORME FRIB1TRECON - {domain}")
    lines.append(f" Generado: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"NIVEL DE RIESGO: {risk['level_label'].upper()} ({risk_score_txt}%)")
    for item in risk["breakdown"]:
        estado = "A REVISAR" if item["triggered"] else "OK"
        weight_txt = f"{item['weight']:.2f}".rstrip("0").rstrip(".")
        lines.append(f"  [{estado:>9}] {item['label']} (peso {weight_txt})")
    lines.append("")
    lines.append(f"Documentos con metadatos encontrados : {len(docs)}")
    lines.append(f"Ficheros sensibles encontrados       : {len(sensitive)}")
    lines.append(f"Menciones en plataformas externas     : {len(platform)}")
    lines.append(f"Paginas con emails publicos           : {len(email_osint)}")
    lines.append(f"Personas encontradas en LinkedIn       : {len(people)}")
    lines.append(f"Hallazgos en fuentes externas          : {len(external)}")
    lines.append(f"Comprobaciones DNS/WHOIS realizadas    : {len(dns_checks)}")
    lines.append(f"Comprobaciones TLS/cabeceras realizadas : {len(tls_checks)}")
    lines.append(f"Puertos abiertos / servicios detectados : {len(ports_checks)}")
    if typosquat_checks:
        lines.append(f"Comprobaciones typosquat/domain squat realizadas : {len(typosquat_checks)}")
    lines.append(f"Software con CVEs/exploits conocidos   : {len(vulns)}")
    lines.append(f"Posibles leaks / credenciales         : {len(leaks)}")
    lines.append("")
    lines.append("-- RESUMEN --")
    lines.append(f"Usuarios/autores encontrados : {', '.join(authors) or '-'}")
    lines.append(f"Editores (last modified by)  : {', '.join(editors) or '-'}")
    lines.append(f"Software/aplicaciones        : {', '.join(software) or '-'}")
    lines.append(f"Emails detectados            : {', '.join(emails) or '-'}")
    lines.append(f"Rutas internas detectadas    : {', '.join(paths) or '-'}")
    lines.append(f"Equipos/servidores detectados: {', '.join(computers) or '-'}")
    cloud = [f for f in findings if f.category == "cloud"]
    if cloud:
        lines.append(f"Proveedores cloud detectados : {', '.join(f.dork_name.split(': ')[-1] for f in cloud)}")
    tech = [f for f in findings if f.category == "tech"]
    if tech:
        tech_list = ", ".join(f"{f.dork_name.replace('Tecnologia detectada: ', '')} {f.title}" for f in tech)
        lines.append(f"Tecnologias web detectadas   : {tech_list}")
    lines.append("")

    if dns_checks:
        lines.append("-- DNS Y WHOIS --")
        for f in dns_checks:
            lines.append(f"[{f.dork_name}] {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if tls_checks:
        lines.append("-- TLS Y CABECERAS DE SEGURIDAD --")
        for f in tls_checks:
            lines.append(f"[{f.dork_name}] {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if typosquat_checks:
        lines.append("-- TYPOSQUATTING Y DOMAIN SQUATTING --")
        for f in typosquat_checks:
            lines.append(f"[{f.dork_name}] {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if ports_checks:
        lines.append("-- PUERTOS Y SERVICIOS (nmap, escaneo activo) --")
        for f in ports_checks:
            lines.append(f"[{f.dork_name}] {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if docs:
        lines.append("-- DOCUMENTOS --")
        for f in docs:
            lines.append(f"[{f.filetype}] {f.url}")
            lines.append(f"    Autor: {f.author or '-'}  |  Ult. modif. por: {f.last_modified_by or '-'}")
            lines.append(f"    Software: {f.software or '-'}  |  Creado: {f.created or '-'}  |  Modificado: {f.modified or '-'}")
            if f.emails:
                lines.append(f"    Emails: {', '.join(f.emails)}")
            if f.internal_paths:
                lines.append(f"    Rutas internas: {', '.join(f.internal_paths)}")
            if f.computers:
                lines.append(f"    Equipos/servidores: {', '.join(f.computers)}")
            if f.gps:
                lines.append(f"    [!] GPS: {f.gps}  (https://www.google.com/maps?q={f.gps})")
            lines.append("")

    if sensitive:
        lines.append("-- FICHEROS SENSIBLES --")
        for f in sensitive:
            marker = " [!] " if f.secrets else " "
            lines.append(f"[{f.filetype}]{marker}{f.url}")
            if f.secrets:
                lines.append(f"    Patrones detectados: {', '.join(f.secrets)}")
            lines.append("")

    if platform or leaks:
        lines.append("-- PLATAFORMAS EXTERNAS / OSINT --")
        for f in findings:
            if f.category in ("platform", "leak"):
                marker = " [LEAK] " if f.category == "leak" else " "
                detalle = leak_detail(f)
                sufijo = f" ({detalle})" if detalle else ""
                lines.append(f"{marker}{f.dork_name}: {f.url}{sufijo}")
        lines.append("")

    if email_osint:
        lines.append("-- EMAILS DE FUENTES PUBLICAS --")
        for f in email_osint:
            lines.append(f"{', '.join(f.emails)}  ({f.dork_name}: {f.url})")
        lines.append("")

    if people:
        lines.append("-- ORGANIGRAMA APROXIMADO (LinkedIn) --")
        lines.append("(agrupado por nivel de seniority detectado en el puesto; NO son")
        lines.append(" relaciones de jefatura reales, LinkedIn no las expone en busqueda publica)")
        lines.append("")
        current_level = None
        for f in people:
            if f.seniority != current_level:
                current_level = f.seniority
                lines.append(f"  [{SENIORITY_LABELS.get(current_level, current_level)}]")
            lines.append(f"    - {f.person_name} - {f.role}  [{confianza_empresa(f)}]  ({f.url})")
        lines.append("")

    if external:
        lines.append("-- FUENTES EXTERNAS Y CLOUD (Shodan / VirusTotal / AbuseIPDB / GrayHatWarfare / IntelX / crt.sh / Wayback / AWS-Azure-GCP...) --")
        for f in external:
            lines.append(f"[{f.dork_name}] {f.title or '-'}")
            if f.note:
                lines.append(f"    {f.note}")
            if f.url:
                lines.append(f"    {f.url}")
        lines.append("")

    if tech:
        lines.append("-- TECNOLOGIAS WEB DETECTADAS --")
        for f in tech:
            lines.append(f"[{f.dork_name.replace('Tecnologia detectada: ', '')}] version {f.title or '-'}")
        lines.append("")

    if vulns:
        lines.append("-- VULNERABILIDADES CONOCIDAS (NVD / ExploitDB / Sploitus) --")
        for f in vulns:
            software_name = f.dork_name.replace("Vulnerabilidades conocidas: ", "")
            lines.append(f"[{software_name}] {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def export_excel(findings: list[Finding], domain: str, path: Path):
    """Excel con una hoja por categoria + hoja de resumen."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
    leak_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

    def write_sheet(ws, headers, rows, highlight_col=None, highlight_value=None):
        """highlight_value=None: resalta si la celda de highlight_col no esta
        vacia. Si se da un valor, resalta solo cuando la celda coincide con el
        (p.ej. Categoria == "leak"), para no pintar filas que simplemente
        tienen ese campo relleno siempre."""
        ws.append(headers)
        for cell in ws[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center")
        for row in rows:
            ws.append(row)
        for i, _ in enumerate(headers, start=1):
            ws.column_dimensions[get_column_letter(i)].width = 28
        if highlight_col is not None:
            for row_cells in ws.iter_rows(min_row=2):
                value = row_cells[highlight_col].value
                hit = (value == highlight_value) if highlight_value is not None \
                    else value not in (None, "", "-")
                if hit:
                    for cell in row_cells:
                        cell.fill = leak_fill

    ws_docs = wb.active
    ws_docs.title = "Documentos"
    docs = [f for f in findings if f.category == "document"]
    write_sheet(
        ws_docs,
        ["Tipo", "Autor", "Ult. modif. por", "Software", "Company", "Manager",
         "Creado", "Modificado", "Emails", "Rutas internas", "Equipos/Servidores", "GPS", "URL"],
        [[f.filetype, f.author, f.last_modified_by, f.software, f.company, f.manager,
          f.created, f.modified, ", ".join(f.emails), ", ".join(f.internal_paths),
          ", ".join(f.computers), f.gps or "-", f.url]
         for f in docs],
    )

    ws_sens = wb.create_sheet("Sensibles")
    sens = [f for f in findings if f.category == "sensitive"]
    write_sheet(
        ws_sens,
        ["Tipo", "Patrones detectados", "URL"],
        [[f.filetype, ", ".join(f.secrets), f.url] for f in sens],
        highlight_col=1,
    )

    ws_plat = wb.create_sheet("Plataformas_OSINT")
    plat = [f for f in findings if f.category in ("platform", "leak")]
    write_sheet(
        ws_plat,
        ["Categoria", "Dork", "Detalle", "URL"],
        [[f.category, f.dork_name, leak_detail(f), f.url]
         for f in plat],
        highlight_col=0, highlight_value="leak",
    )

    ws_email = wb.create_sheet("Emails_OSINT")
    email_osint = [f for f in findings if f.category == "email"]
    write_sheet(
        ws_email,
        ["Emails", "Encontrado en", "URL"],
        [[", ".join(f.emails), f.dork_name, f.url] for f in email_osint],
        highlight_col=0,
    )

    ws_org = wb.create_sheet("Organigrama")
    people = org_chart_rows(findings)
    write_sheet(
        ws_org,
        ["Nivel", "Nombre", "Puesto", "Empresa", "LinkedIn"],
        [[SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name, f.role,
          confianza_empresa(f), f.url]
         for f in people],
    )
    if people:
        ws_org["F1"] = "Nota: agrupado por nivel detectado en el puesto (palabras clave)."
        ws_org["F2"] = "No son relaciones de jefatura reales: LinkedIn no las expone en busqueda publica."

    ws_ext = wb.create_sheet("Fuentes_Externas")
    external = [f for f in findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    write_sheet(
        ws_ext,
        ["Categoria", "Fuente", "Info", "Detalle", "URL"],
        [[f.category, f.dork_name, f.title or "-", f.note or "-", f.url or "-"] for f in external],
        highlight_col=0, highlight_value="bucket",
    )

    ws_dns = wb.create_sheet("DNS_WHOIS")
    dns_checks = [f for f in findings if f.category == "dns"]
    write_sheet(
        ws_dns,
        ["Comprobacion", "Resultado", "Detalle"],
        [[f.dork_name, f.title or "-", f.note or "-"] for f in dns_checks],
    )

    ws_tls = wb.create_sheet("TLS_Cabeceras")
    tls_checks = [f for f in findings if f.category == "tls"]
    write_sheet(
        ws_tls,
        ["Comprobacion", "Resultado", "Detalle"],
        [[f.dork_name, f.title or "-", f.note or "-"] for f in tls_checks],
    )

    ws_typo = wb.create_sheet("Typosquatting")
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]
    write_sheet(
        ws_typo,
        ["Comprobacion", "Resultado", "Variantes registradas"],
        [[f.dork_name, f.title or "-", f.note or "-"] for f in typosquat_checks],
    )

    ws_ports = wb.create_sheet("Puertos")
    write_sheet(
        ws_ports,
        ["Comprobacion", "Resultado", "Detalle"],
        [[f.dork_name, f.title or "-", f.note or "-"] for f in ports_checks],
    )

    ws_tech = wb.create_sheet("Tecnologias")
    tech = [f for f in findings if f.category == "tech"]
    write_sheet(
        ws_tech,
        ["Tecnologia", "Version", "URL"],
        [[f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"] for f in tech],
    )

    ws_vuln = wb.create_sheet("Vulnerabilidades")
    vulns = [f for f in findings if f.category == "vuln"]
    write_sheet(
        ws_vuln,
        ["Software", "Resultados", "Detalle (NVD / ExploitDB / Sploitus)"],
        [[f.dork_name.replace("Vulnerabilidades conocidas: ", ""), f.title or "-", f.note or "-"]
         for f in vulns],
    )

    ws_sum = wb.create_sheet("Resumen")
    authors = sorted({f.author for f in findings if f.author})
    editors = sorted({f.last_modified_by for f in findings if f.last_modified_by})
    software = sorted({f.software for f in findings if f.software})
    emails = sorted({e for f in findings for e in f.emails})
    paths = sorted({p for f in findings for p in f.internal_paths})
    computers = sorted({c for f in findings for c in f.computers})
    leaks = [f for f in findings if f.secrets or f.category in ("leak", "bucket")]
    risk = compute_risk_score(findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")
    write_sheet(
        ws_sum,
        ["Categoria", "Valores"],
        [
            ["Dominio", domain],
            ["Generado", datetime.now().isoformat(timespec="seconds")],
            ["NIVEL DE RIESGO", f"{risk['level_label'].upper()} ({risk_score_txt}%)"],
            *[[f"  - {item['label']}", "A REVISAR" if item["triggered"] else "OK"]
              for item in risk["breakdown"]],
            ["Usuarios/autores", ", ".join(authors) or "-"],
            ["Editores", ", ".join(editors) or "-"],
            ["Software", ", ".join(software) or "-"],
            ["Emails", ", ".join(emails) or "-"],
            ["Rutas internas", ", ".join(paths) or "-"],
            ["Equipos/servidores", ", ".join(computers) or "-"],
            ["Personas en LinkedIn", str(len(people))],
            ["Hallazgos en fuentes externas", str(len(external))],
            ["Comprobaciones DNS/WHOIS", str(len(dns_checks))],
            ["Comprobaciones TLS/cabeceras", str(len(tls_checks))],
            ["Comprobaciones typosquat/domain squat", str(len(typosquat_checks))],
            ["Puertos abiertos / servicios", str(len(ports_checks))],
            ["Tecnologias web detectadas", ", ".join(
                f"{f.dork_name.replace('Tecnologia detectada: ', '')} {f.title}" for f in tech) or "-"],
            ["Software con CVEs/exploits conocidos", str(len(vulns))],
            ["Ficheros con posibles leaks", str(len(leaks))],
        ],
    )

    wb.save(path)


def export_docx(findings: list[Finding], domain: str, path: Path, network_png: Path | None = None):
    """Informe en Word, con la misma informacion que el .txt/.xlsx pero en
    formato documento (tablas con estilo, apto para adjuntar a un correo o
    a una auditoria sin tener que abrir Excel). Si `network_png` existe
    (generado antes con export_network_diagram), se incrusta la imagen del
    diagrama de red al final del documento."""
    import docx
    from docx.shared import Inches

    from .cyber_health_report import _generate_cover_image
    from .docx_common import GREEN, RED, add_confidential_footer, heading, setup_document, style_table

    def add_table(doc, headers, rows):
        table = doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        for cell, text in zip(table.rows[0].cells, headers):
            cell.text = text
            for p in cell.paragraphs:
                for run in p.runs:
                    run.bold = True
        for row in rows:
            cells = table.add_row().cells
            for cell, value in zip(cells, row):
                cell.text = str(value) if value not in (None, "") else "-"
        style_table(table)
        return table

    authors = sorted({f.author for f in findings if f.author})
    editors = sorted({f.last_modified_by for f in findings if f.last_modified_by})
    software = sorted({f.software for f in findings if f.software})
    emails = sorted({e for f in findings for e in f.emails})
    paths = sorted({p for f in findings for p in f.internal_paths})
    computers = sorted({c for f in findings for c in f.computers})
    leaks = [f for f in findings if f.secrets or f.category in ("leak", "bucket")]
    docs = [f for f in findings if f.category == "document"]
    sensitive = [f for f in findings if f.category == "sensitive"]
    plat = [f for f in findings if f.category in ("platform", "leak")]
    email_osint = [f for f in findings if f.category == "email"]
    people = org_chart_rows(findings)
    external = [f for f in findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    dns_checks = [f for f in findings if f.category == "dns"]
    tls_checks = [f for f in findings if f.category == "tls"]
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]
    tech = [f for f in findings if f.category == "tech"]
    vulns = [f for f in findings if f.category == "vuln"]

    # grafo completo (misma fuente que el diagrama interactivo de la web);
    # de aqui se recortan los mini-esquemas que van encima de cada tabla
    full_graph = build_network_graph_data(findings, domain)

    def add_section_schema(doc, groups):
        """Mini-diagrama (host -> nodos de `groups`) justo encima de la
        tabla de la seccion: de un vistazo, de que host sale cada cosa.
        No hace nada si no hay graphviz o no hay nodos de esos grupos."""
        sub = filter_graph_data(full_graph, groups)
        png_path = render_graph_png(sub, max_size="3.2,3.2")
        if not png_path:
            return
        try:
            width_in, height_in = _docx_picture_size(png_path, max_width_in=3.0, max_height_in=3.0)
            doc.add_picture(str(png_path), width=Inches(width_in), height=Inches(height_in))
        finally:
            png_path.unlink(missing_ok=True)

    risk = compute_risk_score(findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")

    doc = docx.Document()
    setup_document(doc)
    add_confidential_footer(doc)
    sec0 = doc.sections[0]
    printable_w = sec0.page_width - sec0.left_margin - sec0.right_margin
    cover_buf = _generate_cover_image(domain, None, risk["score"], risk["level_label"].upper(),
                                       title_label="Informe Técnico Detallado",
                                       subtitle_label="frib1trecon")
    doc.add_picture(cover_buf, width=printable_w)
    doc.add_page_break()

    heading(doc, "Nivel de riesgo", 1)
    risk_par = doc.add_paragraph()
    risk_run = risk_par.add_run(f"{risk['level_label'].upper()} ({risk_score_txt}%)")
    risk_run.bold = True
    risk_run.font.color.rgb = RED if risk["score"] >= 40 else GREEN
    add_table(doc, ["Categoria de riesgo", "Peso", "Estado"], [
        [item["label"], f"{item['weight']:.2f}".rstrip("0").rstrip("."),
         "A REVISAR" if item["triggered"] else "OK"]
        for item in risk["breakdown"]
    ])

    heading(doc, "Resumen", 1)
    add_table(doc, ["Categoria", "Valores"], [
        ["Documentos con metadatos", str(len(docs))],
        ["Ficheros sensibles", str(len(sensitive))],
        ["Menciones en plataformas / leaks", str(len(plat))],
        ["Paginas con emails publicos", str(len(email_osint))],
        ["Personas en LinkedIn", str(len(people))],
        ["Hallazgos en fuentes externas", str(len(external))],
        ["Comprobaciones DNS/WHOIS", str(len(dns_checks))],
        ["Comprobaciones TLS/cabeceras", str(len(tls_checks))],
        ["Comprobaciones typosquat/domain squat", str(len(typosquat_checks))],
        ["Puertos abiertos / servicios", str(len(ports_checks))],
        ["Tecnologias web detectadas", str(len(tech))],
        ["Software con CVEs/exploits conocidos", str(len(vulns))],
        ["Usuarios/autores", ", ".join(authors) or "-"],
        ["Editores", ", ".join(editors) or "-"],
        ["Software", ", ".join(software) or "-"],
        ["Emails detectados", ", ".join(emails) or "-"],
        ["Rutas internas", ", ".join(paths) or "-"],
        ["Equipos/servidores", ", ".join(computers) or "-"],
        ["Ficheros con posibles leaks", str(len(leaks))],
    ])

    if dns_checks:
        heading(doc, "DNS y WHOIS", 1)
        add_table(doc, ["Comprobacion", "Resultado", "Detalle"], [
            [f.dork_name, f.title or "-", f.note or "-"] for f in dns_checks
        ])

    if tls_checks:
        heading(doc, "TLS y cabeceras de seguridad", 1)
        add_table(doc, ["Comprobacion", "Resultado", "Detalle"], [
            [f.dork_name, f.title or "-", f.note or "-"] for f in tls_checks
        ])

    if typosquat_checks:
        heading(doc, "Typosquatting y domain squatting", 1)
        add_table(doc, ["Comprobacion", "Resultado", "Variantes registradas"], [
            [f.dork_name, f.title or "-", f.note or "-"] for f in typosquat_checks
        ])

    if ports_checks:
        heading(doc, "Puertos y servicios (nmap)", 1)
        add_table(doc, ["Comprobacion", "Resultado", "Detalle"], [
            [f.dork_name, f.title or "-", f.note or "-"] for f in ports_checks
        ])

    if docs:
        heading(doc, "Documentos con metadatos", 1)
        add_section_schema(doc, {"document"})
        add_table(doc, ["Tipo", "Autor", "Ult. modif.", "Software", "Emails", "Rutas", "Equipos", "GPS", "URL"], [
            [f.filetype, f.author, f.last_modified_by, f.software,
             ", ".join(f.emails), ", ".join(f.internal_paths), ", ".join(f.computers), f.gps or "-", f.url]
            for f in docs
        ])

    if sensitive:
        heading(doc, "Ficheros sensibles (sql/log/env/bak)", 1)
        add_section_schema(doc, {"sensitive"})
        add_table(doc, ["Tipo", "Patrones detectados", "URL"],
                  [[f.filetype, ", ".join(f.secrets), f.url] for f in sensitive])

    if plat:
        heading(doc, "Plataformas externas / posibles leaks", 1)
        add_section_schema(doc, {"platform", "leak"})
        add_table(doc, ["Categoria", "Dork", "Detalle", "URL"], [
            [f.category, f.dork_name, leak_detail(f), f.url]
            for f in plat
        ])

    if email_osint:
        heading(doc, "Emails recopilados de fuentes publicas", 1)
        add_section_schema(doc, {"email"})
        add_table(doc, ["Emails", "Encontrado en", "URL"],
                  [[", ".join(f.emails), f.dork_name, f.url] for f in email_osint])

    if people:
        heading(doc, "Organigrama aproximado (LinkedIn)", 1)
        note = doc.add_paragraph()
        note.add_run(
            "Agrupado por nivel de seniority detectado en el puesto (palabras clave). "
            "No son relaciones de jefatura reales: LinkedIn no las expone en busqueda publica."
        ).italic = True
        add_section_schema(doc, {"person"})
        add_table(doc, ["Nivel", "Nombre", "Puesto", "Empresa", "LinkedIn"], [
            [SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name, f.role,
             confianza_empresa(f), f.url]
            for f in people
        ])

    if external:
        heading(doc, "Fuentes externas y Cloud (Shodan / VirusTotal / AbuseIPDB / GrayHatWarfare / IntelX / crt.sh / Wayback / AWS-Azure-GCP...)", 1)
        add_section_schema(doc, {"ip", "cloud"})
        add_table(doc, ["Fuente", "Info", "Detalle", "URL"], [
            [f.dork_name, f.title or "-", f.note or "-", f.url or "-"] for f in external
        ])

    if tech:
        heading(doc, "Tecnologias detectadas", 1)
        add_section_schema(doc, {"tech"})
        add_table(doc, ["Tecnologia", "Version", "URL"], [
            [f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"]
            for f in tech
        ])

    if vulns:
        heading(doc, "Vulnerabilidades conocidas (NVD / ExploitDB / Sploitus)", 1)
        add_section_schema(doc, {"vuln"})
        add_table(doc, ["Software", "Resultados", "Detalle"], [
            [f.dork_name.replace("Vulnerabilidades conocidas: ", ""), f.title or "-", f.note or "-"]
            for f in vulns
        ])

    if network_png and network_png.exists():
        heading(doc, "Diagrama de red", 1)
        width_in, height_in = _docx_picture_size(network_png, max_width_in=6.3, max_height_in=8.0)
        doc.add_picture(str(network_png), width=Inches(width_in), height=Inches(height_in))

    doc.save(path)


def export_maltego_csv(findings: list[Finding], domain: str, path: Path):
    """CSV en formato largo (EntityType, Value, Source, Notas) para importar
    a mano en Maltego como entidades (su importador de CSV te deja mapear
    cada EntityType a su tipo de entidad real: Domain, Email Address,
    Person, URL, IPv4 Address...). Maltego no tiene una API/SDK que se
    pueda llamar desde aqui, asi que esto es lo maximo integrable sin la
    aplicacion de escritorio."""
    rows = [{"EntityType": "Domain", "Value": domain, "Source": "frib1trecon", "Notes": ""}]

    emails = sorted({e for f in findings for e in f.emails})
    for e in emails:
        rows.append({"EntityType": "Email", "Value": e, "Source": "frib1trecon", "Notes": ""})

    for f in org_chart_rows(findings):
        rows.append({
            "EntityType": "Person", "Value": f.person_name,
            "Source": "LinkedIn", "Notes": f"{f.role} | {f.url}",
        })

    computers = sorted({c for f in findings for c in f.computers})
    for c in computers:
        rows.append({"EntityType": "Server", "Value": c, "Source": "metadatos de documentos", "Notes": ""})

    for f in findings:
        if f.category == "shodan":
            rows.append({
                "EntityType": "IPAddress", "Value": f.title, "Source": f.dork_name, "Notes": f.note,
            })

    for f in findings:
        if f.url and f.category not in ("shodan",):
            rows.append({
                "EntityType": "URL", "Value": f.url, "Source": f.category, "Notes": f.note or f.dork_name,
            })

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["EntityType", "Value", "Source", "Notes"])
        writer.writeheader()
        writer.writerows(rows)


def export_master_txt(results: dict[str, list[Finding]], domain: str, path: Path):
    """Informe que junta TODOS los hosts (dominio + subdominios de
    --recursive) en un solo fichero, con un resumen global, los leaks de
    todos los hosts juntos, y luego un bloque por host."""
    all_findings = [f for fs in results.values() for f in fs]
    authors = sorted({f.author for f in all_findings if f.author})
    editors = sorted({f.last_modified_by for f in all_findings if f.last_modified_by})
    software = sorted({f.software for f in all_findings if f.software})
    emails = sorted({e for f in all_findings for e in f.emails})
    paths = sorted({p for f in all_findings for p in f.internal_paths})
    computers = sorted({c for f in all_findings for c in f.computers})
    leaks = [f for f in all_findings if f.secrets or f.category in ("leak", "bucket")]
    dns_checks = [f for f in all_findings if f.category == "dns"]
    tls_checks = [f for f in all_findings if f.category == "tls"]
    typosquat_checks = [f for f in all_findings if f.category == "typosquat"]
    ports_checks = [f for f in all_findings if f.category == "ports"]
    tech = [f for f in all_findings if f.category == "tech"]
    vulns = [f for f in all_findings if f.category == "vuln"]

    risk = compute_risk_score(all_findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")

    lines = []
    lines.append("=" * 70)
    lines.append(f" INFORME MAESTRO FRIB1TRECON - {domain} (+{len(results) - 1} subdominio(s))")
    lines.append(f" Hosts escaneados: {', '.join(results.keys())}")
    lines.append(f" Generado: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"NIVEL DE RIESGO (todos los hosts): {risk['level_label'].upper()} ({risk_score_txt}%)")
    for item in risk["breakdown"]:
        estado = "A REVISAR" if item["triggered"] else "OK"
        weight_txt = f"{item['weight']:.2f}".rstrip("0").rstrip(".")
        lines.append(f"  [{estado:>9}] {item['label']} (peso {weight_txt})")
    lines.append("")
    lines.append(f"Total de hallazgos (todos los hosts) : {len(all_findings)}")
    lines.append(f"Posibles leaks / credenciales          : {len(leaks)}")
    lines.append("")
    lines.append("-- RESUMEN GLOBAL --")
    lines.append(f"Usuarios/autores encontrados : {', '.join(authors) or '-'}")
    lines.append(f"Editores (last modified by)  : {', '.join(editors) or '-'}")
    lines.append(f"Software/aplicaciones        : {', '.join(software) or '-'}")
    lines.append(f"Emails detectados            : {', '.join(emails) or '-'}")
    lines.append(f"Rutas internas detectadas    : {', '.join(paths) or '-'}")
    lines.append(f"Equipos/servidores detectados: {', '.join(computers) or '-'}")
    lines.append(f"Comprobaciones DNS/WHOIS realizadas: {len(dns_checks)}")
    lines.append(f"Comprobaciones TLS/cabeceras realizadas: {len(tls_checks)}")
    lines.append(f"Puertos abiertos / servicios realizados: {len(ports_checks)}")
    if typosquat_checks:
        lines.append(f"Comprobaciones typosquat/domain squat realizadas: {len(typosquat_checks)}")
    lines.append(f"Tecnologias web detectadas: {len(tech)}")
    lines.append(f"Software con CVEs/exploits conocidos: {len(vulns)}")
    lines.append("")

    if dns_checks:
        lines.append("-- DNS Y WHOIS (todos los hosts) --")
        for f in dns_checks:
            lines.append(f"[{f.host or domain}] {f.dork_name}: {f.title or '-'}")
        lines.append("")

    if tls_checks:
        lines.append("-- TLS Y CABECERAS DE SEGURIDAD (todos los hosts) --")
        for f in tls_checks:
            lines.append(f"[{f.host or domain}] {f.dork_name}: {f.title or '-'}")
        lines.append("")

    if typosquat_checks:
        lines.append("-- TYPOSQUATTING Y DOMAIN SQUATTING (todos los hosts) --")
        for f in typosquat_checks:
            lines.append(f"[{f.host or domain}] {f.dork_name}: {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if ports_checks:
        lines.append("-- PUERTOS Y SERVICIOS (nmap, todos los hosts) --")
        for f in ports_checks:
            lines.append(f"[{f.host or domain}] {f.dork_name}: {f.title or '-'}")
        lines.append("")

    if tech:
        lines.append("-- TECNOLOGIAS WEB DETECTADAS (todos los hosts) --")
        for f in tech:
            lines.append(f"[{f.host or domain}] {f.dork_name.replace('Tecnologia detectada: ', '')}: version {f.title or '-'}")
        lines.append("")

    if vulns:
        lines.append("-- VULNERABILIDADES CONOCIDAS (NVD / ExploitDB / Sploitus, todos los hosts) --")
        for f in vulns:
            software_name = f.dork_name.replace("Vulnerabilidades conocidas: ", "")
            lines.append(f"[{f.host or domain}] {software_name}: {f.title or '-'}")
            for note_line in (f.note or "").splitlines():
                lines.append(f"    {note_line}")
        lines.append("")

    if leaks:
        lines.append("-- LEAKS / CREDENCIALES (todos los hosts) --")
        for f in leaks:
            detalle = leak_detail(f)
            lines.append(f"[{f.host or domain}] {f.dork_name}: {f.url}  ({detalle})")
        lines.append("")

    for host, host_findings in results.items():
        lines.append("-" * 70)
        lines.append(f" HOST: {host}  ({len(host_findings)} hallazgo(s))")
        lines.append("-" * 70)

        docs = [f for f in host_findings if f.category == "document"]
        for f in docs:
            lines.append(f"  [doc:{f.filetype}] {f.url}")
            lines.append(f"      autor={f.author or '-'}  software={f.software or '-'}"
                         f"  emails={', '.join(f.emails) or '-'}")

        sens = [f for f in host_findings if f.category == "sensitive" and f.secrets]
        for f in sens:
            lines.append(f"  [sensible:{f.filetype}] {f.url}  patrones={', '.join(f.secrets)}")

        host_leaks = [f for f in host_findings if f.category in ("leak", "bucket")]
        for f in host_leaks:
            detalle = leak_detail(f)
            lines.append(f"  [LEAK] {f.dork_name}: {f.url}  ({detalle})")

        host_emails = sorted({e for f in host_findings for e in f.emails if f.category == "email"})
        if host_emails:
            lines.append(f"  emails publicos: {', '.join(host_emails)}")

        host_external = [f for f in host_findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
        for f in host_external:
            lines.append(f"  [{f.category}] {f.dork_name}: {f.title or f.url} — {f.note or '-'}")

        host_dns = [f for f in host_findings if f.category == "dns"]
        for f in host_dns:
            lines.append(f"  [dns] {f.dork_name}: {f.title or '-'}")

        host_tls = [f for f in host_findings if f.category == "tls"]
        for f in host_tls:
            lines.append(f"  [tls] {f.dork_name}: {f.title or '-'}")

        host_typosquat = [f for f in host_findings if f.category == "typosquat"]
        for f in host_typosquat:
            lines.append(f"  [typosquat] {f.dork_name}: {f.title or '-'}")

        host_tech = [f for f in host_findings if f.category == "tech"]
        for f in host_tech:
            lines.append(f"  [tech] {f.dork_name}: version {f.title or '-'}")

        host_vulns = [f for f in host_findings if f.category == "vuln"]
        for f in host_vulns:
            lines.append(f"  [vuln] {f.dork_name}: {f.title or '-'}")

        lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def export_master_excel(results: dict[str, list[Finding]], domain: str, path: Path):
    """Como export_excel pero con todos los hosts juntos y una columna
    'Host' en cada hoja, mas una hoja de resumen por host."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    all_findings = [f for fs in results.values() for f in fs]

    wb = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
    leak_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

    def write_sheet(ws, headers, rows, highlight_col=None, highlight_value=None):
        ws.append(headers)
        for cell in ws[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center")
        for row in rows:
            ws.append(row)
        for i, _ in enumerate(headers, start=1):
            ws.column_dimensions[get_column_letter(i)].width = 24
        if highlight_col is not None:
            for row_cells in ws.iter_rows(min_row=2):
                value = row_cells[highlight_col].value
                hit = (value == highlight_value) if highlight_value is not None \
                    else value not in (None, "", "-")
                if hit:
                    for cell in row_cells:
                        cell.fill = leak_fill

    ws_docs = wb.active
    ws_docs.title = "Documentos"
    docs = [f for f in all_findings if f.category == "document"]
    write_sheet(
        ws_docs,
        ["Host", "Tipo", "Autor", "Ult. modif.", "Software", "Emails", "Rutas internas", "Equipos", "GPS", "URL"],
        [[f.host or domain, f.filetype, f.author, f.last_modified_by, f.software,
          ", ".join(f.emails), ", ".join(f.internal_paths), ", ".join(f.computers), f.gps or "-", f.url]
         for f in docs],
    )

    ws_sens = wb.create_sheet("Sensibles")
    sens = [f for f in all_findings if f.category == "sensitive"]
    write_sheet(
        ws_sens,
        ["Host", "Tipo", "Patrones detectados", "URL"],
        [[f.host or domain, f.filetype, ", ".join(f.secrets), f.url] for f in sens],
        highlight_col=2,
    )

    ws_plat = wb.create_sheet("Plataformas_OSINT")
    plat = [f for f in all_findings if f.category in ("platform", "leak")]
    write_sheet(
        ws_plat,
        ["Host", "Categoria", "Dork", "Detalle", "URL"],
        [[f.host or domain, f.category, f.dork_name,
          leak_detail(f), f.url] for f in plat],
        highlight_col=1, highlight_value="leak",
    )

    ws_email = wb.create_sheet("Emails_OSINT")
    email_osint = [f for f in all_findings if f.category == "email"]
    write_sheet(
        ws_email,
        ["Host", "Emails", "Encontrado en", "URL"],
        [[f.host or domain, ", ".join(f.emails), f.dork_name, f.url] for f in email_osint],
    )

    ws_org = wb.create_sheet("Organigrama")
    people = org_chart_rows(all_findings)
    write_sheet(
        ws_org,
        ["Host", "Nivel", "Nombre", "Puesto", "Empresa", "LinkedIn"],
        [[f.host or domain, SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name, f.role,
          confianza_empresa(f), f.url]
         for f in people],
    )

    ws_ext = wb.create_sheet("Fuentes_Externas")
    external = [f for f in all_findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    write_sheet(
        ws_ext,
        ["Host", "Categoria", "Fuente", "Info", "Detalle", "URL"],
        [[f.host or domain, f.category, f.dork_name, f.title or "-", f.note or "-", f.url or "-"]
         for f in external],
        highlight_col=1, highlight_value="bucket",
    )

    ws_dns = wb.create_sheet("DNS_WHOIS")
    dns_checks = [f for f in all_findings if f.category == "dns"]
    write_sheet(
        ws_dns,
        ["Host", "Comprobacion", "Resultado", "Detalle"],
        [[f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in dns_checks],
    )

    ws_tls = wb.create_sheet("TLS_Cabeceras")
    tls_checks = [f for f in all_findings if f.category == "tls"]
    write_sheet(
        ws_tls,
        ["Host", "Comprobacion", "Resultado", "Detalle"],
        [[f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in tls_checks],
    )

    ws_typo = wb.create_sheet("Typosquatting")
    typosquat_checks = [f for f in all_findings if f.category == "typosquat"]
    ports_checks = [f for f in all_findings if f.category == "ports"]
    write_sheet(
        ws_typo,
        ["Host", "Comprobacion", "Resultado", "Variantes registradas"],
        [[f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in typosquat_checks],
    )

    ws_ports = wb.create_sheet("Puertos")
    write_sheet(
        ws_ports,
        ["Host", "Comprobacion", "Resultado", "Detalle"],
        [[f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in ports_checks],
    )

    ws_tech = wb.create_sheet("Tecnologias")
    tech = [f for f in all_findings if f.category == "tech"]
    write_sheet(
        ws_tech,
        ["Host", "Tecnologia", "Version", "URL"],
        [[f.host or domain, f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"]
         for f in tech],
    )

    ws_vuln = wb.create_sheet("Vulnerabilidades")
    vulns = [f for f in all_findings if f.category == "vuln"]
    write_sheet(
        ws_vuln,
        ["Host", "Software", "Resultados", "Detalle (NVD / ExploitDB / Sploitus)"],
        [[f.host or domain, f.dork_name.replace("Vulnerabilidades conocidas: ", ""), f.title or "-", f.note or "-"]
         for f in vulns],
    )

    ws_risk = wb.create_sheet("Riesgo_Global")
    risk = compute_risk_score(all_findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")
    write_sheet(
        ws_risk,
        ["Categoria de riesgo", "Peso", "Estado"],
        [["NIVEL DE RIESGO (todos los hosts)", "100",
          f"{risk['level_label'].upper()} ({risk_score_txt}%)"]]
        + [[item["label"], f"{item['weight']:.2f}".rstrip("0").rstrip("."),
            "A REVISAR" if item["triggered"] else "OK"]
           for item in risk["breakdown"]],
    )

    ws_sum = wb.create_sheet("Resumen_por_host")
    rows = []
    for host, host_findings in results.items():
        host_leaks = [f for f in host_findings if f.secrets or f.category in ("leak", "bucket")]
        host_emails = {e for f in host_findings for e in f.emails}
        host_docs = len([f for f in host_findings if f.category == "document"])
        rows.append([host, host_docs, len(host_leaks), len(host_emails), len(host_findings)])
    write_sheet(ws_sum, ["Host", "Documentos", "Leaks", "Emails unicos", "Total hallazgos"], rows)

    wb.save(path)


def export_master_docx(results: dict[str, list[Finding]], domain: str, path: Path, network_png: Path | None = None):
    """Como export_docx pero con todos los hosts juntos y columna 'Host'."""
    import docx
    from docx.shared import Inches

    from .cyber_health_report import _generate_cover_image
    from .docx_common import GREEN, RED, add_confidential_footer, heading, setup_document, style_table

    all_findings = [f for fs in results.values() for f in fs]
    full_graph = build_network_graph_data(results, domain)

    def add_table(doc, headers, rows):
        table = doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        for cell, text in zip(table.rows[0].cells, headers):
            cell.text = text
            for p in cell.paragraphs:
                for run in p.runs:
                    run.bold = True
        for row in rows:
            cells = table.add_row().cells
            for cell, value in zip(cells, row):
                cell.text = str(value) if value not in (None, "") else "-"
        style_table(table)
        return table

    def add_section_schema(doc, groups):
        """Mini-diagrama (host -> nodos de `groups`) justo encima de la
        tabla de la seccion. No hace nada si no hay graphviz o no hay
        nodos de esos grupos."""
        sub = filter_graph_data(full_graph, groups)
        png_path = render_graph_png(sub, max_size="3.2,3.2")
        if not png_path:
            return
        try:
            width_in, height_in = _docx_picture_size(png_path, max_width_in=3.0, max_height_in=3.0)
            doc.add_picture(str(png_path), width=Inches(width_in), height=Inches(height_in))
        finally:
            png_path.unlink(missing_ok=True)

    risk = compute_risk_score(all_findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")

    doc = docx.Document()
    setup_document(doc)
    add_confidential_footer(doc)
    sec0 = doc.sections[0]
    printable_w = sec0.page_width - sec0.left_margin - sec0.right_margin
    cover_buf = _generate_cover_image(domain, None, risk["score"], risk["level_label"].upper(),
                                       title_label="Informe Técnico Detallado (maestro)",
                                       subtitle_label="frib1trecon")
    doc.add_picture(cover_buf, width=printable_w)
    doc.add_paragraph(f"Hosts escaneados ({len(results)}): {', '.join(results.keys())}")
    doc.add_page_break()

    heading(doc, "Nivel de riesgo (todos los hosts)", 1)
    risk_par = doc.add_paragraph()
    risk_run = risk_par.add_run(f"{risk['level_label'].upper()} ({risk_score_txt}%)")
    risk_run.bold = True
    risk_run.font.color.rgb = RED if risk["score"] >= 40 else GREEN
    add_table(doc, ["Categoria de riesgo", "Peso", "Estado"], [
        [item["label"], f"{item['weight']:.2f}".rstrip("0").rstrip("."),
         "A REVISAR" if item["triggered"] else "OK"]
        for item in risk["breakdown"]
    ])

    heading(doc, "Resumen por host", 1)
    rows = []
    for host, host_findings in results.items():
        host_leaks = [f for f in host_findings if f.secrets or f.category in ("leak", "bucket")]
        host_emails = {e for f in host_findings for e in f.emails}
        host_docs = len([f for f in host_findings if f.category == "document"])
        rows.append([host, str(host_docs), str(len(host_leaks)), str(len(host_emails))])
    add_table(doc, ["Host", "Documentos", "Leaks", "Emails unicos"], rows)

    docs = [f for f in all_findings if f.category == "document"]
    if docs:
        heading(doc, "Documentos con metadatos", 1)
        add_section_schema(doc, {"document"})
        add_table(doc, ["Host", "Tipo", "Autor", "Software", "Emails", "GPS", "URL"], [
            [f.host or domain, f.filetype, f.author, f.software, ", ".join(f.emails), f.gps or "-", f.url]
            for f in docs
        ])

    leaks = [f for f in all_findings if f.secrets or f.category in ("leak", "bucket")]
    if leaks:
        heading(doc, "Leaks / credenciales (todos los hosts)", 1)
        add_section_schema(doc, {"leak"})
        add_table(doc, ["Host", "Dork", "Detalle", "URL"], [
            [f.host or domain, f.dork_name, leak_detail(f), f.url]
            for f in leaks
        ])

    email_osint = [f for f in all_findings if f.category == "email"]
    if email_osint:
        heading(doc, "Emails de fuentes publicas", 1)
        add_section_schema(doc, {"email"})
        add_table(doc, ["Host", "Emails", "Encontrado en", "URL"], [
            [f.host or domain, ", ".join(f.emails), f.dork_name, f.url] for f in email_osint
        ])

    people = org_chart_rows(all_findings)
    if people:
        heading(doc, "Organigrama aproximado (LinkedIn)", 1)
        add_section_schema(doc, {"person"})
        add_table(doc, ["Host", "Nivel", "Nombre", "Puesto", "Empresa", "LinkedIn"], [
            [f.host or domain, SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name, f.role,
             confianza_empresa(f), f.url]
            for f in people
        ])

    external = [f for f in all_findings if f.category in ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    if external:
        heading(doc, "Fuentes externas y Cloud", 1)
        add_section_schema(doc, {"ip", "cloud"})
        add_table(doc, ["Host", "Fuente", "Info", "Detalle", "URL"], [
            [f.host or domain, f.dork_name, f.title or "-", f.note or "-", f.url or "-"] for f in external
        ])

    dns_checks = [f for f in all_findings if f.category == "dns"]
    if dns_checks:
        heading(doc, "DNS y WHOIS", 1)
        add_table(doc, ["Host", "Comprobacion", "Resultado", "Detalle"], [
            [f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in dns_checks
        ])

    tls_checks = [f for f in all_findings if f.category == "tls"]
    if tls_checks:
        heading(doc, "TLS y cabeceras de seguridad", 1)
        add_table(doc, ["Host", "Comprobacion", "Resultado", "Detalle"], [
            [f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in tls_checks
        ])

    typosquat_checks = [f for f in all_findings if f.category == "typosquat"]
    ports_checks = [f for f in all_findings if f.category == "ports"]
    if typosquat_checks:
        heading(doc, "Typosquatting y domain squatting", 1)
        add_table(doc, ["Host", "Comprobacion", "Resultado", "Variantes registradas"], [
            [f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in typosquat_checks
        ])

    if ports_checks:
        heading(doc, "Puertos y servicios (nmap)", 1)
        add_table(doc, ["Host", "Comprobacion", "Resultado", "Detalle"], [
            [f.host or domain, f.dork_name, f.title or "-", f.note or "-"] for f in ports_checks
        ])

    tech = [f for f in all_findings if f.category == "tech"]
    if tech:
        heading(doc, "Tecnologias detectadas", 1)
        add_section_schema(doc, {"tech"})
        add_table(doc, ["Host", "Tecnologia", "Version", "URL"], [
            [f.host or domain, f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"]
            for f in tech
        ])

    vulns = [f for f in all_findings if f.category == "vuln"]
    if vulns:
        heading(doc, "Vulnerabilidades conocidas (NVD / ExploitDB / Sploitus)", 1)
        add_section_schema(doc, {"vuln"})
        add_table(doc, ["Host", "Software", "Resultados", "Detalle"], [
            [f.host or domain, f.dork_name.replace("Vulnerabilidades conocidas: ", ""), f.title or "-", f.note or "-"]
            for f in vulns
        ])

    if network_png and network_png.exists():
        heading(doc, "Diagrama de red (todos los hosts)", 1)
        width_in, height_in = _docx_picture_size(network_png, max_width_in=6.3, max_height_in=8.0)
        doc.add_picture(str(network_png), width=Inches(width_in), height=Inches(height_in))

    doc.save(path)


SHODAN_HOST_IP_RE = re.compile(r"host/([\d.]+)")

# Paleta + icono por tipo de nodo, igual que el grafo interactivo de la web
# (vis-network, ver frib1trecon-web/templates/graph.html, GROUP_ICONS):
# mismo color y mismo icono Font Awesome 7 Free Solid (codepoint). "size"
# es el diametro del circulo-icono en pulgadas — deliberadamente pequeno
# para que la etiqueta (fontsize mas grande, ver _dot_from_graph_data) no
# quede chica al lado de un icono grande.
NODE_STYLES = {
    "domain":    {"color": "#4F8CFF", "icon": "", "size": 0.42},  # globe
    "subdomain": {"color": "#7C5CFF", "icon": "", "size": 0.3},   # sitemap
    "ip":        {"color": "#22D3EE", "icon": "", "size": 0.3},   # server
    "cloud":     {"color": "#2DD4BF", "icon": "", "size": 0.3},   # cloud
    "vuln":      {"color": "#FB923C", "icon": "", "size": 0.32},  # bug
    "leak":      {"color": "#F43F5E", "icon": "", "size": 0.34},  # skull
    "platform":  {"color": "#F472B6", "icon": "", "size": 0.28},  # share-nodes
    "email":     {"color": "#FACC15", "icon": "", "size": 0.28},  # user
    "person":    {"color": "#A78BFA", "icon": "", "size": 0.28},  # user-tie
    "document":  {"color": "#4ADE80", "icon": "", "size": 0.28},  # envelope
    "sensitive": {"color": "#FBBF24", "icon": "", "size": 0.3},   # lock
    "tech":      {"color": "#38BDF8", "icon": "", "size": 0.28},  # microchip
}

# Fuente Font Awesome 7 Free Solid, solo para el render estatico del grafo
# (el grafo interactivo de la web la carga via CDN; aqui, para un PNG
# incrustado en el DOCX, hace falta un .ttf local). Debian/Kali la trae en
# el paquete fonts-font-awesome; si no esta instalada, el nodo degrada a un
# circulo de color solido sin icono (nunca rompe el render).
_FA_FONT_PATHS = [
    "/usr/share/fonts-font-awesome/fonts/fa-solid-900.ttf",
    "/usr/share/fonts/truetype/font-awesome/fa-solid-900.ttf",
]
_ICON_CACHE_DIR = Path(tempfile.gettempdir()) / "frib1trecon_icons"


def _find_fa_font() -> str | None:
    for p in _FA_FONT_PATHS:
        if Path(p).exists():
            return p
    return None


def _node_icon_png(group: str) -> Path | None:
    """PNG cuadrado (fondo transparente) con un circulo del color del
    grupo y el glifo Font Awesome centrado, cacheado en disco (un fichero
    por grupo, reutilizado entre nodos/ejecuciones). None si Pillow no
    esta disponible: el llamador degrada a un circulo de color solido sin
    icono via graphviz nativo, nunca rompe el render."""
    style = NODE_STYLES.get(group)
    if not style:
        return None
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return None
    _ICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out = _ICON_CACHE_DIR / f"{group}.png"
    if out.exists():
        return out
    px = 160
    img = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([2, 2, px - 2, px - 2], fill=style["color"])
    font_path = _find_fa_font()
    if font_path:
        try:
            font = ImageFont.truetype(font_path, int(px * 0.5))
            glyph = style["icon"]
            bbox = draw.textbbox((0, 0), glyph, font=font)
            w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
            draw.text(((px - w) / 2 - bbox[0], (px - h) / 2 - bbox[1]), glyph, font=font, fill="white")
        except OSError:
            pass
    try:
        img.save(out)
    except OSError:
        return None
    return out


def _short_filename(url: str) -> str:
    """Ultimo segmento de la ruta de una URL, para etiquetas de nodo cortas
    (una URL completa como label hace el grafo ilegible)."""
    from urllib.parse import urlparse
    name = urlparse(url).path.rsplit("/", 1)[-1]
    return name or url


def build_network_graph_data(results, domain: str) -> dict:
    """Extrae TODA la informacion recopilada como nodos/aristas genericos
    (nodes: id/label/group/title: aristas: from/to/label/dashed), formato
    reutilizable tanto para el diagrama estatico (DOT/PNG) como para el
    grafo interactivo en la web (vis-network). Incluye: dominio y
    subdominios, IPs/hostnames de Shodan, infraestructura cloud, software
    con vulnerabilidades conocidas, leaks/buckets, menciones en
    plataformas (perfiles de codigo, apps moviles...), emails corporativos
    y personas encontradas en LinkedIn. `results` acepta una lista de
    Findings de un solo host, o un dict host->findings (--recursive)."""
    if isinstance(results, dict):
        by_host = results
    else:
        by_host = {domain: results}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, label: str, group: str, title: str | None = None) -> str:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "group": group, "title": title or label}
        return node_id

    def add_edge(a: str, b: str, label: str = "", dashed: bool = False):
        edges.append({"from": a, "to": b, "label": label, "dashed": dashed})

    root_id = add_node(f"domain:{domain}", domain, "domain")

    for host, host_findings in by_host.items():
        host_id = root_id
        if host != domain:
            host_id = add_node(f"host:{host}", host, "subdomain")
            add_edge(root_id, host_id, "subdominio", dashed=True)

        for f in host_findings:
            if f.category == "document":
                doc_id = add_node(f"document:{f.url}", _short_filename(f.url), "document",
                                   title=f"{f.url}\nAutor: {f.author or '-'} | Software: {f.software or '-'}")
                add_edge(host_id, doc_id, "documento")
            elif f.category == "sensitive":
                sens_id = add_node(f"sensitive:{f.url}", _short_filename(f.url), "sensitive",
                                    title=f"{f.url}\n{', '.join(f.secrets) if f.secrets else 'sin patron confirmado'}")
                add_edge(host_id, sens_id, "sensible")
            elif f.category == "subdomains":
                for sub in f.computers:
                    if sub in (host, domain):
                        continue
                    sub_id = add_node(f"host:{sub}", sub, "subdomain")
                    add_edge(host_id, sub_id, "subdominio", dashed=True)
            elif f.category == "shodan":
                m = SHODAN_HOST_IP_RE.search(f.url or f.title or "")
                if not m:
                    continue
                ip_id = add_node(f"ip:{m.group(1)}", m.group(1), "ip")
                add_edge(host_id, ip_id, "shodan")
                for hn in f.computers:
                    if hn in (host, domain):
                        continue
                    hn_id = add_node(f"host:{hn}", hn, "subdomain")
                    add_edge(ip_id, hn_id)
            elif f.category == "cloud":
                provider = f.dork_name.replace("Infraestructura cloud: ", "")
                cloud_id = add_node(f"cloud:{provider}", provider, "cloud")
                add_edge(host_id, cloud_id)
            elif f.category == "tech":
                tech_name = f.dork_name.replace("Tecnologia detectada: ", "")
                tech_id = add_node(f"tech:{host}:{tech_name}", f"{tech_name} {f.title}", "tech")
                add_edge(host_id, tech_id, "tecnologia")
            elif f.category == "vuln":
                software = f.dork_name.replace("Vulnerabilidades conocidas: ", "")
                vuln_id = add_node(f"vuln:{host}:{software}", software, "vuln",
                                    title=f"{f.title}\n\n{f.note or ''}")
                add_edge(host_id, vuln_id, "vulnerable")
            elif f.category in ("leak", "bucket") and (f.secrets or f.note):
                label = f.dork_name.replace("Posible leak: ", "")
                leak_id = add_node(f"leak:{f.url}", label, "leak",
                                    title=f"{f.url}\n{leak_detail(f)}")
                add_edge(host_id, leak_id, "leak")
            elif f.category == "platform":
                label = (f.dork_name.replace("Mencion en ", "")
                                     .replace("Cuenta de ", ""))
                plat_id = add_node(f"platform:{f.url}", label, "platform", title=f.url)
                add_edge(host_id, plat_id)
            elif f.category == "email":
                for email in f.emails:
                    email_id = add_node(f"email:{email}", email, "email")
                    add_edge(host_id, email_id)
            elif f.category == "people" and f.person_name:
                person_id = add_node(f"person:{f.person_name}", f.person_name, "person",
                                      title=f.role or "")
                add_edge(host_id, person_id)

    return {"nodes": list(nodes.values()), "edges": edges}


def _dot_from_graph_data(data: dict, rankdir: str = "LR", max_size: str = "18,18") -> str:
    """Renderiza un dict {nodes, edges} (ver build_network_graph_data) como
    texto DOT. Funcion pura reutilizada tanto por el diagrama completo como
    por los mini-esquemas por seccion del DOCX.

    `max_size` es el atributo `size` de Graphviz (pulgadas "ancho,alto"):
    limita el tamano absoluto del PNG renderizado para grafos con muchos
    nodos (si no, un grafo grande puede salir con una relacion de aspecto
    absurda, p.ej. muy alto y estrecho, que luego no cabe bien en una
    pagina del Word ni es comodo de abrir como imagen suelta). Graphviz
    solo encoge, nunca amplia un grafo que ya sea mas pequeno."""

    def dot_id(node_id: str) -> str:
        return "n" + str(abs(hash(node_id)) % (10**9))

    def esc(text: str) -> str:
        return text.replace('"', "'").replace("\n", "\\n")

    lines = [
        "digraph frib1trecon {",
        f'  rankdir={rankdir};',
        f'  size="{max_size}";',
        '  node [fontname="Helvetica", fontsize=14, fontcolor="#16213F", shape=none, '
        'imagescale=true, labelloc=b];',
        '  edge [fontname="Helvetica", fontsize=8, color="#A9B4D1", fontcolor="#6B7794", '
        'arrowsize=0.7];',
    ]
    for n in data["nodes"]:
        style = NODE_STYLES.get(n["group"], NODE_STYLES["subdomain"])
        icon = _node_icon_png(n["group"])
        if icon:
            lines.append(
                f'  {dot_id(n["id"])} [label="{esc(n["label"])}", image="{icon.as_posix()}", '
                f'width={style["size"]}, height={style["size"]}];'
            )
        else:
            # Sin Pillow/fuente disponible: circulo de color solido, sin icono,
            # nunca rompe el render por falta de una dependencia opcional.
            lines.append(
                f'  {dot_id(n["id"])} [label="{esc(n["label"])}", shape=circle, style=filled, '
                f'fillcolor="{style["color"]}", fontcolor=white];'
            )
    for e in data["edges"]:
        attrs = []
        if e["label"]:
            attrs.append(f'label="{esc(e["label"])}"')
        if e["dashed"]:
            attrs.append('style="dashed"')
        attr_str = f" [{', '.join(attrs)}]" if attrs else ""
        lines.append(f'  {dot_id(e["from"])} -> {dot_id(e["to"])}{attr_str};')
    lines.append("}")
    return "\n".join(lines)


def filter_graph_data(data: dict, groups: set[str]) -> dict:
    """Sub-grafo limitado a los nodos de `groups` + el host/dominio que los
    produjo (un salto, via las aristas que ya conectan host->nodo). Base de
    los mini-esquemas que van encima de cada tabla del DOCX: ensenar solo
    'de donde sale esto' sin arrastrar el resto del grafo completo."""
    target_ids = {n["id"] for n in data["nodes"] if n["group"] in groups}
    if not target_ids:
        return {"nodes": [], "edges": []}
    keep_ids = set(target_ids)
    kept_edges = []
    for e in data["edges"]:
        if e["to"] in target_ids or e["from"] in target_ids:
            kept_edges.append(e)
            keep_ids.add(e["from"])
            keep_ids.add(e["to"])
    nodes = [n for n in data["nodes"] if n["id"] in keep_ids]
    return {"nodes": nodes, "edges": kept_edges}


def render_graph_png(data: dict, rankdir: str = "LR", max_size: str = "18,18") -> Path | None:
    """Renderiza un dict {nodes, edges} a un PNG temporal (el llamador debe
    borrarlo cuando termine). None si no hay graphviz instalado, no hay
    nodos, o falla el render -> el llamador simplemente omite la imagen."""
    engine = _graphviz_engine(len(data["nodes"]))
    if not engine or not data["nodes"]:
        return None
    dot_text = _dot_from_graph_data(data, rankdir=rankdir, max_size=max_size)
    with tempfile.NamedTemporaryFile(suffix=".dot", delete=False, mode="w") as f:
        f.write(dot_text)
        dot_path = Path(f.name)
    png_path = dot_path.with_suffix(".png")
    try:
        subprocess.run(
            [engine, "-Tpng", str(dot_path), "-o", str(png_path)],
            capture_output=True, timeout=20, check=True,
        )
        return png_path
    except (subprocess.SubprocessError, OSError):
        return None
    finally:
        dot_path.unlink(missing_ok=True)


def export_network_diagram(results, domain: str, out_path: Path):
    """Escribe siempre el .dot (fuente, se puede abrir/editar sin graphviz);
    si `dot`/`fdp` esta instalado, ademas renderiza un .png junto al .dot
    (mismo nombre, otra extension). Best-effort: si graphviz no esta
    instalado o falla el render, el .dot sigue siendo valido y usable a
    mano abriendolo en cualquier editor o visor de Graphviz."""
    data = build_network_graph_data(results, domain)
    dot_text = _dot_from_graph_data(data)
    out_path.write_text(dot_text)
    engine = _graphviz_engine(len(data["nodes"]))
    if not engine:
        return
    png_path = out_path.with_suffix(".png")
    try:
        subprocess.run(
            [engine, "-Tpng", str(out_path), "-o", str(png_path)],
            capture_output=True, timeout=20, check=True,
        )
    except (subprocess.SubprocessError, OSError):
        pass


def export_network_graph_json(results, domain: str, out_path: Path):
    """Mismos nodos/aristas que el .dot, en JSON, para el grafo interactivo
    de la web (vis-network) y para quien quiera procesarlos a mano."""
    data = build_network_graph_data(results, domain)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _png_dimensions(path: Path) -> tuple[int, int]:
    """Ancho/alto en pixeles de un PNG, leyendo directamente su cabecera
    IHDR (sin depender de Pillow, que no es una dependencia del proyecto).
    Devuelve (800, 600) si el fichero no es un PNG valido o no se puede
    leer, para que el llamador siempre tenga un tamano razonable."""
    try:
        with open(path, "rb") as f:
            header = f.read(24)
        if header[:8] != b"\x89PNG\r\n\x1a\n" or len(header) < 24:
            return (800, 600)
        return struct.unpack(">II", header[16:24])
    except OSError:
        return (800, 600)


def _docx_picture_size(png_path: Path, max_width_in: float, max_height_in: float) -> tuple[float, float]:
    """Ancho/alto (en pulgadas) para incrustar `png_path` en el DOCX sin
    que se salga de una caja de `max_width_in` x `max_height_in`,
    preservando la relacion de aspecto real de la imagen. Sin esto,
    `add_picture(..., width=X)` escala la altura proporcionalmente SIN
    limite, y un diagrama con un aspecto muy alto/estrecho (tipico en
    grafos con muchos nodos) acababa ocupando varias paginas de alto por
    una sola imagen."""
    px_w, px_h = _png_dimensions(png_path)
    aspect = px_h / px_w if px_w else 1.0
    width_in = max_width_in
    height_in = width_in * aspect
    if height_in > max_height_in:
        height_in = max_height_in
        width_in = height_in / aspect
    return width_in, height_in
