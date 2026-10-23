"""
Informe TECNICO en LaTeX/PDF: mismo contenido que export_txt/export_docx
de report.py (todas las categorias, no solo el resumen ejecutivo de 6
bloques de cyber_health_report.py), con el mismo sistema visual que
latex_report.py (banners navy, paleta compartida, logos en cabecera) via
latex_common.py. Genera `informe.tex`/`.pdf`/`.md` junto al resto de
exports en report_export.py.

Mismo criterio de seguridad que latex_report.py: todo el texto que viene
de un Finding (scrapeado de la web) pasa por `tex_escape()`, nunca se
vuelca sin escapar en un entorno verbatim.
"""
import re
import socket
from datetime import datetime
from pathlib import Path

from .cyber_health_report import DEFAULT_LOGO, _cve_rows, _find_logo
from .latex_common import compile_pdf as _compile_pdf
from .latex_common import logo_path as _logo_path
from .latex_common import md_escape as _md
from .latex_common import shared_preamble, tex_escape as _tex, tex_url as _texurl
from .report import SENIORITY_LABELS, compute_risk_score, confianza_empresa, leak_detail, org_chart_rows


def build_latex_technical_report(findings, domain: str, out_dir, results: dict | None = None,
                                  logos_dir=None, compile_pdf: bool = True) -> dict:
    """Genera `informe.tex` (y `.pdf`/`.md`) en `out_dir`. Mismos
    parametros/convencion de logos que build_latex_report/
    build_cyber_health_docx."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cover_image = _find_logo(logos_dir, "portada") or DEFAULT_LOGO
    client_logo = _find_logo(logos_dir, "cliente")
    pentester_logo = _find_logo(logos_dir, "pentester") or DEFAULT_LOGO

    risk = compute_risk_score(findings)
    risk_score_txt = f"{risk['score']:.2f}".rstrip("0").rstrip(".")

    parts: list[str] = []
    md: list[str] = []

    def add(s=""):
        parts.append(s)

    def addmd(s=""):
        md.append(s)

    def heading(text, level=1):
        if level == 1:
            add(r"\clearpage")
            add(f"\\begin{{seccionbanner}}{_tex(text)}\\end{{seccionbanner}}")
            add(r"\vspace{2mm}")
            add(r"\refstepcounter{section}")
            add(f"\\addcontentsline{{toc}}{{section}}{{{_tex(text)}}}")
        else:
            cmd = {2: "subsection", 3: "subsubsection"}[level]
            add(f"\\{cmd}{{{_tex(text)}}}")
        addmd(("#" * level) + " " + text)
        addmd("")

    def para(text, color=None, italic=False, bold=False, small=False):
        t = _tex(text)
        if bold:
            t = f"\\textbf{{{t}}}"
        if italic:
            t = f"\\textit{{{t}}}"
        if color:
            t = f"\\textcolor{{{color}}}{{{t}}}"
        if small:
            t = f"\\small {t}"
        add(t)
        add("")
        md_t = text
        if bold:
            md_t = f"**{md_t}**"
        if italic:
            md_t = f"*{md_t}*"
        addmd(md_t)
        addmd("")

    def no_data(text="Sin datos recopilados en este escaneo para esta sección."):
        para(text, italic=True, color="mutedgray")

    def bullet_list(items):
        if not items:
            return
        add("\\begin{itemize}")
        for item in items:
            if isinstance(item, tuple):
                label, text = item
                add(f"  \\item \\textbf{{{_tex(label)}}} {_tex(text)}")
                addmd(f"- **{label}** {text}")
            else:
                add(f"  \\item {_tex(item)}")
                addmd(f"- {item}")
        add("\\end{itemize}")
        add("")
        addmd("")

    def table(headers, rows, col_widths=None, red_cols=(), url_cols=()):
        if not rows:
            return
        ncols = len(headers)
        colspec = "".join(f"p{{{w}cm}}" for w in col_widths) if col_widths else "l" * ncols
        add(f"\\begin{{longtable}}{{{colspec}}}")
        add("\\hline")
        add(" & ".join(f"\\textbf{{{_tex(h)}}}" for h in headers) + " \\\\")
        add("\\hline")
        add("\\endhead")
        addmd("| " + " | ".join(headers) + " |")
        addmd("|" + "|".join("---" for _ in headers) + "|")
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                txt = _texurl(cell) if i in url_cols else _tex(cell)
                if i in red_cols:
                    txt = f"\\textcolor{{alertred}}{{\\textbf{{{txt}}}}}"
                cells.append(txt)
            add(" & ".join(cells) + " \\\\")
            add("\\hline")
            addmd("| " + " | ".join(_md(c) for c in row) + " |")
        add("\\end{longtable}")
        add("")
        addmd("")

    # ========================================================== preambulo + portada
    parts.extend(shared_preamble(domain, pentester_logo, client_logo, "Informe Técnico"))
    add(r"\begin{titlepage}")
    add(r"\centering")
    add(f"\\includegraphics[width=0.45\\textwidth]{{{_logo_path(cover_image)}}}\\par\\vspace{{1cm}}")
    add(r"{\scshape\LARGE \textbf{Informe Técnico Detallado}\par\vspace{0.4cm}}")
    add(f"{{\\Huge\\textcolor{{navyblue}}{{\\textbf{{frib1trecon}}}}}}\\par\\vspace{{0.2cm}}")
    add(f"{{\\Large\\textbf{{{_tex(domain)}}}}}")
    add(r"\vfill")
    add(r"\begin{tcolorbox}[colback=red!5!white,colframe=red!75!black]")
    add(r"\centering")
    add("Este documento es confidencial y contiene información sensible sobre la superficie de "
        "exposición pública de la organización auditada.\\\\No debe imprimirse ni compartirse con "
        "terceros ajenos a la organización.")
    add(r"\end{tcolorbox}")
    add(r"\vfill")
    add(f"{{\\large Nivel de riesgo: \\textbf{{{risk_score_txt}\\% — {_tex(risk['level_label'].upper())}}}}}\\par")
    add(r"\vspace{0.3cm}")
    add(f"{{\\large {datetime.now().strftime('%d-%m-%Y')}}}\\par")
    add(r"\vfill")
    add(r"\end{titlepage}")
    add("")
    add(r"\clearpage")
    add(r"\tableofcontents")
    add(r"\clearpage")
    add("")

    addmd(f"# Informe Técnico — {domain}")
    addmd("")
    addmd(f"Nivel de riesgo: **{risk_score_txt}% — {risk['level_label'].upper()}**")
    addmd("")
    addmd("> Documento confidencial: no debe compartirse con terceros ajenos a la organización.")
    addmd("")

    # ========================================================== resumen
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
    external = [f for f in findings if f.category in
                ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    vulns = [f for f in findings if f.category == "vuln"]
    dns_checks = [f for f in findings if f.category == "dns"]
    tls_checks = [f for f in findings if f.category == "tls"]
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]
    cloud = [f for f in findings if f.category == "cloud"]
    tech = [f for f in findings if f.category == "tech"]

    heading("Resumen")
    para(f"Nivel de riesgo: {risk_score_txt}% — {risk['level_label'].upper()}", bold=True, color="alertred")
    bullet_list([
        f"Documentos con metadatos encontrados: {len(docs)}",
        f"Ficheros sensibles encontrados: {len(sensitive)}",
        f"Menciones en plataformas externas: {len(platform)}",
        f"Páginas con emails públicos: {len(email_osint)}",
        f"Personas encontradas en LinkedIn: {len(people)}",
        f"Hallazgos en fuentes externas: {len(external)}",
        f"Comprobaciones DNS/WHOIS realizadas: {len(dns_checks)}",
        f"Comprobaciones TLS/cabeceras realizadas: {len(tls_checks)}",
        f"Puertos abiertos / servicios detectados: {len(ports_checks)}",
        f"Software con CVEs/exploits conocidos: {len(vulns)}",
        f"Posibles leaks / credenciales: {len(leaks)}",
    ])
    agregados = [
        f"Usuarios/autores encontrados: {', '.join(authors) or '-'}",
        f"Editores (last modified by): {', '.join(editors) or '-'}",
        f"Software/aplicaciones: {', '.join(software) or '-'}",
        f"Emails detectados: {', '.join(emails) or '-'}",
        f"Rutas internas detectadas: {', '.join(paths) or '-'}",
        f"Equipos/servidores detectados: {', '.join(computers) or '-'}",
    ]
    if cloud:
        agregados.append(f"Proveedores cloud detectados: {', '.join(c.dork_name.split(': ')[-1] for c in cloud)}")
    if tech:
        tech_names = [f"{t.dork_name.replace('Tecnologia detectada: ', '')} {t.title}" for t in tech]
        agregados.append(f"Tecnologías web detectadas: {', '.join(tech_names)}")
    heading("Datos agregados", 2)
    bullet_list(agregados)
    addmd("")

    # ---------- Discovery (si hay varios hosts) ----------
    hosts = list(results.keys()) if results else [domain]
    if len(hosts) > 1:
        heading("Discovery — Subdominios e IPs")
        disc_rows = []
        for h in hosts:
            try:
                ip = socket.gethostbyname(h)
            except OSError:
                ip = "no resuelve"
            own = "Sí" if h == domain or h.endswith("." + domain) else "Externo"
            disc_rows.append([h, ip, own])
        table(["Host", "IP resuelta", "Propio del dominio"], disc_rows, col_widths=[6.0, 4.0, 4.0])

    # ---------- DNS y WHOIS ----------
    if dns_checks:
        heading("DNS y WHOIS")
        for f in dns_checks:
            heading(f.dork_name, 2)
            para(f.title or "-")
            for ln in (f.note or "").splitlines():
                if ln.strip():
                    bullet_list([ln.strip()])

    # ---------- TLS y cabeceras ----------
    if tls_checks:
        heading("TLS y cabeceras de seguridad")
        for f in tls_checks:
            heading(f.dork_name, 2)
            para(f.title or "-")
            for ln in (f.note or "").splitlines():
                if ln.strip():
                    bullet_list([ln.strip()])

    # ---------- Typosquatting ----------
    if typosquat_checks:
        heading("Typosquatting y domain squatting")
        for f in typosquat_checks:
            heading(f.dork_name, 2)
            para(f.title or "-")
            for ln in (f.note or "").splitlines():
                if ln.strip():
                    bullet_list([ln.strip()])

    # ---------- Puertos y servicios ----------
    if ports_checks:
        heading("Puertos y servicios (nmap, escaneo activo)")
        rows = [[f.dork_name, f.title or "-"] for f in ports_checks]
        table(["Puerto/servicio", "Producto/versión"], rows, col_widths=[7.0, 7.0])

    # ---------- Documentos ----------
    if docs:
        heading("Documentos con metadatos")
        rows = []
        for f in docs:
            rows.append([f.filetype or "-", f.author or "-", f.last_modified_by or "-",
                         f.software or "-", f.gps or "-", f.url or "-"])
        table(["Tipo", "Autor", "Últ. modif. por", "Software", "GPS", "URL"], rows,
              col_widths=[1.5, 2.5, 2.5, 3.0, 1.5, 3.0], url_cols=(5,))

    # ---------- Ficheros sensibles ----------
    if sensitive:
        heading("Ficheros sensibles")
        rows = [[f.filetype or "-", "SÍ" if f.secrets else "NO", ", ".join(f.secrets) or "-", f.url or "-"]
                for f in sensitive]
        table(["Tipo", "Patrones detectados", "Detalle", "URL"], rows,
              col_widths=[1.5, 2.5, 4.5, 5.5], red_cols=(1,), url_cols=(3,))

    # ---------- Plataformas externas / leaks ----------
    if platform or leaks:
        heading("Plataformas externas / posibles leaks (OSINT)")
        rows = []
        for f in findings:
            if f.category in ("platform", "leak"):
                detalle = leak_detail(f)
                rows.append(["LEAK" if f.category == "leak" else "-", f.dork_name,
                             detalle or "-", f.url or "-"])
        table(["Tipo", "Fuente", "Detalle", "URL"], rows, col_widths=[1.5, 3.5, 3.5, 5.5],
              red_cols=(0,), url_cols=(3,))

    # ---------- Emails publicos ----------
    if email_osint:
        heading("Emails de fuentes públicas")
        rows = [[", ".join(f.emails), f.dork_name, f.url or "-"] for f in email_osint]
        table(["Emails", "Fuente", "URL"], rows, col_widths=[4.0, 4.5, 5.5], url_cols=(2,))

    # ---------- Organigrama ----------
    if people:
        heading("Organigrama aproximado (LinkedIn)")
        para("Agrupado por nivel de seniority detectado en el puesto; NO son relaciones de "
             "jefatura reales, LinkedIn no las expone en búsqueda pública.", italic=True, color="mutedgray", small=True)
        rows = [[SENIORITY_LABELS.get(f.seniority, f.seniority or "-"), f.person_name or "-",
                 f.role or "-", confianza_empresa(f), f.url or "-"] for f in people]
        table(["Nivel", "Nombre", "Rol", "Confianza", "URL"], rows,
              col_widths=[2.5, 3.0, 3.5, 2.0, 3.0], url_cols=(4,))

    # ---------- Fuentes externas y cloud ----------
    if external:
        heading("Fuentes externas y cloud")
        para("Shodan / VirusTotal / AbuseIPDB / GrayHatWarfare / IntelX / crt.sh / Wayback / "
             "AWS-Azure-GCP...", italic=True, color="mutedgray", small=True)
        rows = [[f.dork_name, f.title or "-", f.note or "-", f.url or "-"] for f in external]
        table(["Fuente", "Resultado", "Detalle", "URL"], rows, col_widths=[3.0, 3.0, 4.0, 4.0], url_cols=(3,))

    # ---------- Tecnologias ----------
    if tech:
        heading("Tecnologías web detectadas")
        rows = [[f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-"] for f in tech]
        table(["Tecnología/plugin", "Versión"], rows, col_widths=[7.0, 7.0])

    # ---------- Vulnerabilidades ----------
    if vulns:
        heading("Vulnerabilidades conocidas (NVD / ExploitDB / Sploitus)")
        rows = _cve_rows(vulns, domain)
        if rows:
            table(["Identificador", "Producto", "Host", "Estado"], rows, col_widths=[3.0, 3.5, 3.5, 4.0])
        eol = [f for f in vulns if f.dork_name.startswith("Fin de soporte")]
        if eol:
            heading("Software sin soporte (EOL)", 2)
            table(["Producto", "Detalle"],
                  [[f.dork_name.replace("Fin de soporte (EOL): ", ""), f.note or "-"] for f in eol],
                  col_widths=[4.0, 10.0])

    # ---------- Diagrama de red ----------
    # Mismo PNG que ya incrusta informe.docx (export_docx/export_master_docx
    # ya lo generan en out_dir antes de llegar aqui, ver report_export.py):
    # se reutiliza tal cual para que ambos documentos muestren exactamente
    # el mismo grafico, no una regeneracion aparte que podria desincronizarse.
    network_png = out_dir / "red.png"
    if network_png.exists():
        heading("Diagrama de red")
        add(f"\\includegraphics[width=\\linewidth, height=0.85\\textheight, "
            f"keepaspectratio]{{{_logo_path(network_png)}}}")
        add("")
        addmd("## Diagrama de red")
        addmd("")
        addmd(f"![Diagrama de red]({network_png.name})")
        addmd("")

    add(r"\end{document}")

    tex_path = out_dir / "informe.tex"
    tex_path.write_text("\n".join(parts), encoding="utf-8")
    md_path = out_dir / "informe.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    pdf_ok = _compile_pdf(tex_path) if compile_pdf else False
    return {"tex_path": tex_path, "md_path": md_path, "pdf_ok": pdf_ok}
