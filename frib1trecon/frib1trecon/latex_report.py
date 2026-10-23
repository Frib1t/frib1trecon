"""
Informe final en LaTeX, mismo patron visual que una plantilla de referencia
de pentest manual (dos logos en cabecera via fancyhdr, portada con caja de
confidencialidad, indice, cajas de "definicion" para terminos tecnicos,
paleta de color propia) pero relleno con los Findings de un analisis de
reconocimiento automatico: NO hay "Escalada de privilegios" ni
"Persistencia" porque frib1trecon no explota nada, son fases de un pentest
manual que no existen en un analisis pasivo/OSINT. El contenido reutiliza
EXACTAMENTE la misma logica de filtrado/calculo que build_cyber_health_docx
(mismas 6 secciones Compromised/Controls/Exposure/Tech/Identity/Brand,
mismos PHRASES, mismo compute_health) para que ambos formatos — DOCX y
LaTeX — digan siempre lo mismo sobre el mismo escaneo.

Genera el .tex y, si `pdflatex` esta instalado, compila tambien el PDF (dos
pasadas, para que el indice salga bien). Si no esta instalado, se deja solo
el .tex para que el usuario lo compile donde quiera — mismo criterio de
"no instalar nada pesado por la fuerza" ya usado en el resto del proyecto
(nmap/exiftool/trufflehog/whatweb son todos opcionales, se detectan solos).

Decision de seguridad: los Findings vienen en parte de contenido scrapeado
de la web (titulos, notas, URLs), que es contenido NO confiable. Por eso
NUNCA se vuelca texto de un Finding dentro de un entorno LaTeX verbatim
(lstlisting/verbatim) sin escapar: un entorno verbatim solo es seguro si el
contenido no puede contener su propio marcador de cierre, y aqui no hay
forma de garantizarlo. Toda evidencia textual pasa por `_tex()` (escapa
\\{}$&#_%^~) y se muestra como texto normal/monoespaciado, nunca dentro de
\\begin{lstlisting}/\\begin{verbatim}.
"""
import re
from pathlib import Path

from .cyber_health_report import (
    DEFAULT_LOGO, PHRASES, _action_items, _cve_rows, _find_logo, _fmt, _host, _num, _port_number,
    compute_health,
)
from .latex_common import compile_pdf as _compile_pdf
from .latex_common import logo_path as _logo_path
from .latex_common import md_escape as _md
from .latex_common import render_cats_bar_chart, render_global_bar_chart
from .latex_common import shared_preamble, tex_escape as _tex, tex_url as _texurl
from .ports_services import criticidad
from .report import _TLS_CERT_ISSUE_MARKERS, leak_detail


def build_latex_report(findings, domain: str, out_dir, results: dict | None = None,
                        empresa: str | None = None, logos_dir=None, compile_pdf: bool = True) -> dict:
    """Genera `cyber_health_check.tex` (y `.pdf` si hay pdflatex) en
    `out_dir`. `results`/`empresa`/`logos_dir` tienen el mismo significado
    que en build_cyber_health_docx (ver ahi la convencion de nombres fijos
    de logos: portada/cliente/pentester)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cover_image = _find_logo(logos_dir, "portada") or DEFAULT_LOGO
    client_logo = _find_logo(logos_dir, "cliente")
    pentester_logo = _find_logo(logos_dir, "pentester") or DEFAULT_LOGO

    health = compute_health(findings, domain)
    total_txt = _fmt(health["total"])

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
            # el banner no es un \section real (es un tcolorbox), asi que no
            # incrementa el contador de seccion por si solo: sin
            # \refstepcounter, las \subsection reales que vengan despues
            # saldrian numeradas "0.1" en vez de "1.1", "2.1"... Y sin
            # entrada de TOC el indice se quedaria sin listar la seccion.
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

    def definicion(text):
        add("\\begin{definicion}")
        add(_tex(text))
        add("\\end{definicion}")
        add("")
        addmd(f"> **Definición:** {text}")
        addmd("")

    def bullet_list(items):
        """`items`: strings sueltas, o tuplas (label, texto) para negrita + texto."""
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
        """longtable (no tabular): algunas de estas tablas pueden tener
        cientos de filas (typosquat, CVEs...) y longtable las reparte sola
        entre paginas repitiendo la cabecera, sin que haya que trocearlas a
        mano."""
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

    def global_chart():
        """Grafico de barra unica con el riesgo global (equivalente en
        imagen al [[CHART risk_global]] nativo del docx, mismos colores)."""
        chart_path = out_dir / "chart_risk_global.png"
        render_global_bar_chart(health["total"], chart_path)
        add(f"\\includegraphics[width=\\linewidth]{{{_logo_path(chart_path)}}}")
        add(r"\vspace{2mm}")
        add("")

    def cats_chart():
        """Grafico con las 7 categorias de riesgo completas (equivalente
        al [[CHART risk_cats]] nativo del docx)."""
        cats = [{"key": k, "label": c["label"], "riskPct": 100.0 if c["points"] else 0.0}
                for k, c in health["categories"].items()]
        chart_path = out_dir / "chart_risk_cats.png"
        render_cats_bar_chart(cats, chart_path)
        add(f"\\includegraphics[width=\\linewidth]{{{_logo_path(chart_path)}}}")
        add(r"\vspace{2mm}")
        add("")

    def section_badge(keys):
        """Tira de indicador bajo el banner de seccion: peso combinado de
        riesgo real (suma de pesos de las categorias que cubre esta
        seccion) + estado OK/A REVISAR, igual que section_badge del docx."""
        weight = sum(health["categories"][k]["weight"] for k in keys)
        triggered = any(health["categories"][k]["points"] for k in keys)
        estado_color = "alertred" if triggered else "okgreen"
        estado_bg = "alertred!10" if triggered else "okgreen!10"
        estado_txt = "A REVISAR" if triggered else "OK"
        add(r"\noindent\renewcommand{\arraystretch}{1.8}")
        add(r"\begin{tabular}{@{}p{3cm}p{13cm}@{}}")
        add(f"\\cellcolor{{navyblue}}\\centering\\textcolor{{white}}{{\\textbf{{\\Large {_fmt(weight)}\\%}}}}"
            f"\\\\{{\\color{{white}}\\tiny PESO DE RIESGO}}"
            f" & \\cellcolor{{{estado_bg}}}\\centering\\textcolor{{{estado_color}}}{{\\textbf{{{estado_txt}}}}} \\\\")
        add(r"\end{tabular}")
        add(r"\renewcommand{\arraystretch}{1}")
        add(r"\vspace{3mm}")
        add("")

    def section_chart(keys):
        """Grafico con el subconjunto de categorias que cubre esta
        seccion (equivalente al [[CHART risk_section_...]] nativo del
        docx para la misma seccion)."""
        cats = [{"key": k, "label": health["categories"][k]["label"],
                 "riskPct": 100.0 if health["categories"][k]["points"] else 0.0} for k in keys]
        chart_path = out_dir / f"chart_section_{'_'.join(keys)}.png"
        render_cats_bar_chart(cats, chart_path)
        add(f"\\includegraphics[width=\\linewidth]{{{_logo_path(chart_path)}}}")
        add(r"\vspace{2mm}")
        add("")

    def action_box(title, items, color_name):
        """Caja de accion (equivalente al action_box del docx): titulo
        coloreado + lista de hallazgos agrupados por urgencia."""
        if not items:
            return
        add(f"\\begin{{tcolorbox}}[enhanced, breakable, colback={color_name}!8, "
            f"colframe={color_name}!70!black, arc=0mm, boxrule=0.8pt, "
            f"colbacktitle={color_name}, coltitle=white, fonttitle=\\bfseries, "
            f"title={{{_tex(title.upper())}}}]")
        add(r"\begin{itemize}")
        for item in items:
            add(f"  \\item \\small {_tex(item)}")
        add(r"\end{itemize}")
        add(r"\end{tcolorbox}")
        add(r"\vspace{2mm}")
        add("")

    # ========================================================== preambulo
    # Sin babel[spanish] a proposito: no da ningun beneficio funcional aqui
    # (el \contentsname se redefine a mano, las fechas se generan en Python,
    # no en LaTeX) y en algunas instalaciones de texlive incompletas/con
    # paquetes de idioma desincronizados falla en seco con "Unknown option
    # 'spanish'" incluso en un documento minimo. Quitarlo hace el informe
    # compilable en cualquier instalacion de texlive, no solo en las que
    # tengan el locale espanol de babel bien instalado.
    parts.extend(shared_preamble(domain, pentester_logo, client_logo, "Cyber Health Check"))

    # ========================================================== portada
    add(r"\begin{titlepage}")
    add(r"\centering")
    add(f"\\includegraphics[width=0.45\\textwidth]{{{_logo_path(cover_image)}}}\\par\\vspace{{1cm}}")
    if empresa:
        add(f"{{\\Large\\textbf{{\\textcolor{{okgreen}}{{{_tex(empresa.upper())}}}}}}}\\par\\vspace{{0.3cm}}")
    add(r"{\scshape\LARGE \textbf{Informe Técnico}\par\vspace{0.4cm}}")
    add(f"{{\\Huge\\textcolor{{navyblue}}{{\\textbf{{Cyber Health Check}}}}}}\\par\\vspace{{0.2cm}}")
    add(f"{{\\Large\\textbf{{{_tex(domain)}}}}}")
    add(r"\vfill")
    add(r"\begin{tcolorbox}[colback=red!5!white,colframe=red!75!black]")
    add(r"\centering")
    add("Este documento es confidencial y contiene información sensible sobre la superficie de "
        "exposición pública de la organización auditada.\\\\No debe imprimirse ni compartirse con "
        "terceros ajenos a la organización.")
    add(r"\end{tcolorbox}")
    add(r"\vfill")
    add(f"{{\\large Nivel de riesgo: \\textbf{{{total_txt}\\% — {_tex(health['level'])}}}}}\\par")
    add(r"\vspace{0.3cm}")
    from datetime import datetime
    add(f"{{\\large {datetime.now().strftime('%d-%m-%Y')}}}\\par")
    add(r"\vfill")
    add(r"\end{titlepage}")
    add("")
    add(r"\clearpage")
    add(r"\tableofcontents")
    add(r"\clearpage")
    add("")

    addmd(f"# Cyber Health Check — {domain}")
    addmd("")
    if empresa:
        addmd(f"**{empresa.upper()}**")
        addmd("")
    addmd(f"Nivel de riesgo: **{total_txt}% — {health['level']}**")
    addmd("")
    addmd("> Documento confidencial: contiene información sensible sobre la superficie de "
          "exposición pública de la organización auditada. No debe compartirse con terceros "
          "ajenos a la organización.")
    addmd("")

    # ========================================================== antecedentes / objetivos
    ports_ran = any(f.category == "ports" for f in findings)
    heading("Antecedentes")
    para(f"El presente documento recoge los resultados obtenidos durante el analisis de "
         f"reconocimiento aplicado sobre el dominio {domain}, enumerando la superficie de "
         f"exposicion publica identificada, los hallazgos de riesgo asociados y las "
         f"recomendaciones de remediacion correspondientes.")

    heading("Objetivos")
    para(PHRASES["methodology"])
    para(PHRASES["methodology_intro"])
    bullet_list(PHRASES["methodology_items"])
    para(PHRASES["methodology_note"], italic=True, color="mutedgray", small=True)

    heading("Alcance", 2)
    alcance_items = [
        f"Identificar la superficie de exposición pública del dominio {domain} y sus subdominios.",
        "Detectar leaks, credenciales y ficheros sensibles filtrados públicamente.",
        "Evaluar la postura DNS, TLS y cabeceras de seguridad HTTP.",
        "Identificar tecnologías, versiones, CVEs conocidos y software sin soporte (EOL).",
        "Detectar typosquatting, domain squatting y riesgos de reputación.",
    ]
    if ports_ran:
        alcance_items.append("Enumerar puertos y servicios expuestos mediante escaneo activo (nmap).")
    bullet_list(alcance_items)

    heading("Impedimentos y limitaciones", 2)
    impedimentos = [
        "No se ha realizado ninguna prueba de explotación, denegación de servicio ni "
        "modificación de ningún sistema del objetivo.",
    ]
    if ports_ran:
        impedimentos.append("El escaneo de puertos (nmap) implica tráfico activo controlado contra "
                             "el objetivo; el resto del análisis es 100% pasivo (fuentes públicas).")
    else:
        impedimentos.append("Todo el análisis se ha realizado de forma 100% pasiva, sin enviar "
                             "tráfico directo al objetivo más allá de peticiones HTTP/DNS normales.")
    bullet_list(impedimentos)
    add("")

    # ========================================================== resumen ejecutivo
    heading("Resumen ejecutivo")
    add(f"\\textcolor{{alertred}}{{Nivel de riesgo global: "
        f"\\textbf{{{_tex(f'{total_txt}% — ' + health['level'])}}}}}")
    add("")
    addmd(f"**Nivel de riesgo global: {total_txt}% — {health['level']}**")
    addmd("")
    global_chart()
    heading("Evaluación por categoría", 2)
    cats_chart()
    cat_rows = []
    for key, c in health["categories"].items():
        estado = "A REVISAR" if c["points"] else "OK"
        cat_rows.append([c["label"], f"{_fmt(c['weight'])}%", estado, f"{_fmt(c['points'])} pts"])
    table(["Categoría de riesgo", "Peso", "Estado", "Riesgo"], cat_rows,
          col_widths=[7.0, 2.0, 2.5, 2.0], red_cols=(2,))

    heading("Plan de acción inmediata", 2)
    sanear, revisar = _action_items(findings, domain)
    if sanear or revisar:
        para("Hallazgos agrupados por urgencia de remediación, a partir de los mismos datos "
             "detallados en el resto del informe.", italic=True, color="mutedgray", small=True)
        action_box("Sanear de inmediato", sanear, "alertred")
        action_box("Revisar", revisar, "navyblue")
    else:
        no_data("No se identificaron hallazgos que requieran acción inmediata en este escaneo.")

    heading("Indicadores clave", 2)
    ips = {m for f in findings for m in re.findall(r"tcp://(\d+\.\d+\.\d+\.\d+)", f.url or "")}
    ports_n = sum(1 for f in findings if f.category == "ports" and _port_number(f))
    hosts_n = len(results) if results else 1
    cves_n = sum(len(re.findall(r"CVE-\d{4}-\d+", f.note or "")) for f in findings if f.category == "vuln")
    eol_n = sum(1 for f in findings if f.category == "vuln" and f.dork_name.startswith("Fin de soporte"))
    squat_n = sum(len([ln for ln in (f.note or "").splitlines() if "->" in ln])
                  for f in findings if f.category == "typosquat")
    comp_ips = sum(1 for f in findings if f.category == "reputation" and f.title and
                   re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title) and
                   (_num(f.note, r"confianza de abuso=(\d+)%") >= 50 or _num(f.note, r"malicioso=(\d+)") > 0))
    table(["Indicador", "Valor"], [
        ["Hosts / Subdominios", str(hosts_n)],
        ["IPs propias analizadas", str(len(ips))],
        ["Puertos abiertos", str(ports_n)],
        ["IPs comprometidas", str(comp_ips)],
        ["CVEs asociados", str(cves_n)],
        ["Tecnologías obsoletas (EOL)", str(eol_n)],
        ["Dominios de squatting / typosquatting activos", str(squat_n)],
    ], col_widths=[11.0, 3.0])
    para(f"Ante la evaluación global de {health['level'].lower()} ({total_txt}%) observada en la "
         f"infraestructura externa de {domain}, se recomienda articular el plan de remediación "
         f"prioritario en torno a las siguientes líneas estratégicas:", italic=True, color="mutedgray")
    bullet_list(PHRASES["strategy"])
    add("")

    # ========================================================== discovery
    heading("Discovery — Subdominios e IPs")
    import socket
    hosts = list(results.keys()) if results else [domain]
    disc_rows = []
    for h in hosts:
        try:
            ip = socket.gethostbyname(h)
        except OSError:
            ip = "no resuelve"
        own = "Sí" if h == domain or h.endswith("." + domain) else "Externo"
        disc_rows.append([h, ip, own])
    para("Hosts analizados. La columna \"Propio del dominio\" indica si el host pertenece al "
         "dominio analizado o a un servicio de terceros.", color="mutedgray", small=True)
    table(["Host", "IP resuelta", "Propio del dominio"], disc_rows, col_widths=[7.0, 4.5, 4.5])
    add("")

    # ========================================================== 1. Compromised Systems
    heading("1. Compromised Systems")
    section_badge(["reputation", "squatting"])
    section_chart(["reputation", "squatting"])
    heading("Estado por IP", 2)
    rep_ip = [f for f in findings if f.category == "reputation" and f.title and
              re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title)]
    if rep_ip:
        rows = []
        for f in rep_ip:
            flagged = _num(f.note, r"confianza de abuso=(\d+)%") >= 50 or _num(f.note, r"malicioso=(\d+)") > 0
            rows.append([f.title, _host(f, domain), "REVISAR" if flagged else "OK",
                         "A REVISAR" if flagged else "OK",
                         str(_num(f.note, r"confianza de abuso=(\d+)%"))])
        table(["IP", "Dominio", "Blacklist", "Estado", "Índice abuso"], rows,
              col_widths=[3.0, 4.5, 2.5, 2.5, 2.5])
    else:
        no_data("No se consultó reputación de IP (requiere api key de VirusTotal o AbuseIPDB).")
    para(PHRASES["compromised"])
    para(PHRASES["compromised_blacklist"])
    heading("Recomendaciones", 2)
    para(PHRASES["compromised_recs"])
    add("")

    # ========================================================== 2. Security Controls
    heading("2. Security Controls")
    section_badge(["dns_email", "tls_web"])
    section_chart(["dns_email", "tls_web"])
    heading("Email Security", 2)
    definicion(PHRASES["email"])
    dns_rows = [f for f in findings if f.category == "dns" and f.dork_name.startswith("Autenticacion de correo")]
    if dns_rows:
        note = dns_rows[0].note or ""
        spf = "Publicado" if "SPF: presente" in note else "Ausente"
        dmarc = "Publicado" if "DMARC: presente" in note else "Ausente"
        dkim = "Detectado" if "Selectores DKIM detectados" in note else "No detectado"
        bullet_list([f"SPF: {spf}", f"DMARC: {dmarc}", f"DKIM: {dkim}"])
    else:
        no_data()

    heading("DNS Security", 2)
    definicion(PHRASES["dns"])
    axfr = [f for f in findings if "AXFR" in (f.dork_name or "")]
    if axfr:
        rows = []
        for f in axfr:
            if f.category == "leak":
                for ns in f.computers:
                    rows.append([ns, "PERMITIDO (crítico)"])
            else:
                for ns in re.findall(r"Testeados: (.+)", f.note or ""):
                    for n in [x.strip() for x in ns.split(",") if x.strip()]:
                        rows.append([n, "Denegado"])
        table(["Nameserver", "Zone Transfer (AXFR)"], rows, col_widths=[8.0, 6.0], red_cols=(1,))
    dnssec = [f for f in findings if f.dork_name == "DNSSEC"]
    if dnssec:
        para(f"DNSSEC: {dnssec[0].title}")

    heading("TLS Security", 2)
    definicion(PHRASES["tls"])
    certs = [f for f in findings if f.dork_name == "Certificado TLS"]
    for f in certs:
        if f.title == "No se pudo conectar por HTTPS":
            bullet_list([("No se pudo establecer conexión HTTPS con el host:", _host(f, domain))])
            continue
        lines = [ln for ln in (f.note or "").splitlines() if ln.strip()]
        keep = [ln for ln in lines if ln.startswith(("Emisor:", "CN:", "Caducidad:", "Cifrado:", "SAN:"))]
        bullet_list(keep)
        issues = [ln for ln in lines if any(m in ln for m in _TLS_CERT_ISSUE_MARKERS)]
        if issues:
            bullet_list([("Hallazgo:", ln) for ln in issues])
        else:
            bullet_list(["Sin hallazgos en la configuración TLS."])
    if not certs:
        no_data()

    heading("Web Security — HTTP Headers", 2)
    definicion(PHRASES["web"])
    hdr = [f for f in findings if f.dork_name == "Cabeceras de seguridad HTTP"]
    if hdr:
        rows = []
        for f in hdr:
            server = re.search(r"Server: (.+)", f.note or "")
            missing = re.search(r"Ausentes: (.+)", f.note or "")
            ausentes = re.sub(r"\s*\((alta|media|baja)\)", "", missing.group(1)).strip() if missing else "ninguna"
            rows.append([f.url or _host(f, domain), server.group(1) if server else "-",
                         ausentes if ausentes != "-" else "ninguna"])
        table(["URL", "Server", "Cabeceras ausentes"], rows, col_widths=[5.5, 3.5, 5.0], url_cols=(0,))
    else:
        no_data()
    heading("Recomendaciones", 2)
    para(PHRASES["controls_recs"])
    add("")

    # ========================================================== 3. Exposure Management
    heading("3. Exposure Management")
    section_badge(["tls_web"])
    section_chart(["tls_web"])
    heading("Puertos y servicios (por IP)", 2)
    definicion(PHRASES["exposure"])
    ports = [f for f in findings if f.category == "ports" and _port_number(f)]
    if ports:
        by_host: dict[str, list] = {}
        for f in ports:
            by_host.setdefault(_host(f, domain), []).append(f)
        for h, fs in by_host.items():
            ip_m = re.search(r"tcp://(\d+\.\d+\.\d+\.\d+)", fs[0].url or "")
            heading(f"{ip_m.group(1) if ip_m else '—'}   {h}", 3)
            rows = []
            for f in sorted(fs, key=_port_number):
                m = re.match(r"Puerto \d+/\w+ \((.*)\)", f.dork_name)
                svc = m.group(1) if m else "-"
                rows.append([str(_port_number(f)), svc, f.title or "—", criticidad(_port_number(f))])
            table(["Puerto", "Servicio", "Producto / Versión", "Criticidad"], rows,
                  col_widths=[2.0, 3.5, 5.5, 3.0])
    else:
        no_data("No se detectaron puertos abiertos o no se ejecutó el escaneo de puertos "
                "(categoría 'ports').")
    heading("Cloud Exposure", 2)
    definicion(PHRASES["cloud"])
    buckets = [f for f in findings if f.category == "bucket"]
    if buckets:
        table(["Recurso", "Estado", "URL"], [[f.dork_name, f.title or "-", f.url or "-"] for f in buckets],
              col_widths=[4.0, 5.0, 5.0], red_cols=(1,), url_cols=(2,))
    else:
        para("Sin exposición cloud pública confirmada.")
    heading("Recomendaciones", 2)
    para(PHRASES["exposure_recs"])
    add("")

    # ========================================================== 4. Technology & Vulnerability
    heading("4. Technology & Vulnerability Exposure")
    section_badge(["vuln"])
    section_chart(["vuln"])
    definicion(PHRASES["tech"])
    vulns = [f for f in findings if f.category == "vuln"]
    rows = _cve_rows(vulns, domain)
    n_cve = sum(1 for r in rows if r[0].startswith("CVE-"))
    n_edb = sum(1 for r in rows if r[3].startswith("PoC disponible (ExploitDB)"))
    n_spl = sum(1 for r in rows if r[3].startswith("PoC disponible (Sploitus)"))
    para(f"Resumen: {n_cve} CVE(s) verificados en NVD, {n_edb} exploit(s) en ExploitDB y "
         f"{n_spl} PoC(s) en Sploitus asociados a las tecnologías y servicios identificados.", bold=True)
    techs = [f for f in findings if f.category == "tech"]
    if techs:
        heading("Tecnologías y plugins detectados", 2)
        table(["Tecnología / plugin", "Versión", "URL"],
              [[f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"]
               for f in techs], col_widths=[5.0, 3.0, 6.0], url_cols=(2,))
    if rows:
        by_host2: dict[str, list] = {}
        for ident, product, host, estado in rows:
            by_host2.setdefault(host, []).append((ident, product, estado))
        for h, items in by_host2.items():
            heading(h, 3)
            table(["Identificador", "Producto", "Estado"], [[i, p, e] for i, p, e in items],
                  col_widths=[4.0, 5.0, 5.0])
    else:
        no_data("No se encontraron CVEs ni exploits públicos para las tecnologías y versiones "
                "identificadas.")
    eol = [f for f in vulns if f.dork_name.startswith("Fin de soporte")]
    if eol:
        heading("Tecnologías sin soporte del fabricante (EOL)", 2)
        table(["Producto", "Detalle"],
              [[f.dork_name.replace("Fin de soporte (EOL): ", ""), f.note] for f in eol],
              col_widths=[4.0, 10.0])
    heading("Recomendaciones", 2)
    para(PHRASES["tech_recs"])
    add("")

    # ========================================================== 5. Identity & User Exposure
    heading("5. Identity & User Exposure")
    section_badge(["leaks", "identity"])
    section_chart(["leaks", "identity"])
    heading("Employee Email Exposure", 2)
    definicion(PHRASES["identity"])
    emails = [f for f in findings if f.category == "email"]
    email_rows = [["Fuentes públicas", "email corporativo", e, "Baja"] for f in emails for e in f.emails]
    if email_rows:
        table(["Fuente", "Hallazgo", "Evidencia / URL", "Severidad"], email_rows,
              col_widths=[3.5, 3.5, 5.5, 1.5])
    else:
        no_data("No se detectaron correos corporativos expuestos en las fuentes consultadas.")

    heading("Exposed Credentials", 2)
    definicion(PHRASES["creds"])
    secret_leaks = [f for f in findings if f.secrets]
    if secret_leaks:
        table(["Recurso", "Datos expuestos", "URL"],
              [[f.dork_name, leak_detail(f), f.url or "-"] for f in secret_leaks],
              col_widths=[4.0, 5.0, 5.0], red_cols=(1,), url_cols=(2,))
    else:
        para("No se detectaron credenciales expuestas en las fuentes consultadas.")

    heading("File Sharing Exposure", 2)
    definicion(PHRASES["file_sharing"])
    docs = [f for f in findings if f.category == "document"]
    if docs:
        table(["Autor", "Metadatos", "Recurso", "URL"],
              [[f.author or "-", f.software or "-", f.filetype or "-", f.url or "-"] for f in docs],
              col_widths=[3.0, 4.0, 2.0, 5.0], url_cols=(3,))
    else:
        no_data("No se encontraron documentos públicos con metadatos.")
    heading("Recomendaciones", 2)
    para(PHRASES["identity_recs"])
    add("")

    # ========================================================== 6. Brand Reputation
    heading("6. Brand Reputation")
    section_badge(["reputation", "squatting"])
    section_chart(["reputation", "squatting"])
    heading("Valoración de reputación", 2)
    definicion(PHRASES["brand_reputation"])
    dom_rep = [f for f in findings if f.category == "reputation" and
               not (f.title and re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title))]
    if dom_rep:
        flagged = any(_num(f.note, r"malicioso=(\d+)") > 0 for f in dom_rep)
        para(f"Reputación de dominio: {'Indicios de mala reputación' if flagged else 'Sin indicios de mala reputación'}")
    else:
        para("Reputación de dominio: no consultada (requiere api key de VirusTotal o AbuseIPDB).",
             italic=True, color="mutedgray")
    ipr = [f for f in findings if f.category == "reputation" and f.title and
           re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title)]
    bad = [f.title for f in ipr if _num(f.note, r"confianza de abuso=(\d+)%") >= 50 or
           _num(f.note, r"malicioso=(\d+)") > 0]
    if bad:
        para(f"IPs propias con reputación negativa: {len(bad)} IP(s): {', '.join(bad)}")

    squat_f = [f for f in findings if f.category == "typosquat" and "squat" in (f.dork_name or "").lower()]
    typo_f = [f for f in findings if f.category == "typosquat" and "typo" in (f.dork_name or "").lower()]

    def _pairs(fs):
        out = []
        for f in fs:
            for ln in (f.note or "").splitlines():
                m = re.match(r"(\S+)\s*->\s*(\S+)", ln)
                if m:
                    out.append([m.group(1), m.group(2)])
        return out

    heading("Domain Squatting", 2)
    definicion(PHRASES["squatting"])
    sq = _pairs(squat_f)
    if sq:
        table(["Dominio", "IP"], sq, col_widths=[9.0, 5.0])
    else:
        para("No se detectaron dominios de squatting activos (registrados y resolviendo).")
    heading("Typosquatting", 2)
    definicion(PHRASES["typosquat"])
    ts = _pairs(typo_f)
    if ts:
        table(["Dominio", "IP"], ts, col_widths=[9.0, 5.0])
    else:
        para("No se detectaron variantes tipográficas del dominio activas.")
    heading("Recomendaciones", 2)
    para(PHRASES["brand_recs"])

    # ========================================================== conclusiones
    heading("Conclusiones")
    add(f"El análisis de reconocimiento aplicado sobre {_tex(domain)} refleja un nivel de riesgo "
        f"global de \\textbf{{{_tex(f'{total_txt}% (' + health['level'] + ')')}}}.")
    add("")
    addmd(f"El análisis de reconocimiento aplicado sobre {domain} refleja un nivel de riesgo "
          f"global de **{total_txt}% ({health['level']})**.")
    addmd("")
    triggered = [c["label"] for c in health["categories"].values() if c["points"]]
    if triggered:
        para("Las categorías que han disparado riesgo en esta evaluación son:")
        bullet_list(triggered)
        para("Se recomienda priorizar la remediación de estos hallazgos siguiendo las "
             "recomendaciones detalladas en cada sección de este informe.")
    else:
        para("No se ha detectado ninguna categoría de riesgo en esta evaluación: la superficie de "
             "exposición pública analizada no presenta hallazgos significativos en este momento.")

    add(r"\end{document}")

    tex_path = out_dir / "cyber_health_check.tex"
    tex_path.write_text("\n".join(parts), encoding="utf-8")
    md_path = out_dir / "cyber_health_check.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    pdf_ok = _compile_pdf(tex_path) if compile_pdf else False
    return {"health": health, "tex_path": tex_path, "md_path": md_path, "pdf_ok": pdf_ok}
