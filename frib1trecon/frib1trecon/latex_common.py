"""
Utilidades LaTeX compartidas por latex_report.py (informe ejecutivo) y
latex_technical_report.py (informe tecnico), para no duplicar la logica
de escapado/compilacion entre los dos.
"""
import re
import shutil
import subprocess
from pathlib import Path

from .docx_charts import LEVELS, SHORT

_TEX_SPECIAL = {
    "\\": r"\textbackslash{}", "{": r"\{", "}": r"\}", "$": r"\$", "&": r"\&",
    "#": r"\#", "_": r"\_", "%": r"\%", "^": r"\textasciicircum{}",
    "~": r"\textasciitilde{}", "<": r"\textless{}", ">": r"\textgreater{}",
}
_TEX_RE = re.compile("|".join(re.escape(k) for k in _TEX_SPECIAL))

# Cadenas sin espacios de 30+ caracteres (hashes, tokens, URLs/rutas sin
# barras, secretos) no tienen ningun punto de ruptura natural para TeX: en
# una columna estrecha de longtable desbordan la celda y se solapan
# visualmente con la columna de al lado (y a veces el margen de pagina).
# \seqsplit permite partirlas por cualquier caracter sin perder la
# justificacion del resto del texto (ver shared_preamble: usepackage{seqsplit}).
_LONG_TOKEN_RE = re.compile(r"\S{30,}")


def tex_escape(s) -> str:
    """Escapa texto para LaTeX. Imprescindible para TODO lo que venga de un
    Finding (titulos/notas/URLs/dominios): es contenido scrapeado de la web,
    no confiable. Nunca se vuelca sin escapar dentro de un entorno verbatim/
    lstlisting (ver nota de seguridad en latex_report.py)."""
    if s is None:
        return ""
    escaped = _TEX_RE.sub(lambda m: _TEX_SPECIAL[m.group(0)], str(s))
    return _LONG_TOKEN_RE.sub(lambda m: f"\\seqsplit{{{m.group(0)}}}", escaped)


def tex_url(u) -> str:
    """\\url{} para que el enlace sea clicable; si la URL tiene caracteres
    que rompen el parser de \\url (\\, {, }) se muestra como texto normal
    escapado en vez de arriesgar una compilacion rota."""
    if not u:
        return "-"
    if any(c in u for c in ("\\", "{", "}")):
        return tex_escape(u)
    return f"\\url{{{u}}}"


def logo_path(p) -> str:
    return Path(p).resolve().as_posix()


def md_escape(s) -> str:
    """Escapa lo minimo para que el texto no rompa la estructura del
    Markdown (tablas/listas): barra invertida, pipe (celdas de tabla) y
    saltos de linea sueltos."""
    if s is None:
        return ""
    s = str(s).replace("\\", "\\\\").replace("|", "\\|")
    return s.replace("\r\n", " ").replace("\n", " ")


def compile_pdf(tex_path: Path) -> bool:
    """Compila el .tex a PDF con pdflatex si esta instalado (dos pasadas,
    para que el indice salga completo). Degrada a False sin lanzar
    excepcion si pdflatex no esta, si falla, o si tarda demasiado: el .tex
    se deja igual para que el usuario lo compile donde quiera.

    Se invoca con `cwd=out_dir` y el nombre de fichero SIN ruta (nunca
    `-output-directory <ruta absoluta>`): kpathsea (el resolvedor de rutas
    de TeX) trata ':' como separador de lista de rutas, asi que una ruta
    absoluta con ':' (p.ej. de un nombre de host mal normalizado) puede
    hacer fallar la compilacion en seco sin motivo real relacionado con el
    contenido del documento. Evitar pasarle rutas absolutas a pdflatex
    evita esa clase de fallo por completo."""
    if not shutil.which("pdflatex"):
        return False
    out_dir = tex_path.parent
    cmd = ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    log_path = tex_path.with_suffix(".log")
    ok = True
    try:
        for _ in range(2):
            r = subprocess.run(cmd, capture_output=True, timeout=90, cwd=out_dir)
            if r.returncode != 0:
                ok = False
                break
    except (subprocess.TimeoutExpired, OSError) as exc:
        ok = False
        print(f"[latex] Aviso: fallo al compilar {tex_path.name} a PDF ({exc}).")
    if not ok and log_path.exists():
        print(f"[latex] Aviso: pdflatex no pudo compilar {tex_path.name} a PDF; detalle en {log_path}.")
    for ext in (".aux", ".out", ".toc"):
        p = tex_path.with_suffix(ext)
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    if ok and log_path.exists():
        try:
            log_path.unlink()
        except OSError:
            pass
    return ok and tex_path.with_suffix(".pdf").exists()


def shared_preamble(domain: str, pentester_logo, client_logo, chead_label: str) -> list[str]:
    """Preambulo LaTeX comun a ambos informes: mismos paquetes, misma
    paleta de color (alineada con cyber_health_report.py/docx_charts.py),
    misma cabecera con 2 logos + regla navy, mismo pie de pagina. Sin
    babel[spanish] a proposito (ver latex_report.py para el porque)."""
    lines = [
        r"\documentclass[a4paper]{article}",
        r"\usepackage[utf8]{inputenc}",
        r"\usepackage[T1]{fontenc}",
        # lmodern: fuentes escalables (Type1), no los bitmaps Computer Modern
        # por defecto. Sin esto, microtype falla en seco ("font expansion:
        # auto expansion is only possible with scalable fonts") en cualquier
        # instalacion de TeX que no tenga cm-super instalado aparte.
        r"\usepackage{lmodern}",
        r"\usepackage[margin=2cm, top=2.3cm, includefoot]{geometry}",
        r"\usepackage{graphicx}",
        r"\usepackage[table]{xcolor}",
        r"\usepackage[most]{tcolorbox}",
        r"\usepackage{fancyhdr}",
        r"\usepackage[hidelinks, breaklinks=true]{hyperref}",
        r"\usepackage{setspace}",
        r"\setstretch{1.15}",
        r"\usepackage{parskip}",
        r"\usepackage{longtable}",
        r"\usepackage{array}",
        r"\usepackage{microtype}",
        r"\usepackage{seqsplit}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\tabcolsep}{4pt}",
        # Texto siempre justificado (nunca \raggedright): estos ajustes dan a
        # TeX un margen de maniobra extra antes de forzar una caja "overfull"
        # que se saldria del margen de pagina o se solaparia con la columna
        # siguiente en una tabla estrecha.
        r"\tolerance=1000",
        r"\emergencystretch=3em",
        r"\hbadness=10000",
        "",
        r"\definecolor{navyblue}{HTML}{0B1B4D}",
        r"\definecolor{alertred}{HTML}{C9343A}",
        r"\definecolor{mutedgray}{HTML}{6B7794}",
        r"\definecolor{okgreen}{HTML}{1F8F62}",
        "",
        r"\renewcommand{\contentsname}{Índice}",
        r"\setlength{\headheight}{40pt}",
        r"\pagestyle{fancy}",
        r"\fancyhf{}",
        f"\\lhead{{\\includegraphics[height=0.9cm]{{{logo_path(pentester_logo)}}}}}",
    ]
    if client_logo:
        lines.append(f"\\rhead{{\\includegraphics[height=0.9cm]{{{logo_path(client_logo)}}}}}")
    lines += [
        f"\\chead{{\\small\\color{{mutedgray}} {tex_escape(chead_label)} \\textperiodcentered\\ {tex_escape(domain)}}}",
        r"\renewcommand{\headrulewidth}{2pt}",
        r"\renewcommand{\headrule}{\hbox to \headwidth{\color{navyblue}\leaders\hrule height \headrulewidth\hfill}}",
        r"\cfoot{\small\color{mutedgray} Confidencial · Página \thepage}",
        "",
        r"\newtcolorbox{definicion}{breakable, enhanced, colback=white, colframe=navyblue!75!black,"
        r" arc=0mm, boxrule=1pt, leftrule=12mm, fonttitle=\bfseries, coltitle=navyblue!75!black,"
        r" title=Definición, attach title to upper=\par}",
        r"\newtcolorbox{seccionbanner}{enhanced, colback=navyblue, colframe=navyblue,"
        r" width=\linewidth, arc=0mm, boxrule=0pt, left=4mm, right=4mm, top=2mm, bottom=2mm,"
        r" fontupper=\color{white}\bfseries\Large}",
        "",
        r"\begin{document}",
        "",
    ]
    return lines


def _lvl_color(v: float) -> str:
    """Mismo umbral/color que docx_charts._lvl_color (LEVELS importado de
    ahi): bajo<20 verde, medio<40 ambar, alto<65 naranja, critico rojo."""
    return next(c for m, _, c in LEVELS if v < m)


def render_global_bar_chart(pct: float, out_path, width_cm: float = 16.0, height_cm: float = 1.3) -> None:
    """Barra horizontal unica con el riesgo global (equivalente en imagen
    al grafico nativo bar_stacked de docx_charts.py, mismos colores/
    umbrales, para que LaTeX y DOCX digan y SE VEAN igual)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pct = max(0.0, min(100.0, float(pct)))
    color = f"#{_lvl_color(pct)}"
    fig, ax = plt.subplots(figsize=(width_cm / 2.54, height_cm / 2.54), dpi=150)
    ax.barh([0], [pct], color=color, height=0.65, zorder=3)
    ax.barh([0], [100 - pct], left=[pct], color="#E3E8F3", height=0.65, zorder=2)
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 0.5)
    inside = pct > 10
    ax.text(pct / 2 if inside else pct + 1.5, 0, f"{pct:.0f}%",
            va="center", ha="center" if inside else "left",
            color="white" if inside else color, fontsize=12, fontweight="bold")
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    fig.savefig(out_path, transparent=True)
    plt.close(fig)


def render_cats_bar_chart(cats: list[dict], out_path, width_cm: float = 16.0, height_cm: float | None = None) -> None:
    """Una barra horizontal por categoria (0% o 100%, modelo binario),
    coloreada por nivel: equivalente en imagen al grafico nativo bar_cats
    de docx_charts.py (mismos SHORT/LEVELS), usado tanto para el grafico
    'risk_cats' completo como para el badge/grafico de cada una de las 6
    secciones (subconjunto de categorias)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(cats)
    if n == 0:
        return
    if height_cm is None:
        height_cm = max(1.3, 0.9 * n + 0.5)
    labels = [SHORT.get(c["key"], c["label"]) for c in cats][::-1]
    vals = [float(c["riskPct"]) for c in cats][::-1]
    colors = [f"#{_lvl_color(v)}" for v in vals]
    fig, ax = plt.subplots(figsize=(width_cm / 2.54, height_cm / 2.54), dpi=150)
    y = range(n)
    ax.barh(list(y), vals, color=colors, height=0.55, zorder=3)
    ax.set_xlim(0, 118)
    ax.set_ylim(-0.6, n - 0.4)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9, color="#16213F")
    for i, v in enumerate(vals):
        ax.text(v + 3, i, f"{v:.0f}%", va="center", fontsize=9, fontweight="bold", color="#16213F")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(left=False, bottom=False, labelbottom=False)
    fig.subplots_adjust(left=0.3, right=0.98, top=0.98, bottom=0.02)
    fig.savefig(out_path, transparent=True)
    plt.close(fig)
