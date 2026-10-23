"""
Graficos nativos de Word para la seccion de riesgo del informe Cyber Health
Check (clic derecho sobre el grafico > "Editar datos": se abre una mini-hoja
con los numeros, el grafico es 100% editable, no una imagen).

Mismo mecanismo que el toolkit de referencia (docx_charts.py de David): se
genera el grafico con python-pptx (que ya sabe construir chart XML + su
libro de Excel incrustado), se extraen esas dos piezas, y se inyectan en el
.docx sustituyendo un placeholder de texto "[[CHART nombre]]" por un
<w:drawing> que referencia el grafico.

A diferencia del toolkit de referencia, aqui SOLO se portan los graficos que
no dependen de un desglose de "subcontroles" por categoria (el toolkit de
referencia los tiene; el modelo de riesgo de frib1trecon es binario por
categoria: dispara o no dispara, ver report.compute_risk_score): la barra
global de riesgo (bar_stacked) y una barra por categoria (bar_cats). Si
cualquier paso falla (python-pptx no instalado, XML inesperado...) se
degrada sin romper nada: el documento se guarda igual, solo sin los
graficos nativos (ver embed_risk_charts).
"""
import io
import re
import zipfile

from lxml import etree
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION
from pptx.util import Emu, Pt

INK, MUTED, GREY = "16213F", "6B7794", "E3E8F3"
# Mismos umbrales que report.risk_level_for (bajo<20, medio<40, alto<65, critico 65+).
LEVELS = [(20, "BAJO", "1F8F62"), (40, "MEDIO", "D18A00"), (65, "ALTO", "E5640B"), (1e9, "CRITICO", "C9343A")]
CM = 360000

# Nombres cortos para el eje de categorias (las labels reales de RISK_STRUCTURE
# son frases largas, no caben en el eje de un grafico horizontal).
SHORT = {
    "leaks": "Leaks/credenciales", "dns_email": "DNS/email", "tls_web": "TLS/cabeceras",
    "vuln": "CVEs/EOL", "reputation": "Reputacion", "squatting": "Typosquat/squat",
    "identity": "Identidad",
}

_CHART_SIZES_CM = {"risk_global": (13.0, 1.3), "risk_cats": (13.0, 5.2)}


def _lvl_color(v):
    return next(c for m, _, c in LEVELS if v < m)


def _rgb(h):
    return RGBColor.from_string(h)


def _new(chart_type, cd, w, h):
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    gf = slide.shapes.add_chart(chart_type, 0, 0, Emu(int(w)), Emu(int(h)), cd)
    gf.chart.font.name = "Calibri"  # misma familia que el resto del informe
    gf.chart.font.size = Pt(9)
    return prs, gf.chart


def _pack(prs):
    """Genera el pptx en memoria y extrae el chart XML + el libro de Excel
    que python-pptx incrusta solo (no hace falta xlsxwriter para esto)."""
    buf = io.BytesIO()
    prs.save(buf)
    z = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    chart_name = next(n for n in z.namelist() if re.fullmatch(r"ppt/charts/chart\d*\.xml", n))
    embed_name = next(n for n in z.namelist() if n.startswith("ppt/embeddings/"))
    return z.read(chart_name), z.read(embed_name)


def _no_wrap(data_labels):
    """Evita un bug real visto en bar_stacked con LibreOffice: cuando el
    segmento coloreado de la barra es estrecho (valores de riesgo bajos),
    la etiqueta de dato se envolvia letra por letra ("4" / "0" / "%" en
    tres lineas) en vez de mostrarse en una sola linea. Forzar wrap="none"
    en el bodyPr de la etiqueta (ya creado por `dl.font.*`) lo evita."""
    ns = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}
    body_pr = data_labels._element.find(".//a:bodyPr", ns)
    if body_pr is not None:
        body_pr.set("wrap", "none")


def _noframe(chart):
    """Sin recuadro ni relleno de fondo alrededor del grafico."""
    cs = chart._chartSpace
    ns = {"c": "http://schemas.openxmlformats.org/drawingml/2006/chart",
          "a": "http://schemas.openxmlformats.org/drawingml/2006/main"}
    sp = cs.find("c:spPr", ns)
    if sp is None:
        sp = etree.SubElement(cs, "{%s}spPr" % ns["c"])
        tx = cs.find("c:txPr", ns)
        if tx is not None:
            tx.addprevious(sp)
        else:
            ed = cs.find("c:externalData", ns)
            if ed is not None:
                ed.addprevious(sp)
    for ch in list(sp):
        sp.remove(ch)
    etree.SubElement(sp, "{%s}noFill" % ns["a"])
    ln = etree.SubElement(sp, "{%s}ln" % ns["a"])
    etree.SubElement(ln, "{%s}noFill" % ns["a"])


def bar_stacked(pct, w, h):
    """Barra horizontal unica con el riesgo global: tramo coloreado por nivel
    + relleno gris para el resto hasta el 100%."""
    pct = max(0.0, min(100.0, float(pct)))
    cd = CategoryChartData(number_format="0.##")
    cd.categories = ["Riesgo"]
    cd.add_series("Riesgo (%)", [round(pct, 2)])
    cd.add_series("Resto", [round(100 - pct, 2)])
    prs, ch = _new(XL_CHART_TYPE.BAR_STACKED, cd, w, h)
    ch.has_legend = False
    ch.has_title = False
    pl = ch.plots[0]
    pl.gap_width = 25
    pl.overlap = 100
    va, ca = ch.value_axis, ch.category_axis
    va.minimum_scale, va.maximum_scale = 0, 100
    va.visible = False
    va.has_major_gridlines = False
    ca.visible = False
    s0, s1 = pl.series
    s0.format.fill.solid()
    s0.format.fill.fore_color.rgb = _rgb(_lvl_color(pct))
    s1.format.fill.solid()
    s1.format.fill.fore_color.rgb = _rgb(GREY)
    dl = s0.data_labels
    dl.show_value = True
    dl.number_format = '0.##"%"'
    dl.number_format_is_linked = False
    dl.font.size = Pt(11)
    dl.font.bold = True
    dl.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    _no_wrap(dl)
    _noframe(ch)
    return _pack(prs)


def bar_cats(cats, w, h):
    """Una barra horizontal por categoria de riesgo (0% o 100%, el modelo de
    frib1trecon es binario), coloreada segun su nivel."""
    cd = CategoryChartData(number_format="0.##")
    cd.categories = [SHORT.get(c["key"], c["label"]) for c in cats]
    vals = [round(c["riskPct"], 2) for c in cats]
    cd.add_series("Riesgo (%)", vals)
    prs, ch = _new(XL_CHART_TYPE.BAR_CLUSTERED, cd, w, h)
    ch.has_legend = False
    ch.has_title = False
    pl = ch.plots[0]
    pl.gap_width = 45
    pl.vary_by_categories = False
    va, ca = ch.value_axis, ch.category_axis
    va.minimum_scale, va.maximum_scale = 0, 118
    va.visible = False
    va.has_major_gridlines = False
    ca.reverse_order = True
    ca.tick_labels.font.size = Pt(9)
    ca.tick_labels.font.color.rgb = _rgb(INK)
    ca.format.line.color.rgb = _rgb(GREY)
    ca.has_major_gridlines = False
    s = pl.series[0]
    for i, v in enumerate(vals):
        pt = s.points[i]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = _rgb(_lvl_color(v))
    dl = s.data_labels
    dl.show_value = True
    dl.number_format = '0.##"%"'
    dl.number_format_is_linked = False
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    dl.font.size = Pt(9)
    dl.font.bold = True
    dl.font.color.rgb = _rgb(INK)
    _noframe(ch)
    return _pack(prs)


def _section_keys(name):
    """Nombres dinamicos 'risk_section_<key1>__<key2>...' para el grafico
    de una seccion del informe ejecutivo que cubre un subconjunto de
    categorias de riesgo (separador '__', ya que ninguna key de
    RISK_STRUCTURE lleva doble guion bajo)."""
    return name[len("risk_section_"):].split("__")


def _chart_size(name):
    if name in _CHART_SIZES_CM:
        return _CHART_SIZES_CM[name]
    if name.startswith("risk_section_"):
        n = len(_section_keys(name))
        return (13.0, max(0.95, 0.65 * n + 0.35))
    raise KeyError(name)


def _build_chart(name, data):
    w, h = (x * CM for x in _chart_size(name))
    if name == "risk_global":
        return bar_stacked(data["score"], w, h)
    if name == "risk_cats":
        return bar_cats(data["categories"], w, h)
    if name.startswith("risk_section_"):
        keys = set(_section_keys(name))
        subset = [c for c in data["categories"] if c["key"] in keys]
        return bar_cats(subset, w, h)
    raise KeyError(name)


def _inject(data, src, dst):
    """Sustituye cada '[[CHART nombre]]' de `src` (ruta o file-like .docx) por
    un grafico nativo, escribiendo el resultado en `dst` (ruta o file-like)."""
    zin = zipfile.ZipFile(src)
    files = {n: zin.read(n) for n in zin.namelist()}
    doc = files["word/document.xml"].decode("utf8")
    rels = files["word/_rels/document.xml.rels"].decode("utf8")
    ct = files["[Content_Types].xml"].decode("utf8")
    used = max([int(x) for x in re.findall(r'Id="rId(\d+)"', rels)] + [0])
    k = 0

    def repl(m):
        nonlocal k, rels, ct, used
        name = m.group(1)
        k += 1
        w, h = (int(x * CM) for x in _chart_size(name))
        cx, emb = _build_chart(name, data)
        cname, ename = f"chart{k}.xml", f"Microsoft_Excel_Sheet{k}.xlsx"
        files[f"word/charts/{cname}"] = cx
        files[f"word/embeddings/{ename}"] = emb
        files[f"word/charts/_rels/{cname}.rels"] = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" '
            f'Target="../embeddings/{ename}"/></Relationships>'
        ).encode()
        ct = ct.replace(
            "</Types>",
            f'<Override PartName="/word/charts/{cname}" '
            f'ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/></Types>',
        )
        used += 1
        rid = f"rId{used}"
        rels = rels.replace(
            "</Relationships>",
            f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" '
            f'Target="charts/{cname}"/></Relationships>',
        )
        return (
            f'<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{w}" cy="{h}"/>'
            '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
            f'<wp:docPr id="{900 + k}" name="Grafico {k}"/><wp:cNvGraphicFramePr/>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
            f'<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
            f'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="{rid}"/>'
            "</a:graphicData></a:graphic></wp:inline></w:drawing></w:r>"
        )

    doc = re.sub(r"<w:r>(?:(?!</w:r>).)*?\[\[CHART ([\w]+)\]\](?:(?!</w:r>).)*?</w:r>", repl, doc, flags=re.S)
    if "Extension=\"xlsx\"" not in ct:
        ct = ct.replace(
            "<Override",
            '<Default Extension="xlsx" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"/><Override',
            1,
        )
    if "xmlns:wp=" not in doc[:3000]:
        doc = doc.replace(
            "<w:document ",
            '<w:document xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" ',
            1,
        )
    files["word/document.xml"] = doc.encode("utf8")
    files["word/_rels/document.xml.rels"] = rels.encode("utf8")
    files["[Content_Types].xml"] = ct.encode("utf8")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
        zo.writestr("[Content_Types].xml", files.pop("[Content_Types].xml"))
        for n, b in files.items():
            zo.writestr(n, b)


def embed_risk_charts(data: dict, src, dst) -> bool:
    """Sustituye los placeholders [[CHART risk_global]]/[[CHART risk_cats]]
    por graficos nativos editables. `src` puede ser una ruta o un file-like
    ya con el .docx (se reposiciona solo al principio). Si algo falla
    (python-pptx no instalado, XML inesperado...) copia `src` a `dst` tal
    cual: el informe se genera igual, solo sin los graficos nativos."""
    try:
        if hasattr(src, "seek"):
            src.seek(0)
        _inject(data, src, dst)
        return True
    except Exception as exc:  # noqa: BLE001 - degradar sin romper el informe
        if hasattr(src, "seek"):
            src.seek(0)
            raw = src.read()
        else:
            with open(src, "rb") as fh:
                raw = fh.read()
        with open(dst, "wb") as fh:
            fh.write(raw)
        print(f"[cyber_health_report] Aviso: no se pudieron incorporar los graficos nativos ({exc}).")
        return False
