"""
Orquestacion de exportacion de informes, compartida por la CLI (cli.py) y
la web (app.py) para que ambas generen EXACTAMENTE lo mismo a partir de los
mismos `results` (antes cada una tenia su propia copia de esta logica, con
riesgo de que se desincronizaran).

Disenio: un unico informe por corrida, lo mas completo posible.
  - Un solo host (sin --recursive / sin subdominios descubiertos): el
    comportamiento de siempre, archivos en `out_dir` con los datos de ese
    host.
  - Mas de un host (recursive encontro subdominios): en vez de generar un
    informe del dominio solo Y OTRO "maestro" con todos los hosts (lo que
    antes vivia como informe.* + informe-maestro.*), se genera un UNICO
    informe en `out_dir` con el dominio + todos los subdominios juntos,
    usando los mismos nombres de archivo de siempre (sin sufijo "-maestro"
    desde que ya no hace falta distinguirlo del otro). Cada subdominio
    ademas conserva su propio informe completo en
    `out_dir/subdominios/<subdominio>/`, sin cambios.
"""
from pathlib import Path

from .cyber_health_report import build_cyber_health_docx
from .latex_report import build_latex_report
from .latex_technical_report import build_latex_technical_report
from .report import (
    Finding, export_csv, export_docx, export_excel, export_json, export_maltego_csv,
    export_master_docx, export_master_excel, export_master_txt, export_network_diagram,
    export_network_graph_json, export_txt,
)


def export_all(results: dict[str, list[Finding]], domain: str, out_dir: Path,
                logos_dir: str | Path | None = None, latex_pdf: bool = True) -> list[Finding]:
    """Escribe todos los informes/exports a disco segun el diseño descripto
    arriba y devuelve `all_findings` (la union de todos los hosts, con
    `f.host` seteado) para que el llamador la use en resumenes/risk score."""
    all_findings: list[Finding] = []
    multi_host = len(results) > 1

    for host, host_findings in results.items():
        for f in host_findings:
            f.host = host
        all_findings.extend(host_findings)

        if host == domain and multi_host:
            # El dominio principal no recibe su propio informe aparte
            # cuando hay subdominios: queda cubierto por el informe
            # combinado que se escribe mas abajo, en out_dir.
            continue

        host_out_dir = out_dir if host == domain else out_dir / "subdominios" / host
        host_out_dir.mkdir(parents=True, exist_ok=True)
        export_json(host_findings, host_out_dir / "resultados.json")
        export_csv(host_findings, host_out_dir / "resultados.csv")
        export_txt(host_findings, host, host_out_dir / "informe.txt")
        export_excel(host_findings, host, host_out_dir / "informe.xlsx")
        export_maltego_csv(host_findings, host, host_out_dir / "maltego.csv")
        export_network_diagram(host_findings, host, host_out_dir / "red.dot")
        export_network_graph_json(host_findings, host, host_out_dir / "red.json")
        export_docx(host_findings, host, host_out_dir / "informe.docx",
                    network_png=host_out_dir / "red.png")
        build_cyber_health_docx(host_findings, host, host_out_dir / "cyber_health_check.docx",
                                logos_dir=logos_dir)
        build_latex_report(host_findings, host, host_out_dir, logos_dir=logos_dir, compile_pdf=latex_pdf)
        build_latex_technical_report(host_findings, host, host_out_dir,
                                      logos_dir=logos_dir, compile_pdf=latex_pdf)

    if multi_host:
        # Unico informe para out_dir cuando hay mas de un host: dominio +
        # subdominios juntos, con los nombres de archivo de siempre (ya no
        # hay un informe.* "solo del dominio" con el que distinguirse).
        export_json(all_findings, out_dir / "resultados.json")
        export_csv(all_findings, out_dir / "resultados.csv")
        export_maltego_csv(all_findings, domain, out_dir / "maltego.csv")
        export_master_txt(results, domain, out_dir / "informe.txt")
        export_master_excel(results, domain, out_dir / "informe.xlsx")
        export_network_diagram(results, domain, out_dir / "red.dot")
        export_network_graph_json(results, domain, out_dir / "red.json")
        export_master_docx(results, domain, out_dir / "informe.docx",
                            network_png=out_dir / "red.png")
        build_cyber_health_docx(all_findings, domain, out_dir / "cyber_health_check.docx",
                                 results=results, logos_dir=logos_dir)
        build_latex_report(all_findings, domain, out_dir, results=results,
                            logos_dir=logos_dir, compile_pdf=latex_pdf)
        build_latex_technical_report(all_findings, domain, out_dir, results=results,
                                      logos_dir=logos_dir, compile_pdf=latex_pdf)

    return all_findings
