#!/usr/bin/env python3
"""
Interfaz web de frib1trecon. Vive en una carpeta separada de la CLI
(frib1trecon/) a proposito: no toca ni importa nada que modifique el estado
de un escaneo por CLI que ya este corriendo. Reutiliza la logica del paquete
frib1trecon/ de esa carpeta (en concreto engine.run_scan) via sys.path, sin
duplicarla.

Requiere que SearXNG ya este arriba (mismo requisito que la CLI):
    cd ../frib1trecon && ./install.sh          # o setup_searxng.py

Uso:
    python3 app.py
    -> abre http://127.0.0.1:5000
"""
import sys
import threading
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for

FRIB1TRECON_ROOT = Path(__file__).resolve().parent.parent / "frib1trecon"
sys.path.insert(0, str(FRIB1TRECON_ROOT))

from frib1trecon.engine import VALID_CATEGORIES, normalize_domain, run_scan_recursive  # noqa: E402
from frib1trecon.report_export import export_all  # noqa: E402
from frib1trecon.report import (  # noqa: E402
    SENIORITY_LABELS, compute_risk_score, confianza_empresa, leak_detail, org_chart_rows,
)

app = Flask(__name__)

RESULTS_DIR = Path(__file__).resolve().parent / "scans"
RESULTS_DIR.mkdir(exist_ok=True)

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

LOGO_UPLOAD_FIELDS = {"portada_logo": "portada", "cliente_logo": "cliente", "pentester_logo": "pentester"}
ALLOWED_LOGO_EXT = {".png", ".jpg", ".jpeg"}


def _save_logo_uploads(out_dir: Path) -> str | None:
    """Guarda los logos subidos desde el formulario (si hay alguno) en
    out_dir/logos/<nombre fijo>.<ext>, el mismo nombre que espera
    cyber_health_report._find_logo. La extension sale del propio fichero
    subido, nunca del nombre original (nunca se usa ese nombre para
    construir la ruta): cero riesgo de path traversal."""
    logos_dir = out_dir / "logos"
    saved_any = False
    for field, basename in LOGO_UPLOAD_FIELDS.items():
        f = request.files.get(field)
        if not f or not f.filename:
            continue
        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_LOGO_EXT:
            continue
        logos_dir.mkdir(parents=True, exist_ok=True)
        f.save(str(logos_dir / f"{basename}{ext}"))
        saved_any = True
    return str(logos_dir) if saved_any else None


def new_job(domain: str, opts: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "id": job_id,
        "domain": domain,
        "status": "running",
        "events": [],
        "findings": [],
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "opts": opts,
        # Igual que la CLI (frib1trecon_output/<dominio>/): una sola carpeta
        # por dominio en la carpeta principal, para que nunca se mezclen
        # resultados de dominios distintos. El id de job sigue existiendo
        # como clave interna (JOBS[job_id], /job/<job_id>, etc.) pero ya no
        # forma parte de la ruta en disco; si se vuelve a escanear el mismo
        # dominio desde la web, se sobrescribe su carpeta, igual que ya
        # pasa en la CLI hoy.
        "out_dir": RESULTS_DIR / domain,
        "error": None,
        "hosts": [domain],
    }
    return job_id


def on_event_factory(job_id: str):
    def on_event(evt: dict):
        with JOBS_LOCK:
            job = JOBS[job_id]
            if evt["type"] == "finding":
                finding = evt["finding"]
                job["findings"].append(finding)
                job["events"].append({
                    "type": "finding_summary",
                    "url": finding.url,
                    "category": finding.category,
                    "leak": bool(finding.secrets) or finding.category == "leak",
                })
            else:
                job["events"].append(evt)
    return on_event


def run_job(job_id: str):
    job = JOBS[job_id]
    out_dir = job["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    opts = job["opts"]
    domain = job["domain"]
    try:
        # Por defecto se corre TODO (VALID_CATEGORIES), igual que la CLI sin
        # flags. Los checkboxes del form son para EXCLUIR, no para sumar:
        # si llegan destildados, sacan esa categoria del set completo.
        categories = set(VALID_CATEGORIES)
        if not opts["linkedin"]:
            categories.discard("people")
        if not opts["external_osint"]:
            categories.discard("external")
        if not opts["vuln"]:
            categories.discard("vuln")
        if not opts["typosquat"]:
            categories.discard("typosquat")
        if not opts["ports"]:
            categories.discard("ports")

        results = run_scan_recursive(
            domain, out_dir,
            searxng_endpoints=[opts["searxng"]], proxies=opts["proxy_list"],
            min_delay=opts["min_delay"], max_delay=opts["max_delay"],
            save_docs=opts["save_docs"], no_download=opts["no_download"],
            categories=categories, recursive_categories=opts["recursive_categories"],
            external_keys={
                "shodan": opts["shodan_key"] or None,
                "grayhatwarfare": opts["ghw_key"] or None,
                "intelx": opts["intelx_key"] or None,
                "dnsdumpster": opts["dnsdumpster_key"] or None,
                "virustotal": opts["vt_key"] or None,
                "abuseipdb": opts["abuseipdb_key"] or None,
                "censys": (opts["censys_id"], opts["censys_secret"]) if opts["censys_id"] and opts["censys_secret"] else None,
                "fofa": (opts["fofa_email"], opts["fofa_key"]) if opts["fofa_email"] and opts["fofa_key"] else None,
                "hibp": opts["hibp_key"] or None,
                "domscan": opts["domscan_key"] or None,
                "otx": opts["otx_key"] or None,
            },
            recursive=opts["recursive"], max_subdomains=opts["max_subdomains"],
            on_event=on_event_factory(job_id),
        )

        # export_all() es la misma funcion que usa la CLI (report_export.py):
        # garantiza que ambas generen exactamente lo mismo a partir de los
        # mismos `results` — un unico informe completo por corrida, no un
        # informe.* del dominio solo mas un informe-maestro.* aparte.
        all_findings = export_all(results, domain, out_dir, logos_dir=opts["logos_dir"] or None,
                                   latex_pdf=not opts["no_latex_pdf"])

        with JOBS_LOCK:
            job["findings"] = all_findings
            job["hosts"] = list(results.keys())
            job["status"] = "done"
    except Exception as exc:  # noqa: BLE001 - queremos reportar cualquier fallo a la web
        with JOBS_LOCK:
            job["status"] = "error"
            job["error"] = str(exc)


def summarize(findings) -> dict:
    authors = sorted({f.author for f in findings if f.author})
    editors = sorted({f.last_modified_by for f in findings if f.last_modified_by})
    software = sorted({f.software for f in findings if f.software})
    emails = sorted({e for f in findings for e in f.emails})
    paths = sorted({p for f in findings for p in f.internal_paths})
    computers = sorted({c for f in findings for c in f.computers})
    people = [f for f in findings if f.category == "people" and f.person_name]
    leaks = [f for f in findings if f.secrets or f.category in ("leak", "bucket")]
    external = [f for f in findings if f.category in
                ("shodan", "bucket", "intelx", "subdomains", "wayback", "cloud", "reputation")]
    cloud = sorted({f.dork_name.split(": ")[-1] for f in findings if f.category == "cloud"})
    tech = sorted({f"{f.dork_name.replace('Tecnologia detectada: ', '')} {f.title}"
                   for f in findings if f.category == "tech"})
    vulns = [f for f in findings if f.category == "vuln"]
    dns_checks = [f for f in findings if f.category == "dns"]
    axfr_vulnerable = any("AXFR" in f.dork_name for f in findings if f.category == "leak")
    tls_checks = [f for f in findings if f.category == "tls"]
    typosquat_checks = [f for f in findings if f.category == "typosquat"]
    ports_checks = [f for f in findings if f.category == "ports"]
    risk = compute_risk_score(findings)
    return {
        "authors": authors, "editors": editors, "software": software,
        "emails": emails, "paths": paths, "computers": computers,
        "n_people": len(people), "n_leaks": len(leaks), "n_external": len(external),
        "cloud": cloud, "tech": tech, "n_vulns": len(vulns),
        "n_dns": len(dns_checks), "axfr_vulnerable": axfr_vulnerable,
        "n_tls": len(tls_checks), "n_typosquat": len(typosquat_checks), "n_ports": len(ports_checks),
        "risk": risk,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/help")
def help_page():
    return render_template("help.html")


@app.route("/scan", methods=["POST"])
def scan():
    # normalize_domain acepta tanto "site.com" como una URL completa pegada
    # del navegador y siempre devuelve el hostname desnudo: sin esto, pegar
    # la URL entera rompe DNS/TLS/puertos y el nombre de la carpeta de
    # salida (ver engine.normalize_domain).
    domain = normalize_domain(request.form.get("domain", ""))
    if not domain:
        return redirect(url_for("index"))

    opts = {
        "save_docs": request.form.get("save_docs") == "on",
        "no_download": request.form.get("no_download") == "on",
        "linkedin": request.form.get("linkedin") == "on",
        "external_osint": request.form.get("external_osint") == "on",
        "vuln": request.form.get("vuln") == "on",
        "typosquat": request.form.get("typosquat") == "on",
        "ports": request.form.get("ports") == "on",
        "recursive": request.form.get("recursive") == "on",
        "max_subdomains": int(request.form.get("max_subdomains") or 10),
        "shodan_key": request.form.get("shodan_key", "").strip(),
        "ghw_key": request.form.get("ghw_key", "").strip(),
        "intelx_key": request.form.get("intelx_key", "").strip(),
        "dnsdumpster_key": request.form.get("dnsdumpster_key", "").strip(),
        "vt_key": request.form.get("vt_key", "").strip(),
        "abuseipdb_key": request.form.get("abuseipdb_key", "").strip(),
        "censys_id": request.form.get("censys_id", "").strip(),
        "censys_secret": request.form.get("censys_secret", "").strip(),
        "fofa_email": request.form.get("fofa_email", "").strip(),
        "fofa_key": request.form.get("fofa_key", "").strip(),
        "hibp_key": request.form.get("hibp_key", "").strip(),
        "domscan_key": request.form.get("domscan_key", "").strip(),
        "otx_key": request.form.get("otx_key", "").strip(),
        "min_delay": float(request.form.get("min_delay") or 2.5),
        "max_delay": float(request.form.get("max_delay") or 6.0),
        "searxng": request.form.get("searxng") or "http://127.0.0.1:8080",
        "proxy_list": [p.strip() for p in request.form.get("proxy", "").split(",") if p.strip()] or None,
        "recursive_categories": ({c.strip().lower() for c in request.form.get("recursive_categories", "").split(",") if c.strip()}
                                  & VALID_CATEGORIES) or None,
        "no_latex_pdf": request.form.get("no_latex_pdf") == "on",
    }
    job_id = new_job(domain, opts)
    # Los logos se suben como ficheros (enctype=multipart/form-data), no
    # como ruta de texto: se guardan ya dentro de out_dir, que solo se
    # conoce tras crear el job.
    opts["logos_dir"] = _save_logo_uploads(JOBS[job_id]["out_dir"])
    threading.Thread(target=run_job, args=(job_id,), daemon=True).start()
    return redirect(url_for("job_page", job_id=job_id))


@app.route("/job/<job_id>")
def job_page(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Job no encontrado (¿reiniciaste el servidor?)", 404

    if job["status"] != "done":
        return render_template("job_running.html", job=job)

    findings = job["findings"]
    people = []
    for f in org_chart_rows(findings):
        row = asdict(f)
        row["nivel_label"] = SENIORITY_LABELS.get(f.seniority, f.seniority or "-")
        row["confianza"] = confianza_empresa(f)
        people.append(row)

    rendered_findings = []
    for f in findings:
        row = asdict(f)
        row["detalle"] = leak_detail(f)
        rendered_findings.append(row)

    out_dir = job["out_dir"]
    reports = {
        "cyber_health_pdf": (out_dir / "cyber_health_check.pdf").exists(),
        "cyber_health_tex": (out_dir / "cyber_health_check.tex").exists(),
        "cyber_health_md": (out_dir / "cyber_health_check.md").exists(),
        "informe_pdf": (out_dir / "informe.pdf").exists(),
        "informe_tex": (out_dir / "informe.tex").exists(),
        "informe_md": (out_dir / "informe.md").exists(),
    }

    return render_template(
        "job_done.html", job=job,
        findings=rendered_findings,
        people=people,
        summary=summarize(findings),
        multi_host=len(job.get("hosts", [])) > 1,
        reports=reports,
    )


@app.route("/job/<job_id>/graph")
def job_graph(job_id):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return "No disponible", 404
    return render_template("graph.html", job=job)


@app.route("/api/job/<job_id>/graph")
def job_graph_data(job_id):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "not_found"}), 404
    path = job["out_dir"] / "red.json"
    if not path.exists():
        return jsonify({"nodes": [], "edges": []})
    return send_from_directory(job["out_dir"], "red.json", mimetype="application/json")


@app.route("/api/job/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    since = int(request.args.get("since", 0))
    with JOBS_LOCK:
        new_events = job["events"][since:]
        cursor = len(job["events"])
        status = job["status"]
        n_findings = len(job["findings"])
        error = job["error"]
    return jsonify({
        "status": status, "events": new_events, "cursor": cursor,
        "n_findings": n_findings, "error": error,
    })


@app.route("/download/<job_id>/<fmt>")
def download(job_id, fmt):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return "No disponible", 404
    filenames = {
        "txt": "informe.txt", "xlsx": "informe.xlsx", "docx": "informe.docx",
        "json": "resultados.json", "csv": "resultados.csv", "maltego": "maltego.csv",
        "red-dot": "red.dot", "red-png": "red.png", "red-json": "red.json",
        "cyber-health": "cyber_health_check.docx",
        "cyber-health-pdf": "cyber_health_check.pdf", "cyber-health-tex": "cyber_health_check.tex",
        "cyber-health-md": "cyber_health_check.md",
        "informe-pdf": "informe.pdf", "informe-tex": "informe.tex", "informe-md": "informe.md",
    }
    fname = filenames.get(fmt)
    if not fname:
        return "Formato no soportado", 400
    return send_from_directory(job["out_dir"], fname, as_attachment=True)


if __name__ == "__main__":
    # Solo localhost por defecto: esto navega documentos y metadatos de
    # terceros, no lo expongas en red sin anadir autenticacion antes.
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
