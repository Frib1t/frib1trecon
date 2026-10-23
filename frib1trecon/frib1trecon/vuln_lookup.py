"""
Busqueda de vulnerabilidades conocidas para el software/version detectado
en los metadatos de documentos (p.ej. "Microsoft Word 2010", "Apache
2.2.3"): cruza esos datos contra bases de exploits publicas en vez de
dejarlos como texto suelto en el informe.

Tres fuentes, todas opcionales y best-effort (si una falla, no esta
disponible o no tiene resultados, las demas siguen funcionando igual y el
escaneo nunca se rompe por esto):
  - NVD (National Vulnerability Database, NIST): API publica oficial de
    CVEs, sin api key para uso moderado (hay que espaciar las llamadas,
    el limite sin key es bajo).
  - ExploitDB via `searchsploit` (CLI local, ya viene en Kali o se instala
    con `apt install exploitdb`): usa la copia local de la base de datos,
    no hace ninguna peticion de red.
  - Sploitus: agregador publico de ExploitDB/Metasploit/Packet Storm. Sin
    api key documentada, usa el mismo endpoint JSON que su pagina web.
"""
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

EXPLOITDB_BIN = shutil.which("searchsploit")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SPLOITUS_API = "https://sploitus.com/search"

# la NVD sin api key limita a ~5 peticiones / 30s; se espacia cada llamada
# para no recibir 403/429 en un escaneo con varios documentos distintos.
_NVD_MIN_INTERVAL = 6.5
_last_nvd_call = 0.0


def search_nvd(query: str, timeout: int = 15, max_results: int = 5) -> list[dict]:
    """CVEs cuya descripcion/producto coincide con `query`."""
    global _last_nvd_call
    wait = _NVD_MIN_INTERVAL - (time.monotonic() - _last_nvd_call)
    if wait > 0:
        time.sleep(wait)
    _last_nvd_call = time.monotonic()

    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": max_results})
    req = urllib.request.Request(
        f"{NVD_API}?{params}",
        headers={"User-Agent": "frib1trecon-osint-tool/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return []

    results = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key)
            if metric_list:
                score = metric_list[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    break
        if not cve_id:
            continue
        results.append({
            "source": "NVD", "id": cve_id, "score": score,
            "summary": desc[:200], "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return results


def search_exploitdb_local(query: str, timeout: int = 15, max_results: int = 5) -> list[dict]:
    """Busca en la copia LOCAL de exploit-db via `searchsploit` (sin red)."""
    if not EXPLOITDB_BIN:
        return []
    try:
        out = subprocess.run(
            [EXPLOITDB_BIN, "--json", query],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(out.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return []

    results = []
    for item in (data.get("RESULTS_EXPLOIT") or [])[:max_results]:
        edb_id = item.get("EDB-ID", "")
        results.append({
            "source": "ExploitDB", "id": f"EDB-{edb_id}" if edb_id else "EDB-?",
            "score": None, "summary": item.get("Title", ""),
            "url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "",
        })
    return results


def search_sploitus(query: str, timeout: int = 15, max_results: int = 5) -> list[dict]:
    """Busca en Sploitus (agregador de ExploitDB/Metasploit/Packet Storm).
    Best-effort: cualquier fallo (cambio de formato, bloqueo, timeout) se
    traduce en lista vacia, nunca rompe el resto del escaneo."""
    payload = json.dumps({"type": "exploits", "sort": "default", "query": query, "page": 1}).encode()
    req = urllib.request.Request(
        SPLOITUS_API, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return []

    results = []
    for item in (data.get("exploits") or [])[:max_results]:
        title = item.get("title") or ""
        if not title:
            continue
        results.append({
            "source": "Sploitus", "id": item.get("id", "Sploitus"), "score": item.get("score"),
            "summary": title, "url": item.get("href", ""),
        })
    return results


def lookup_vulnerabilities(software: str, timeout: int = 15) -> list[dict]:
    """Junta los resultados de las 3 fuentes para un software/version dado.
    No lanza excepcion si alguna fuente falla; simplemente aporta menos."""
    results = []
    results.extend(search_nvd(software, timeout=timeout))
    results.extend(search_exploitdb_local(software, timeout=timeout))
    results.extend(search_sploitus(software, timeout=timeout))
    return results
