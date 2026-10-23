"""
Enumeracion activa de buckets/storage accounts cloud mal configurados:
genera nombres candidatos derivados del dominio (nombre + sufijos tipicos
como backup/static/media/dev/staging...) y los prueba contra AWS S3, GCP
Cloud Storage y Azure Blob Storage mirando el CUERPO real de la respuesta
(XML de listado/error), no solo el status HTTP — eso evita falsos
positivos (un bucket que no existe tambien puede devolver 200/403 segun
el proveedor). Sin api keys: son endpoints publicos de los propios
proveedores cloud, cualquiera puede probarlos.
"""
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import http_client

CLOUD_ENUM_WORKERS = 20
CLOUD_ENUM_TIMEOUT = 6
MAX_BUCKET_CANDIDATES = 48

CLOUD_NAME_SUFFIXES = [
    "", "backup", "backups", "assets", "static", "media", "files", "data",
    "uploads", "public", "private", "dev", "development", "staging", "stage",
    "prod", "production", "test", "www", "cdn", "images", "img", "docs",
    "storage", "web", "app", "apps", "cloud", "internal", "corp", "old",
]

_HEADERS = {"User-Agent": "Mozilla/5.0"}


def _split_domain(d):
    parts = d.rsplit(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (d, "com")


def build_bucket_name_candidates(domain: str, max_candidates: int = MAX_BUCKET_CANDIDATES) -> list[str]:
    """Nombre del dominio (con y sin guiones) combinado con sufijos
    tipicos de bucket, en ambos ordenes (nombre-sufijo y sufijo-nombre)."""
    name, _ = _split_domain(domain)
    base_names = {name, name.replace("-", "")}
    candidates = set()
    for base in base_names:
        for suffix in CLOUD_NAME_SUFFIXES:
            if not suffix:
                candidates.add(base)
            else:
                candidates.add(f"{base}-{suffix}")
                candidates.add(f"{suffix}-{base}")
    return sorted(candidates)[:max_candidates]


def check_s3_bucket(name: str, timeout: int = CLOUD_ENUM_TIMEOUT) -> dict | None:
    """AWS S3: parsea el XML real de la respuesta.
    <ListBucketResult>+<Contents> = publico con contenido listable;
    <ListBucketResult> sin <Contents> = publico pero vacio;
    <Error><Code>NoSuchBucket</Code> = no existe (evita falso positivo);
    <Error><Code>AccessDenied</Code> = existe pero privado."""
    url = f"https://{name}.s3.amazonaws.com/"
    r = http_client.get(url, timeout=timeout)
    if r is None:
        return None
    body = r.text or ""

    if "<Code>NoSuchBucket</Code>" in body or "<Code>InvalidBucketName</Code>" in body:
        return None
    if "<Code>AccessDenied</Code>" in body or "<Code>AllAccessDisabled</Code>" in body:
        return {"provider": "AWS S3", "name": name, "url": url,
                "status": "Existe (acceso privado)", "severity": "info"}

    if "<Code>PermanentRedirect</Code>" in body or "<Code>TemporaryRedirect</Code>" in body:
        m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body)
        if m:
            endpoint = m.group(1).strip()
            r2 = http_client.get(f"https://{endpoint}/", timeout=timeout)
            if r2 is not None:
                body = r2.text or ""
                url = f"https://{endpoint}/"

    if "<ListBucketResult" in body:
        has_contents = "<Contents>" in body
        key_count = body.count("<Key>")
        if has_contents:
            return {"provider": "AWS S3", "name": name, "url": url,
                    "status": f"PUBLICO - listado abierto ({key_count} objeto(s) visibles)",
                    "severity": "critical"}
        return {"provider": "AWS S3", "name": name, "url": url,
                "status": "Existe - listado publico pero vacio", "severity": "info"}

    return None


def check_gcs_bucket(name: str, timeout: int = CLOUD_ENUM_TIMEOUT) -> dict | None:
    """GCP Cloud Storage: mismo criterio que S3 pero sobre el endpoint
    storage.googleapis.com."""
    url = f"https://storage.googleapis.com/{name}/"
    r = http_client.get(url, timeout=timeout)
    if r is None:
        return None
    body = r.text or ""

    if "<Code>NoSuchBucket</Code>" in body or "NoSuchBucket" in body:
        return None
    if ("AccessDenied" in body or "does not have storage.objects.list" in body
            or "<Code>UserProjectMissing</Code>" in body):
        return {"provider": "GCP Cloud Storage", "name": name, "url": url,
                "status": "Existe (acceso privado)", "severity": "info"}
    if "<ListBucketResult" in body:
        has_contents = "<Contents>" in body
        key_count = body.count("<Key>")
        if has_contents:
            return {"provider": "GCP Cloud Storage", "name": name, "url": url,
                    "status": f"PUBLICO - listado abierto ({key_count} objeto(s) visibles)",
                    "severity": "critical"}
        return {"provider": "GCP Cloud Storage", "name": name, "url": url,
                "status": "Existe - listado publico pero vacio", "severity": "info"}
    return None


def check_azure_blob(name: str, timeout: int = CLOUD_ENUM_TIMEOUT) -> dict | None:
    """Azure Blob Storage, en dos pasos: (1) la storage account tiene que
    existir de verdad (resolucion DNS de {name}.blob.core.windows.net,
    evita falsos positivos de cuentas inexistentes), (2) prueba de
    listado publico a nivel cuenta y en varios containers comunes
    (?restype=container&comp=list -> <EnumerationResults> si es publico)."""
    clean = re.sub(r"[^a-z0-9]", "", name.lower())
    if not (3 <= len(clean) <= 24):
        return None

    account_host = f"{clean}.blob.core.windows.net"
    base_url = f"https://{account_host}/"

    try:
        socket.gethostbyname(account_host)
    except OSError:
        return None

    common_containers = ["", "public", "files", "data", "backup", "assets", "media", "uploads", "$web"]
    for container in common_containers:
        if container:
            list_url = f"https://{account_host}/{container}?restype=container&comp=list"
        else:
            list_url = f"https://{account_host}/?comp=list"
        r = http_client.get(list_url, timeout=timeout)
        if r is None:
            continue
        body = r.text or ""
        if r.status_code == 200 and ("<EnumerationResults" in body or "<Blobs>" in body):
            blob_count = body.count("<Blob>")
            loc = f"container '{container}'" if container else "listado de containers"
            return {"provider": "Azure Blob Storage", "name": clean, "url": base_url,
                    "status": f"PUBLICO - {loc} ({blob_count} blob(s) visibles)",
                    "severity": "critical"}

    return {"provider": "Azure Blob Storage", "name": clean, "url": base_url,
            "status": "Existe (sin container publico detectado - revisar manualmente)", "severity": "info"}


def scan_cloud_buckets(domain: str) -> dict:
    """Enumera nombres candidatos de bucket/storage account derivados
    del dominio contra S3, GCS y Azure Blob, en paralelo (thread pool)
    para no tardar minutos por la cantidad de combinaciones."""
    candidates = build_bucket_name_candidates(domain)
    checks = [check_s3_bucket, check_gcs_bucket, check_azure_blob]
    tasks = [(fn, name) for name in candidates for fn in checks]

    findings = []
    with ThreadPoolExecutor(max_workers=CLOUD_ENUM_WORKERS) as executor:
        futures = {executor.submit(fn, name): (fn, name) for fn, name in tasks}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    return {"candidates_tested": len(candidates), "findings": findings}
