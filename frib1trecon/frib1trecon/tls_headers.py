"""
Postura TLS/HTTPS y cabeceras de seguridad web: certificado (emisor,
caducidad, SAN, cifrado negociado), soporte de protocolos obsoletos
(TLSv1.0/1.1), y cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy) + flags de
cookies (Secure/HttpOnly). Todo pasivo: una conexion TLS normal y una
peticion HTTP GET normal, lo mismo que hace cualquier navegador.
"""
import datetime
import socket
import ssl

import requests

from . import http_client

HTTP_TIMEOUT = 10

# criticidad de cada cabecera si falta (solo para ordenar/priorizar en el
# informe, no cambia la logica de deteccion)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "alta", "Content-Security-Policy": "alta",
    "X-Content-Type-Options": "media", "X-Frame-Options": "media",
    "Referrer-Policy": "baja", "Permissions-Policy": "baja",
}


def check_tls(hostname: str, port: int = 443, timeout: int = HTTP_TIMEOUT) -> dict:
    """Certificado TLS (emisor, caducidad, SAN, cifrado) y si el servidor
    todavia acepta protocolos obsoletos (TLSv1.0/1.1, inseguros desde
    hace años)."""
    result = {"reachable": False, "certificate": {}, "issues": [], "protocols_supported": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["reachable"] = True
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                not_after = cert.get("notAfter")
                days_left = None
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                result["certificate"] = {
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject_cn": subject.get("commonName"), "san": san,
                    "not_after": not_after, "days_left": days_left,
                    "cipher_suite": cipher[0] if cipher else None,
                    "tls_version_negotiated": cipher[1] if cipher else None,
                }
                if days_left is not None:
                    if days_left < 0:
                        result["issues"].append("Certificado EXPIRADO")
                    elif days_left < 15:
                        result["issues"].append(f"Certificado expira en {days_left} dias (critico)")
                    elif days_left < 30:
                        result["issues"].append(f"Certificado expira en {days_left} dias")
                if cipher and any(w in cipher[0] for w in ("RC4", "DES", "MD5")):
                    result["issues"].append(f"Cifrado debil negociado: {cipher[0]}")
    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"Certificado invalido/no confiable: {e}")
    except Exception as e:
        result["issues"].append(f"No se pudo establecer conexion TLS: {e}")
        return result

    # prueba explicita de downgrade a protocolos obsoletos (TLSv1.0/1.1):
    # un servidor bien configurado los tiene deshabilitados y esto falla
    for name, tls_version in {
        "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
        "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
    }.items():
        if tls_version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["protocols_supported"][name] = True
                    result["issues"].append(f"El servidor todavia acepta {name} (obsoleto/inseguro)")
        except Exception:
            result["protocols_supported"][name] = False

    return result


def check_web_headers(hostname: str, scheme: str = "https", timeout: int = HTTP_TIMEOUT) -> dict:
    """Cabeceras de seguridad HTTP presentes/ausentes y flags de cookies
    (Secure/HttpOnly)."""
    result = {"reachable": False, "headers_present": {}, "missing": [],
              "cookies_issues": [], "final_url": None, "status_code": None,
              "server_banner": None, "powered_by": None}
    url = f"{scheme}://{hostname}"
    r = http_client.get(url, timeout=timeout, allow_redirects=True)
    if r is None:
        result["conn_error"] = "sin respuesta"
        return result
    try:
        result["reachable"] = True
        result["status_code"] = r.status_code
        result["final_url"] = r.url
        result["server_banner"] = r.headers.get("Server")
        result["powered_by"] = r.headers.get("X-Powered-By")
        for header, crit in SECURITY_HEADERS.items():
            if header in r.headers:
                result["headers_present"][header] = r.headers[header]
            else:
                result["missing"].append({"header": header, "criticidad": crit})
        for cookie in r.cookies:
            flags = []
            if not cookie.secure:
                flags.append("sin flag Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("sin flag HttpOnly")
            if flags:
                result["cookies_issues"].append(f"{cookie.name}: {', '.join(flags)}")
    except requests.RequestException as e:
        result["conn_error"] = str(e)
    return result
