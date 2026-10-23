"""
Deteccion de typosquatting y domain squatting: genera cientos de variantes
tipograficamente parecidas al dominio (estilo dnstwist: omision/repeticion/
transposicion de letras, teclas adyacentes QWERTY, homoglifos, guiones,
cambio de vocal...) y de domain squatting clasico (mismo nombre en otros
TLDs, combosquatting con palabras tipicas de phishing como "login"/
"secure"/"verify"), y resuelve todas por DNS en paralelo para ver cuales
estan realmente registradas. Todo pasivo (solo resolucion DNS, ninguna
conexion al dominio sospechoso) y sin api keys.

Fuente extra opcional: dnstwister.report (API publica gratuita, sin key)
para sumar variantes que el motor propio no cubra.
"""
import itertools
import socket
import string
from concurrent.futures import ThreadPoolExecutor

import requests

HTTP_TIMEOUT = 15
DNS_RESOLVE_WORKERS = 30
MAX_TYPOSQUAT_CANDIDATES = 800
MAX_DOMAINSQUAT_CANDIDATES = 500

QWERTY_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "erfcxs", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}

COMMON_TLDS = [
    "com", "net", "org", "info", "biz", "co", "io", "xyz", "online", "site",
    "top", "club", "shop", "live", "app", "cloud", "digital", "world",
    "group", "network", "store", "tech", "vip", "cc", "tv", "me", "link",
    "email", "support", "download", "es", "eu", "dev", "pro", "company",
    "services", "solutions", "global", "web", "page", "space", "fun",
    "website", "host", "systems", "agency", "center", "team", "work",
    "us", "uk", "de", "fr", "org.es", "com.es", "one", "now",
]

HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "b": "8", "g": "9", "t": "7"}

VISUAL_SEQUENCES = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("m", "rn"), ("w", "vv")]

COMBOSQUAT_KEYWORDS = [
    "login", "secure", "support", "account", "verify", "pay", "billing",
    "portal", "help", "service", "update", "auth", "sso", "id", "online",
    "web", "app", "mobile", "cliente", "clientes", "oficial", "seguro",
    "acceso", "cuenta", "ayuda", "soporte", "pagos", "factura", "verificacion",
    "mail", "correo", "vpn", "intranet", "admin", "signin", "myaccount",
    "confirm", "recovery", "reset", "password", "seguridad", "banca",
]


def _split_domain(d):
    parts = d.rsplit(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (d, "com")


def generate_typosquat_candidates(domain: str, max_candidates: int = MAX_TYPOSQUAT_CANDIDATES) -> list[str]:
    """Motor de permutacion estilo dnstwist: omision, repeticion,
    transposicion, teclas adyacentes QWERTY, homoglifos numericos,
    secuencias visuales (rn/m, vv/w...), guiones, cambio de vocal,
    bitsquatting, plural/singular, etc."""
    name, tld = _split_domain(domain)
    candidates = set()

    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1:] + "." + tld)
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + "." + tld)
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        candidates.add("".join(swapped) + "." + tld)
    for i, ch in enumerate(name):
        for adj in QWERTY_ADJACENT.get(ch, ""):
            candidates.add(name[:i] + adj + name[i + 1:] + "." + tld)
    for i, ch in enumerate(name):
        for adj in QWERTY_ADJACENT.get(ch, ""):
            candidates.add(name[:i] + adj + name[i:] + "." + tld)
    for i, ch in enumerate(name):
        if ch in HOMOGLYPHS:
            candidates.add(name[:i] + HOMOGLYPHS[ch] + name[i + 1:] + "." + tld)
    homoglyph_positions = [i for i, ch in enumerate(name) if ch in HOMOGLYPHS]
    for i, j in itertools.combinations(homoglyph_positions, 2):
        variant = list(name)
        variant[i] = HOMOGLYPHS[name[i]]
        variant[j] = HOMOGLYPHS[name[j]]
        candidates.add("".join(variant) + "." + tld)
    for seq, repl in VISUAL_SEQUENCES:
        if seq in name:
            candidates.add(name.replace(seq, repl, 1) + "." + tld)
    if "-" in name:
        candidates.add(name.replace("-", "") + "." + tld)
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + "." + tld)
    for i in range(len(name) - 1):
        if name[i] == name[i + 1]:
            candidates.add(name[:i] + name[i + 1:] + "." + tld)
    vowels = "aeiou"
    for i, ch in enumerate(name):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    candidates.add(name[:i] + v + name[i + 1:] + "." + tld)
    for i in range(len(name) + 1):
        for ch in string.ascii_lowercase:
            candidates.add(name[:i] + ch + name[i:] + "." + tld)
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isalnum() and flipped != ch:
                candidates.add(name[:i] + flipped.lower() + name[i + 1:] + "." + tld)
    ext_homoglyphs = {"m": ["rn"], "w": ["vv"], "d": ["cl"], "cl": ["d"],
                       "nn": ["m"], "vv": ["w"], "q": ["g"], "g": ["q"]}
    for src, repls in ext_homoglyphs.items():
        if src in name:
            for rep in repls:
                candidates.add(name.replace(src, rep, 1) + "." + tld)
    if name.endswith("s"):
        candidates.add(name[:-1] + "." + tld)
    else:
        candidates.add(name + "s." + tld)
    for ch in string.ascii_lowercase:
        candidates.add(ch + name + "." + tld)
        candidates.add(name + ch + "." + tld)
    for extra_tld in ("com", "net", "org"):
        if extra_tld != tld:
            candidates.add(f"{name}-{tld}.{extra_tld}")
            candidates.add(f"{name}{tld}.{extra_tld}")

    candidates.discard(domain)
    candidates = {c for c in candidates if c.replace(".", "").replace("-", "").isalnum()}
    candidates = list(candidates)
    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]
    return candidates


def generate_domain_squatting_candidates(domain: str, max_candidates: int = MAX_DOMAINSQUAT_CANDIDATES) -> list[str]:
    """Domain squatting clasico: mismo nombre en otros TLDs, y
    combosquatting (nombre + palabra tipica de phishing dirigido como
    "login"/"secure"/"verify", en ambos ordenes y con/sin guion)."""
    name, original_tld = _split_domain(domain)
    candidates = set()

    for tld in COMMON_TLDS:
        if tld != original_tld:
            candidates.add(f"{name}.{tld}")

    squat_tlds = [original_tld] + [t for t in ("com", "net", "org") if t != original_tld][:2]
    for kw in COMBOSQUAT_KEYWORDS:
        for tld in squat_tlds:
            candidates.add(f"{name}-{kw}.{tld}")
            candidates.add(f"{kw}-{name}.{tld}")
            candidates.add(f"{name}{kw}.{tld}")
            candidates.add(f"{kw}{name}.{tld}")

    candidates.add(f"{name}-oficial.{original_tld}")
    candidates.add(f"{name}-online.{original_tld}")
    candidates.add(f"mi{name}.{original_tld}")
    candidates.add(f"{name}app.{original_tld}")
    candidates.add(f"grupo{name}.{original_tld}")
    candidates.add(f"{name}group.{original_tld}")

    candidates.discard(domain)
    candidates = list(candidates)
    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]
    return candidates


def resolve_candidates(candidates: list[str], on_candidate=None) -> list[dict]:
    """Resolucion DNS concurrente (thread pool) para poder testear
    cientos de variantes sin que tarde minutos por lookup secuencial.
    `on_candidate(domain, ip)` se llama por cada variante viva encontrada,
    para poder emitir progreso en tiempo real."""
    alive = []
    if not candidates:
        return alive

    def _try_resolve(c):
        try:
            ip = socket.gethostbyname(c)
            return (c, ip)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=DNS_RESOLVE_WORKERS) as executor:
        for result in executor.map(_try_resolve, candidates):
            if result:
                c, ip = result
                alive.append({"domain": c, "ip": ip})
                if on_candidate:
                    on_candidate(c, ip)

    return alive


def fetch_extra_variants(domain: str, timeout: int = HTTP_TIMEOUT) -> list[str]:
    """Variantes adicionales de una API publica gratuita de permutacion
    de dominios (dnstwister.report, sin api key). Si no responde o falla,
    devuelve lista vacia sin lanzar excepcion."""
    try:
        hexd = domain.encode("utf-8").hex()
        url = f"https://dnstwister.report/api/fuzz/{hexd}"
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return []
        data = r.json()
        return [item["domain"] for item in data.get("fuzzy_domains", [])
                if item.get("domain") and item["domain"] != domain]
    except Exception:
        return []
