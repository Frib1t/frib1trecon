"""
Informe "Cyber Health Check" en formato de entrega al cliente: portada,
indice, metodologia, resumen ejecutivo con el modelo ponderado de 6
categorias, y una seccion por categoria con tablas de datos y
recomendaciones. Se genera desde los mismos Findings que el resto de
informes (no consulta nada nuevo).

El modelo de riesgo de este informe (6 categorias, pesos 20/20/20/15/20/5 y
puntos por subcategoria) es distinto al de 7 categorias que muestran los
informes tecnicos (report.compute_risk_score): este es el que se entrega al
cliente.
"""
import io
import re
import socket
from datetime import datetime

from pathlib import Path

from .docx_charts import embed_risk_charts
from .ports_services import criticidad
from .report import _TLS_CERT_ISSUE_MARKERS, compute_risk_score, leak_detail

DEFAULT_LOGO = Path(__file__).resolve().parent.parent / "assets" / "frib1trecon_logo.png"

CATEGORY_WEIGHTS = {
    "compromised": 20.0, "controls": 20.0, "exposure": 20.0,
    "tech_vuln": 15.0, "identity": 20.0, "brand": 5.0,
}

CATEGORY_LABELS = {
    "compromised": "1. Compromised Systems",
    "controls": "2. Security Controls",
    "exposure": "3. Exposure Management",
    "tech_vuln": "4. Technology & Vulnerability Exposure",
    "identity": "5. Identity & User Exposure",
    "brand": "6. Brand Reputation",
}

SUBCATEGORIES = {
    "compromised": [("botnet", "Botnet Infections", 5.0), ("spam", "Spam Propagation", 5.0),
                    ("malwarec2", "Malware Hosting / C2", 5.0), ("blacklist", "Domain / IP Blacklist", 5.0)],
    "controls": [("email", "Email Security", 5.0), ("dns", "DNS Security", 5.0),
                 ("tls", "TLS Security", 5.0), ("web", "Web Security", 5.0)],
    "exposure": [("open_ports", "Open Ports", 5.0), ("exposed_services", "Exposed Services", 5.0),
                 ("server_software", "Server Software", 5.0), ("cloud", "Cloud Exposure", 5.0)],
    "tech_vuln": [("cves", "Known CVEs", 7.5), ("outdated", "Outdated Software", 7.5)],
    "identity": [("employee_email", "Employee Email Exposure", 20 / 3),
                 ("exposed_creds", "Exposed Credentials", 20 / 3),
                 ("file_sharing", "File Sharing", 20 / 3)],
    "brand": [("domain_rep", "Domain Reputation", 1.25), ("ip_rep", "IP Reputation", 1.25),
              ("domain_squat", "Domain Squatting", 1.25), ("typo_squat", "Typosquatting", 1.25)],
}

PHRASES = {
    "methodology": (
        "El Cybersecurity Health Check es una evaluación de seguridad basada en técnicas de "
        "reconocimiento pasivo, complementado con verificación no intrusiva de exposición de "
        "activos cloud. El análisis se realiza mediante fuentes de información públicas y servicios "
        "de terceros, sin interacción directa ni pruebas intrusivas sobre la infraestructura. La "
        "evaluación refleja la superficie de exposición que un potencial atacante externo podría "
        "identificar."),
    "methodology_intro": "El Health Check se estructura en torno a seis categorías de análisis:",
    "methodology_items": [
        ("Compromised Systems:", "Identificación de activos comprometidos y actividad maliciosa."),
        ("Exposure Management:", "Identificación de activos, servicios y superficie de ataque expuestos."),
        ("Security Controls:", "Evaluación de las configuraciones y mecanismos de protección visibles desde el exterior."),
        ("Identity & User Exposure:", "Identificación de credenciales e información expuestas."),
        ("Technology & Vulnerability Exposure:", "Detección de tecnologías, versiones y vulnerabilidades conocidas (CVE)."),
        ("Brand Reputation:", "Detección de riesgos de reputación y posibles casos de suplantación de marca."),
    ],
    "methodology_note": (
        "* Servicio de carácter informativo. No sustituye auditorías técnicas ni pruebas de penetración. "
        "Para una visión completa se recomienda complementar con pentesting, auditorías de configuración "
        "o revisiones internas."),
    "compromised": (
        "Los eventos de infección por botnet indican que se observó que dispositivos en la red de una "
        "empresa participaban en botnets como bots o servidores de comando y control. Las botnets se "
        "pueden utilizar para filtrar secretos corporativos e información confidencial de los clientes, "
        "reutilizar recursos de la empresa para actividades ilegales y servir como conductos para otras "
        "infecciones."),
    "compromised_blacklist": (
        "La inclusión en listas negras de reputación indica que se ha detectado actividad maliciosa, "
        "fraudulenta o flujos de spam desde los dominios o IPs de la empresa. Al no contar con una "
        "monitorización proactiva, estas amenazas operan de forma oculta, destruyendo la reputación "
        "digital corporativa y paralizando la comunicación por correo electrónico antes de que la "
        "organización pueda percatarse y reaccionar internamente."),
    "compromised_recs": (
        "Es aconsejable revisar los dominios asociados para evitar futuros bloqueos y garantizar que los "
        "correos lleguen a la bandeja de entrada. Si se trata de un servicio de hosting, es importante "
        "solicitar al proveedor la limpieza o cambio de las direcciones IP afectadas en las listas negras. "
        "Asimismo, se debe coordinar la revisión de los registros de acceso (logs) y un análisis de "
        "seguridad en la plataforma para descartar la presencia de código malicioso o la suplantación de "
        "la identidad de la empresa."),
    "email": (
        "Una configuración insuficiente de los mecanismos de seguridad del correo electrónico (SPF, DKIM y "
        "DMARC) puede permitir que un atacante falsifique correos electrónicos haciéndolos pasar por "
        "comunicaciones legítimas del dominio corporativo. SPF autoriza qué servidores pueden enviar correo "
        "en nombre de la organización; DKIM incorpora una firma criptográfica que garantiza la integridad del "
        "mensaje; y DMARC establece la política que debe aplicar el servidor receptor cuando las validaciones "
        "anteriores no se superan."),
    "dns": (
        "DNSSEC es un protocolo que utiliza cifrado de clave pública para autenticar servidores DNS. Se verifica "
        "si la empresa está utilizando DNSSEC y si está configurado de manera efectiva."),
    "tls": (
        "Los certificados TLS/SSL permiten cifrar las comunicaciones entre los usuarios y los servicios expuestos "
        "a Internet, garantizando la autenticidad de los servidores y protegiendo la confidencialidad e integridad "
        "de la información transmitida. Se analiza la validez, configuración y fortaleza de los certificados "
        "TLS/SSL para verificar que cumplen con las mejores prácticas de seguridad."),
    "web": (
        "Las cabeceras HTTP de seguridad (HTTP Security Headers) son instrucciones que un servidor web envía al "
        "navegador junto con cada respuesta HTTP. Su objetivo es indicar al navegador cómo debe comportarse para "
        "proteger la aplicación frente a determinados ataques. No evitan por sí mismas las vulnerabilidades, pero "
        "añaden una capa adicional de protección y reducen la superficie de ataque."),
    "controls_recs": (
        "Para mitigar las carencias identificadas en los controles de seguridad perimetral, se recomienda configurar "
        "las políticas DMARC en modo de rechazo (reject) y aplicar la extensión DNSSEC en los dominios. Asimismo, es "
        "fundamental reforzar la seguridad del cifrado en los servidores para garantizar que se utilicen conexiones "
        "seguras y actualizadas, junto con la implementación de cabeceras de seguridad HTTP faltantes para reducir la "
        "superficie de exposición ante ataques desde el navegador de los usuarios."),
    "exposure": (
        "Esta sección evalúa los puertos y servicios expuestos directamente a Internet. Si bien la apertura de ciertos "
        "puertos es indispensable para la operativa del negocio, la presencia de servicios innecesarios o con "
        "configuraciones deficientes amplía la superficie de ataque, facilitando accesos no autorizados a la red "
        "corporativa. Asimismo, el análisis identifica el software activo y sus versiones en los servidores expuestos. "
        "Esto permite detectar tecnologías obsoletas o sin soporte del fabricante, cuya exposición incrementa "
        "significativamente el riesgo de explotación por parte de un atacante."),
    "cloud": (
        "Es el proceso que identifica configuraciones erróneas o almacenamiento de datos en la nube (como contenedores "
        "de AWS, Azure o Google Cloud) que han quedado accesibles públicamente sin protección. Su supervisión es "
        "fundamental, ya que las fugas de información en entornos cloud suelen deberse a fallos de configuración humana."),
    "exposure_recs": (
        "Con el objetivo de minimizar la superficie de ataque, se recomienda restringir el acceso a los puertos "
        "identificados que no requieran exposición externa o, en su defecto, implementar una lista blanca (White list). "
        "Asimismo, es fundamental minimizar la información de identificación (banners) que revela información acerca del "
        "software y las versiones utilizadas, reduciendo así la visibilidad para potenciales atacantes."),
    "tech": (
        "Este análisis identifica posibles vulnerabilidades conocidas (CVEs) y exploits públicos asociados a los servicios "
        "expuestos a Internet, a partir de las tecnologías y versiones detectadas. La presencia de software con "
        "vulnerabilidades públicas puede incrementar el riesgo de explotación por parte de potenciales atacantes, por lo "
        "que resulta fundamental mantener un proceso continuo de actualización y gestión de vulnerabilidades."),
    "tech_recs": (
        "Para mitigar el riesgo asociado a las vulnerabilidades identificadas en los servicios publicados, resulta "
        "prioritario actualizar todo el software a su última versión estable conocida. Adicionalmente, es necesario "
        "revisar los puertos abiertos en las distintas direcciones IP para validar si son necesarios de exposición pública."),
    "identity": (
        "Este análisis identifica direcciones de correo electrónico corporativas expuestas en fuentes públicas, repositorios "
        "abiertos y filtraciones de datos. La disponibilidad de estas cuentas incrementa la superficie de exposición de la "
        "organización, facilitando campañas de phishing dirigido (Spear Phishing), ingeniería social y ataques de fuerza "
        "bruta orientados a obtener acceso no autorizado a los sistemas corporativos."),
    "creds": (
        "Las credenciales expuestas indican si los empleados de una empresa vieron su información divulgada como resultado "
        "de una violación de datos divulgada públicamente. Muchos sitios web no validan las direcciones de correo "
        "electrónico, lo que dificulta afirmar que ciertos registros expuestos estén asociados con los empleados de una "
        "empresa. No se prueba que las credenciales expuestas sean válidas, para preservar la confianza empresarial."),
    "file_sharing": (
        "Análisis destinado a localizar archivos corporativos (como PDF, Word o Excel) que han quedado indexados públicamente "
        "en internet o que contienen \"metadatos\" internos. Los metadatos revelan nombres de empleados, rutas de servidores "
        "internos, versiones de software o sistemas operativos utilizados por la organización."),
    "identity_recs": (
        "Tras detectar credenciales comprometidas y archivos sensibles expuestos en redes públicas, es prioritario restablecer "
        "de inmediato las contraseñas de las cuentas afectadas, forzar la autenticación multifactor (MFA), así como revisar y "
        "retirar la información confidencial que no deba estar expuesta al público."),
    "brand_reputation": (
        "Es el análisis que verifica si el dominio de la empresa ha sido incluido en listas de bloqueo (blacklists) globales o "
        "bases de datos de inteligencia de amenazas debido a actividades sospechosas, como el envío de spam, alojamiento de "
        "malware o campañas de phishing. Mantener una buena reputación es crucial para asegurar que los correos legítimos de la "
        "organización se entreguen correctamente y que su sitio web no sea bloqueado por los navegadores de sus clientes."),
    "squatting": (
        "Práctica maliciosa de registrar dominios muy similares al nombre de la empresa legítima (utilizando variaciones "
        "ortográficas, otros guiones o extensiones diferentes) con el fin de suplantar la identidad de la marca. Los atacantes "
        "compran estos dominios engañosos para orquestar estafas financieras, confundir a los clientes o lanzar campañas "
        "altamente dirigidas de phishing y fraude electrónico."),
    "typosquat": (
        "Técnica de suplantación basada específicamente en registrar dominios que aprovechan los errores ortográficos o de "
        "tecleo más comunes que cometen los usuarios al escribir el nombre de la empresa en el navegador (por ejemplo, omitir "
        "una letra, intercambiar su orden o duplicar caracteres). Los ciberdelincuentes utilizan estos sitios web \"trampa\" "
        "para interceptar tráfico legítimo, robar credenciales o infectar con malware a los usuarios."),
    "brand_recs": (
        "Ante la presencia de direcciones IP con reputación negativa y la detección de múltiples dominios registrados con "
        "variaciones de la marca (typosquatting y domain squatting), resulta prioritario gestionar la limpieza de las IP en las "
        "listas de reputación, así como valorar la tramitación de retiradas sobre los dominios que sean potencialmente maliciosos."),
    "strategy": [
        ("Gestión de credenciales e identidades:", "Forzar el cambio urgente de las contraseñas corporativas detectadas en "
         "filtraciones públicas, implantar la autenticación de doble factor (MFA) en los accesos corporativos y revisar la "
         "documentación pública para evitar exponer nombres o datos internos."),
        ("Blindaje de la infraestructura expuesta:", "Ocultar los servicios y herramientas de gestión para que no sean accesibles "
         "públicamente desde Internet (restringiéndolas tras una VPN) y actualizar urgentemente los servidores web con fallos de seguridad."),
        ("Protección del correo electrónico:", "Configurar los mecanismos de autenticación de correo (DMARC y DKIM) para evitar que "
         "terceros puedan suplantar la identidad de la empresa y enviar correos engañosos a clientes o proveedores."),
        ("Protección de endpoint y supervisión:", "Desplegar herramientas avanzadas de detección y respuesta (EDR) en los equipos "
         "corporativos y respaldar la infraestructura con la supervisión continua de un equipo especializado (CSIRT). Como medida "
         "complementaria, resulta oportuno realizar auditorías de hacking ético para validar la eficacia real de los mecanismos de "
         "detección y respuesta."),
        ("Defensa de marca y prueba de resistencia:", "Evaluar la retirada de dominios fraudulentos que usan nombres similares a la "
         "marca para engañar a usuarios (typosquatting) y realizar pruebas periódicas de simulación de phishing para medir la "
         "concienciación de la plantilla frente a ataques de suplantación."),
    ],
}


def _num(text: str, pattern: str) -> int:
    m = re.search(pattern, text or "")
    return int(m.group(1)) if m else 0


def _port_number(f) -> int | None:
    m = re.match(r"Puerto (\d+)/", f.dork_name or "")
    return int(m.group(1)) if m else None


def _host(f, domain: str) -> str:
    return f.host or domain


def _flags(findings, domain: str) -> dict:
    """Banderas de riesgo del modelo de 6 categorias, derivadas de los Findings.
    Limitacion: no hay clasificacion botnet/spam/malware por IP; se usan como
    aproximacion AbuseIPDB (score>=50) y VirusTotal (malicioso>0)."""
    rep = [f for f in findings if f.category == "reputation"]
    ip_rep = [f for f in rep if f.title and re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title)]
    domain_rep = [f for f in rep if f not in ip_rep]
    dns = [f for f in findings if f.category == "dns"]
    tls = [f for f in findings if f.category == "tls"]
    ports = [f for f in findings if f.category == "ports" and _port_number(f)]
    vulns = [f for f in findings if f.category == "vuln"]
    leaks = [f for f in findings if f.category in ("leak", "bucket") or f.secrets]
    squat = [f for f in findings if f.category == "typosquat" and "squat" in (f.dork_name or "").lower()]
    typo = [f for f in findings if f.category == "typosquat" and "typo" in (f.dork_name or "").lower()]

    def ip_flagged(f):
        return _num(f.note, r"confianza de abuso=(\d+)%") >= 50 or _num(f.note, r"malicioso=(\d+)") > 0

    flags = {
        "botnet": any(_num(f.note, r"confianza de abuso=(\d+)%") >= 50 for f in rep),
        "blacklist": any(ip_flagged(f) for f in rep),
        "email": any(f.dork_name.startswith("Autenticacion de correo") and
                     (f.title != "Sin problemas detectados" or "Sin selectores DKIM" in (f.note or ""))
                     for f in dns),
        "dns": any(f.category == "leak" and "AXFR" in f.dork_name for f in findings)
               or any(f.dork_name == "DNSSEC" and f.title == "No habilitado" for f in dns)
               or any(re.search(r"CAA: -", f.note or "") for f in dns),
        "tls": any(f.dork_name == "Certificado TLS" and
                   (f.title == "No se pudo conectar por HTTPS" or any(m in (f.note or "") for m in _TLS_CERT_ISSUE_MARKERS))
                   for f in tls),
        "web": any(f.dork_name == "Cabeceras de seguridad HTTP" and f.title != "Todas presentes" for f in tls),
        "open_ports": any(criticidad(_port_number(f)) == "high" for f in ports),
        "exposed_services": any(criticidad(_port_number(f)) == "medium" for f in ports),
        "server_software": any(re.search(r"\d+\.\d+", f.title or "") for f in ports),
        "cloud": any(f.category == "bucket" for f in findings),
        "cves": any("CVE-" in (f.note or "") for f in vulns),
        "outdated": any(f.dork_name.startswith("Fin de soporte") for f in vulns),
        "employee_email": any(f.category == "email" for f in findings),
        "exposed_creds": any(f.secrets for f in leaks),
        "file_sharing": any(f.category == "document" and (f.author or f.software) for f in findings),
        "domain_rep": any(_num(f.note, r"malicioso=(\d+)") > 0 for f in domain_rep),
        "ip_rep": any(ip_flagged(f) for f in ip_rep),
        "domain_squat": any(f.note and f.note != "Ninguna variante registrada." for f in squat),
        "typo_squat": any(f.note and f.note != "Ninguna variante registrada." for f in typo),
    }
    return flags


def compute_health(findings, domain: str) -> dict:
    """Misma puntuacion que los informes tecnicos (7 categorias, report.compute_risk_score)."""
    risk = compute_risk_score(findings)
    cats = {}
    for item in risk["breakdown"]:
        cats[item["key"]] = {"label": item["label"], "weight": item["weight"],
                             "points": item["weight"] if item["triggered"] else 0.0,
                             "flagged": [item["label"]] if item["triggered"] else []}
    return {"total": risk["score"], "level": risk["level_label"].upper(), "categories": cats}



def _fmt(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s.replace(".", ",")


def _cve_rows(vulns, domain):
    """(identificador, producto, puerto/host, estado) desde los Findings de vulnerabilidades."""
    rows = []
    for f in vulns:
        if f.dork_name.startswith("Fin de soporte"):
            continue
        product = f.dork_name.replace("Vulnerabilidades conocidas: ", "")
        for line in (f.note or "").splitlines():
            m = re.match(r"\[(NVD|ExploitDB|Sploitus)\]\s+(.+?)(?:\s+\(|:\s)", line)
            if not m:
                continue
            source, ident = m.group(1), m.group(2)
            if source == "NVD":
                estado = "Verificado (NVD)"
            elif source == "ExploitDB":
                estado = "PoC disponible (ExploitDB)"
            else:
                estado = "PoC disponible (Sploitus)"
            rows.append((ident, product, _host(f, domain), estado))
    return rows


def _unique_ips(findings):
    ips = {}
    for f in findings:
        m = re.search(r"tcp://(\d+\.\d+\.\d+\.\d+)", f.url or "")
        if m:
            ips.setdefault(m.group(1), set()).add(f.host or "")
    return ips


def _action_items(findings, domain: str, cap: int = 8) -> tuple[list[str], list[str]]:
    """Plan de accion inmediata: separa los hallazgos en 'sanear ya'
    (critico, concreto, con remediacion clara) y 'revisar' (menos
    urgente, requiere valoracion). Derivado de los mismos Findings que ya
    alimentan el resto del informe, no es una categoria nueva."""
    sanear, revisar = [], []
    for f in findings:
        host = _host(f, domain)
        if f.secrets:
            sanear.append(f"Credencial expuesta en {f.url or host}: rotarla de inmediato.")
        elif f.category == "bucket":
            sanear.append(f"Bucket cloud publico con listado abierto: {f.title or f.dork_name} ({f.url}).")
        elif f.category == "leak" and "AXFR" in (f.dork_name or ""):
            sanear.append(f"Transferencia de zona (AXFR) permitida en {host}: expone toda la zona DNS.")
        elif f.category == "leak" and (f.dork_name or "").startswith("Fichero compartido expuesto"):
            sanear.append(f"Fichero sensible historico aun accesible: {f.url}.")
        elif f.category == "dns" and f.dork_name.startswith("Autenticacion de correo") and f.title != "Sin problemas detectados":
            revisar.append(f"Autenticacion de correo incompleta en {host}: {f.title}.")
        elif f.category == "tls" and f.dork_name == "Certificado TLS" and any(
                m in (f.note or "") for m in _TLS_CERT_ISSUE_MARKERS):
            revisar.append(f"Configuracion TLS a revisar en {host}.")
        elif f.category == "tls" and f.dork_name == "Cabeceras de seguridad HTTP" and f.title != "Todas presentes":
            revisar.append(f"Cabeceras de seguridad HTTP ausentes en {f.url or host}.")
        elif f.category == "vuln" and f.dork_name.startswith("Fin de soporte"):
            revisar.append(f"Software sin soporte (EOL): {f.dork_name.replace('Fin de soporte (EOL): ', '')}.")
        elif f.category == "typosquat" and f.note and f.note != "Ninguna variante registrada.":
            revisar.append(f"{f.dork_name}: {f.title}.")
        elif f.category == "reputation" and (
                _num(f.note, r"confianza de abuso=(\d+)%") >= 50 or _num(f.note, r"malicioso=(\d+)") > 0):
            revisar.append(f"Reputacion negativa detectada para {f.title}.")
    # dedup conservando orden, luego tope para no desbordar la pagina
    sanear = list(dict.fromkeys(sanear))[:cap]
    revisar = list(dict.fromkeys(revisar))[:cap]
    return sanear, revisar


def _find_logo(logos_dir, basename):
    """Busca <logos_dir>/<basename>.{png,jpg,jpeg} (en ese orden). None si no
    hay carpeta o no existe ninguno de los tres. SVG no se soporta: Word no
    lo incrusta de forma nativa."""
    if not logos_dir:
        return None
    logos_dir = Path(logos_dir)
    for ext in (".png", ".jpg", ".jpeg"):
        candidate = logos_dir / f"{basename}{ext}"
        if candidate.exists():
            return candidate
    return None


_FONT_PATHS_BOLD = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
)
_FONT_PATHS_REGULAR = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
)


def _load_font(paths, size):
    from PIL import ImageFont
    for p in paths:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except OSError:
                continue
    return ImageFont.load_default()  # degrada a la fuente bitmap de PIL si no hay TTF


def _risk_rgb(total: float) -> tuple[int, int, int]:
    """Mismos umbrales/colores que report.risk_level_for y docx_charts.LEVELS."""
    if total < 20:
        return (0x1F, 0x8F, 0x62)
    if total < 40:
        return (0xD1, 0x8A, 0x00)
    if total < 65:
        return (0xE5, 0x64, 0x0B)
    return (0xC9, 0x34, 0x3A)


def _generate_cover_image(domain: str, empresa: str | None, total: float, level_label: str,
                           title_label: str = "INFORME TÉCNICO",
                           subtitle_label: str = "Cyber Health Check") -> io.BytesIO:
    """Portada generada por el propio frib1trecon (sin depender de ninguna
    imagen de terceros): fondo blanco, logo y texto centrados, mismo
    criterio visual limpio que la portada del PDF LaTeX (nada de panel
    navy a toda pagina — eso quedaba demasiado pesado/'grueso' en
    comparacion). Solo se usa cuando el usuario NO sube su propia imagen
    de portada via logos_dir. Reutilizada tambien por report.py para la
    portada de informe.docx/informe_master.docx, pasando `title_label`/
    `subtitle_label` propios para no llamar "Cyber Health Check" al
    informe tecnico detallado."""
    from PIL import Image, ImageDraw

    W, H = 1654, 2339  # proporcion A4 a ~200dpi
    img = Image.new("RGB", (W, H), (0xFF, 0xFF, 0xFF))
    draw = ImageDraw.Draw(img)
    cx = W // 2

    def centered(y, text, font, fill):
        w = font.getlength(text)
        draw.text((cx - w / 2, y), text, font=font, fill=fill)
        return y

    y = int(H * 0.22)
    try:
        logo = Image.open(DEFAULT_LOGO).convert("RGBA")
        logo_w = int(W * 0.22)
        logo_h = int(logo_w * logo.height / logo.width)
        logo = logo.resize((logo_w, logo_h))
        img.paste(logo, (cx - logo_w // 2, y), logo)
        y += logo_h + 70
    except OSError:
        pass

    if empresa:
        f_empresa = _load_font(_FONT_PATHS_BOLD, 30)
        centered(y, empresa.upper(), f_empresa, (0x1F, 0x8F, 0x62))
        y += 55

    f_label = _load_font(_FONT_PATHS_BOLD, 34)
    centered(y, title_label, f_label, (0x16, 0x21, 0x3F))
    y += 50

    size_t = 64
    f_title = _load_font(_FONT_PATHS_BOLD, size_t)
    max_title_w = W * 0.85
    while size_t > 32 and f_title.getlength(subtitle_label) > max_title_w:
        size_t -= 4
        f_title = _load_font(_FONT_PATHS_BOLD, size_t)
    centered(y, subtitle_label, f_title, (0x0B, 0x1B, 0x4D))
    y += size_t + 26

    size = 44
    f_domain = _load_font(_FONT_PATHS_BOLD, size)
    max_width = W * 0.8
    while size > 22 and f_domain.getlength(domain) > max_width:
        size -= 2
        f_domain = _load_font(_FONT_PATHS_BOLD, size)
    centered(y, domain, f_domain, (0x16, 0x21, 0x3F))
    y += size + 260

    # caja de confidencialidad, igual criterio que la portada LaTeX
    f_conf = _load_font(_FONT_PATHS_REGULAR, 22)
    conf_lines = [
        "Este documento es confidencial y contiene información sensible",
        "sobre la superficie de exposición pública de la organización auditada.",
        "No debe imprimirse ni compartirse con terceros ajenos a la organización.",
    ]
    box_w = int(W * 0.72)
    box_h = 36 * len(conf_lines) + 40
    box_x = cx - box_w // 2
    draw.rounded_rectangle([box_x, y, box_x + box_w, y + box_h], radius=8,
                            outline=(0xC9, 0x34, 0x3A), width=2, fill=(0xFC, 0xE8, 0xE9))
    ty = y + 20
    for line in conf_lines:
        centered(ty, line, f_conf, (0x8A, 0x1F, 0x24))
        ty += 36
    y += box_h + 170

    # chip con el nivel de riesgo real del escaneo
    chip_text = f"  Nivel de riesgo: {total:.0f}% — {level_label}  "
    f_chip = _load_font(_FONT_PATHS_BOLD, 30)
    chip_w = int(f_chip.getlength(chip_text)) + 10
    chip_x = cx - chip_w // 2
    draw.text((chip_x, y), chip_text, font=f_chip, fill=_risk_rgb(total))
    y += 70

    f_date = _load_font(_FONT_PATHS_REGULAR, 24)
    centered(y, datetime.now().strftime("%d-%m-%Y"), f_date, (0x6B, 0x77, 0x94))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def build_cyber_health_docx(findings, domain: str, path, results: dict | None = None,
                            empresa: str | None = None, logo_path=DEFAULT_LOGO,
                            logos_dir=None):
    """Genera el informe Cyber Health Check en DOCX. `results` (host -> findings)
    se usa en informes maestro para el listado de hosts y la tabla de discovery.

    `logos_dir`: carpeta opcional con hasta tres imagenes (png/jpg/jpeg) que
    personalizan el informe, buscadas por nombre fijo:
      - portada.{png,jpg,jpeg}   -> imagen de portada (sustituye al logo generico)
      - cliente.{png,jpg,jpeg}   -> logo del cliente, esquina superior derecha
      - pentester.{png,jpg,jpeg} -> logo propio/del pentester, esquina superior
                                     izquierda (si no esta, se usa `logo_path`)
    Cualquiera de los tres que falte simplemente no aparece."""
    import docx
    from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor, Inches, Cm

    cover_image = _find_logo(logos_dir, "portada")
    client_logo = _find_logo(logos_dir, "cliente")
    pentester_logo = _find_logo(logos_dir, "pentester") or logo_path

    # Paleta alineada con la plantilla de referencia (misma que ya usan
    # docx_charts.py/latex_report.py): NAVY/INK/RED/GREEN/MUTED/BLUE son
    # los mismos hex exactos, para que el informe DOCX, los graficos
    # nativos y el informe LaTeX se vean como el mismo sistema visual.
    NAVY = RGBColor(0x0B, 0x1B, 0x4D)
    NAVY_HEX = "0B1B4D"
    INK = RGBColor(0x16, 0x21, 0x3F)
    GREEN = RGBColor(0x1F, 0x8F, 0x62)
    RED = RGBColor(0xC9, 0x34, 0x3A)
    MUTED = RGBColor(0x6B, 0x77, 0x94)
    BLUE = RGBColor(0x2F, 0x6B, 0xFF)
    WHITE = RGBColor(0xFF, 0xFF, 0xFF)
    LIGHT = "F5F7FC"
    ALERT_BG = "FCE8E9"
    OK_BG = "E3F6EE"
    INFO_BG = "EEF3FF"
    HEADING_FONT = "Poppins"  # Word sustituye por una fuente similar si no esta instalada

    health = compute_health(findings, domain)
    total_txt = _fmt(health["total"])

    d = docx.Document()
    for s in d.sections:
        s.left_margin = s.right_margin = Cm(2.2)
        s.top_margin = s.bottom_margin = Cm(2.2)
    base = d.styles["Normal"]
    base.font.name = "Calibri"
    base.font.size = Pt(10)

    def shade(cell, hex_color):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        tcPr.append(shd)

    def shade_paragraph(paragraph, hex_color):
        pPr = paragraph._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        pPr.append(shd)

    def heading(text, level=1):
        """Nivel 1: banda navy de ancho completo (como la plantilla de
        referencia), texto blanco en negrita. Nivel 2/3: texto en negrita
        color navy/ink, sin banda (para no saturar la pagina de bloques
        de color)."""
        p = d.add_paragraph()
        p.paragraph_format.space_before = Pt(12 if level == 1 else 8)
        p.paragraph_format.space_after = Pt(6 if level == 1 else 4)
        r = p.add_run(text)
        r.bold = True
        r.font.name = HEADING_FONT
        if level == 1:
            shade_paragraph(p, NAVY_HEX)
            pPr = p._p.get_or_add_pPr()
            ind = OxmlElement("w:ind")
            ind.set(qn("w:left"), "120")
            ind.set(qn("w:right"), "120")
            pPr.append(ind)
            spacing = OxmlElement("w:spacing")
            spacing.set(qn("w:before"), "40")
            spacing.set(qn("w:after"), "40")
            spacing.set(qn("w:line"), "240")
            spacing.set(qn("w:lineRule"), "auto")
            pPr.append(spacing)
            r.font.size = Pt(12.5)
            r.font.color.rgb = WHITE
        elif level == 2:
            r.font.size = Pt(11.5)
            r.font.color.rgb = NAVY
        else:
            r.font.size = Pt(10.5)
            r.font.color.rgb = INK
        return p

    def section_badge(keys):
        """Tira de indicador bajo el banner de seccion: peso combinado de
        riesgo (suma real de report.compute_risk_score para las
        categorias que cubre esta seccion, no un numero inventado) +
        estado OK/A REVISAR segun si alguna de ellas disparo de verdad."""
        weight = sum(health["categories"][k]["weight"] for k in keys)
        triggered = any(health["categories"][k]["points"] for k in keys)
        t = d.add_table(rows=1, cols=2)
        no_border(t)
        left, right = t.rows[0].cells
        left.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        shade(left, NAVY_HEX)
        lp = left.paragraphs[0]
        lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        lr = lp.add_run(f"{_fmt(weight)}%")
        lr.bold = True
        lr.font.size = Pt(15)
        lr.font.color.rgb = WHITE
        lr.font.name = HEADING_FONT
        lp2 = left.add_paragraph()
        lp2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        lr2 = lp2.add_run("PESO DE RIESGO")
        lr2.font.size = Pt(6.5)
        lr2.font.color.rgb = RGBColor(0xB9, 0xC6, 0xEE)
        shade(right, ALERT_BG if triggered else OK_BG)
        right.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        rp = right.paragraphs[0]
        rr = rp.add_run("⚠ A REVISAR" if triggered else "✓ OK")
        rr.bold = True
        rr.font.color.rgb = RED if triggered else GREEN
        rr.font.size = Pt(11)
        t.rows[0].cells[0].width = Inches(1.1)
        t.rows[0].cells[1].width = Inches(5.2)
        d.add_paragraph().paragraph_format.space_after = Pt(2)
        return weight, triggered

    def section_chart(keys):
        """Grafico nativo (editable en Word) con el riesgo de las
        categorias que cubre esta seccion - mismo mecanismo de
        placeholder que risk_global/risk_cats, ver docx_charts.py."""
        d.add_paragraph().add_run(f"[[CHART risk_section_{'__'.join(keys)}]]")

    def para(text, italic=False, color=None, size=None, bold=False):
        p = d.add_paragraph()
        r = p.add_run(text)
        r.italic = italic
        r.bold = bold
        if color:
            r.font.color.rgb = color
        if size:
            r.font.size = Pt(size)
        p.paragraph_format.space_after = Pt(6)
        return p

    def bullet(label, text=None):
        p = d.add_paragraph(style="List Bullet")
        if text is None:
            p.add_run(label)
        else:
            p.add_run(label + " ").bold = True
            p.add_run(text)
        return p

    def table(headers, rows, col_widths=None, red_cols=()):
        t = d.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, h in enumerate(headers):
            c = t.rows[0].cells[i]
            c.text = ""
            r = c.paragraphs[0].add_run(h)
            r.bold = True
            r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            r.font.size = Pt(9)
            shade(c, NAVY_HEX)
        for n, row in enumerate(rows):
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = ""
                r = cells[i].paragraphs[0].add_run("" if v is None else str(v))
                r.font.size = Pt(9)
                if i in red_cols:
                    r.font.color.rgb = RED
                    r.bold = True
                if n % 2 == 1:
                    shade(cells[i], LIGHT)
        if col_widths:
            for row in t.rows:
                for i, w in enumerate(col_widths):
                    row.cells[i].width = Inches(w)
        d.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    def no_data(text="Sin datos recopilados en este escaneo para esta sección."):
        para(text, italic=True, color=MUTED)

    def action_box(title, items, bg_hex, text_color, icon):
        if not items:
            return
        box = d.add_table(rows=1, cols=1)
        box.style = "Table Grid"
        cell = box.rows[0].cells[0]
        shade(cell, bg_hex)
        tr = cell.paragraphs[0].add_run(f"{icon} {title}")
        tr.bold = True
        tr.font.color.rgb = text_color
        tr.font.size = Pt(11)
        for item in items:
            ip = cell.add_paragraph(style="List Bullet")
            ir = ip.add_run(item)
            ir.font.size = Pt(9)
            ir.font.color.rgb = INK
        d.add_paragraph().paragraph_format.space_after = Pt(4)

    def no_border(table):
        tbl_pr = table._tbl.tblPr
        borders = OxmlElement("w:tblBorders")
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            el = OxmlElement(f"w:{edge}")
            el.set(qn("w:val"), "nil")
            borders.append(el)
        tbl_pr.append(borders)

    # ---------- cabecera y pie de pagina ----------
    # logo del pentester (izquierda) | dominio (centro) | logo del cliente (derecha),
    # igual que \lhead/\rhead de la plantilla LaTeX de referencia.
    sec = d.sections[0]
    hdr_table = sec.header.add_table(rows=1, cols=3, width=Inches(6.5))
    no_border(hdr_table)
    left_cell, mid_cell, right_cell = hdr_table.rows[0].cells
    for hc in (left_cell, mid_cell, right_cell):
        tcPr = hc._tc.get_or_add_tcPr()
        borders = OxmlElement("w:tcBorders")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "6")
        bottom.set(qn("w:color"), "E3E8F3")
        bottom.set(qn("w:space"), "4")
        borders.append(bottom)
        tcPr.append(borders)
    if pentester_logo:
        left_cell.paragraphs[0].add_run().add_picture(str(pentester_logo), height=Inches(0.4))
    mid_p = mid_cell.paragraphs[0]
    mid_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    label_run = mid_p.add_run("CYBERSECURITY HEALTH CHECK   ")
    label_run.font.size = Pt(7.5)
    label_run.font.color.rgb = MUTED
    label_run.font.bold = True
    domain_run = mid_p.add_run(domain)
    domain_run.font.size = Pt(7.5)
    domain_run.font.color.rgb = MUTED
    if client_logo:
        right_p = right_cell.paragraphs[0]
        right_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        right_p.add_run().add_picture(str(client_logo), height=Inches(0.4))
    # el header original de python-docx trae un primer parrafo vacio antes de la tabla
    sec.header.paragraphs[0].text = ""
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = fp.add_run("Confidencial · Página ")
    fr.font.size = Pt(8)
    fr.font.color.rgb = MUTED
    run = fp.add_run()
    for tag, txt in (("begin", None), (None, "PAGE"), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = txt
        run._r.append(el)

    # ---------- portada ----------
    # Si el usuario sube su propia imagen de portada (logos_dir/portada.*)
    # se respeta tal cual (con el texto de siempre debajo). Si no, se
    # genera una portada propia a toda pagina (ver _generate_cover_image):
    # nada de imagenes de terceros, y ademas ya incluye el nivel de riesgo
    # real del escaneo en el propio diseño.
    if cover_image:
        d.add_picture(str(cover_image), width=Inches(6.3))
        if empresa:
            para(empresa.upper(), bold=True, color=GREEN, size=12)
        p = d.add_paragraph()
        r = p.add_run("CYBER HEALTH CHECK")
        r.bold = True
        r.font.size = Pt(26)
        p = d.add_paragraph()
        r = p.add_run(domain)
        r.bold = True
        r.font.size = Pt(20)
        para("Evaluación de seguridad basada en reconocimiento pasivo", color=MUTED, size=11)
        box = d.add_table(rows=1, cols=1)
        box.style = "Table Grid"
        cell = box.rows[0].cells[0]
        shade(cell, ALERT_BG if health["total"] >= 40 else OK_BG)
        cr = cell.paragraphs[0].add_run(f"Nivel de Riesgo:  {total_txt}%   —   {health['level']}")
        cr.bold = True
        cr.font.size = Pt(13)
        cr.font.color.rgb = RED if health["total"] >= 40 else GREEN
        para(datetime.now().strftime("%d-%m-%Y"), color=MUTED)
    else:
        sec0 = d.sections[0]
        printable_w = sec0.page_width - sec0.left_margin - sec0.right_margin
        cover_buf = _generate_cover_image(domain, empresa, health["total"], health["level"])
        d.add_picture(cover_buf, width=printable_w)
    d.add_page_break()

    # ---------- indice ----------
    heading("Índice", 1)
    tp = d.add_paragraph()
    r = tp.add_run()
    for tag, txt in (("begin", None), (None, 'TOC \\o "1-2" \\h \\z \\u'), ("separate", None),
                     (None, "Pulsa F9 (o clic derecho > Actualizar campo) para generar el índice."), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        else:
            el = OxmlElement("w:instrText" if txt and txt.startswith("TOC") else "w:t")
            if el.tag.endswith("instrText"):
                el.set(qn("xml:space"), "preserve")
            el.text = txt
        r._r.append(el)
    d.add_page_break()

    # ---------- metodologia ----------
    heading("Metodología", 1)
    para(PHRASES["methodology"])
    para(PHRASES["methodology_intro"])
    for label, text in PHRASES["methodology_items"]:
        bullet(label, text)
    para(PHRASES["methodology_note"], italic=True, color=MUTED, size=9)
    d.add_page_break()

    # ---------- resumen ejecutivo ----------
    heading("Resumen ejecutivo", 1)
    p = d.add_paragraph()
    p.add_run("Nivel de Riesgo global: ").bold = True
    rr = p.add_run(f"{total_txt}% — {health['level']}")
    rr.bold = True
    rr.font.color.rgb = RED if health["total"] >= 40 else GREEN
    d.add_paragraph().add_run("[[CHART risk_global]]")
    heading("Evaluación por categoría", 2)
    d.add_paragraph().add_run("[[CHART risk_cats]]")
    cat_rows = []
    for key, c in health["categories"].items():
        estado = "A REVISAR" if c["points"] else "OK"
        cat_rows.append([c["label"], f"{_fmt(c['weight'])}%", estado, f"{_fmt(c['points'])} pts"])
    table(["Categoría de riesgo", "Peso", "Estado", "Riesgo"], cat_rows,
          col_widths=[3.6, 0.7, 1.1, 0.9], red_cols=(2,))

    heading("Plan de acción inmediata", 2)
    sanear, revisar = _action_items(findings, domain)
    if sanear or revisar:
        para("Hallazgos agrupados por urgencia de remediación, a partir de los mismos datos "
             "detallados en el resto del informe.", italic=True, color=MUTED, size=9)
        action_box("Sanear de inmediato", sanear, ALERT_BG, RED, "⛔")
        action_box("Revisar", revisar, INFO_BG, NAVY, "🔍")
    else:
        no_data("No se identificaron hallazgos que requieran accion inmediata en este escaneo.")

    heading("Indicadores clave", 2)
    ips = _unique_ips(findings)
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
        ["Hosts / Subdominios", hosts_n],
        ["IPs propias analizadas", len(ips)],
        ["Puertos abiertos", ports_n],
        ["IPs comprometidas", comp_ips],
        ["CVEs asociados", cves_n],
        ["Tecnologías obsoletas (EOL)", eol_n],
        ["Dominios de squatting / typosquatting activos", squat_n],
    ], col_widths=[4.36, 1.94])
    para(f"Ante la evaluación global de {health['level'].lower().replace('riesgo ', 'riesgo ')} "
         f"({total_txt}%) observada en la infraestructura externa de {domain}. Se recomienda "
         "articular el plan de remediación prioritario en torno a las siguientes líneas estratégicas:", italic=True, color=MUTED)
    for label, text in PHRASES["strategy"]:
        bullet(label, text)
    d.add_page_break()

    # ---------- discovery ----------
    heading("Discovery — Subdominios e IPs", 1)
    hosts = list(results.keys()) if results else [domain]
    disc_rows = []
    for h in hosts:
        try:
            ip = socket.gethostbyname(h)
        except OSError:
            ip = "no resuelve"
        own = "Sí" if h == domain or h.endswith("." + domain) else "Externo"
        disc_rows.append([h, ip, own])
    para("Hosts analizados. La columna \"Propio del dominio\" indica si el host pertenece al dominio "
         "analizado o a un servicio de terceros.", color=MUTED, size=9)
    table(["Host", "IP resuelta", "Propio del dominio"], disc_rows, col_widths=[2.95, 1.77, 1.57])
    d.add_page_break()

    # ---------- 1. Compromised Systems ----------
    heading("1. Compromised Systems", 1)
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
                         "N/D", "N/D", "REVISAR" if flagged else "OK",
                         _num(f.note, r"confianza de abuso=(\d+)%")])
        table(["IP", "Dominio", "Botnet", "Spam", "Malware/C2", "Blacklist", "Índice abuso"], rows,
              col_widths=[1.05, 1.66, 0.7, 0.53, 0.79, 0.79, 0.79])
        para("N/D: no hay clasificación por tipo de actividad para esta IP en las fuentes consultadas "
             "(solo se dispone de índice de abuso y motores que la marcan).", italic=True, color=MUTED, size=8)
    else:
        no_data("No se consultó reputación de IP (requiere api key de VirusTotal o AbuseIPDB).")
    para(PHRASES["compromised"])
    para(PHRASES["compromised_blacklist"])
    heading("Recomendaciones", 2)
    para(PHRASES["compromised_recs"])
    d.add_page_break()

    # ---------- 2. Security Controls ----------
    heading("2. Security Controls", 1)
    section_badge(["dns_email", "tls_web"])
    section_chart(["dns_email", "tls_web"])
    heading("Email Security", 2)
    para(PHRASES["email"])
    dns_rows = [f for f in findings if f.category == "dns" and f.dork_name.startswith("Autenticacion de correo")]
    if dns_rows:
        note = dns_rows[0].note or ""
        spf = "Publicado" if "SPF: presente" in note else "Ausente"
        dmarc = "Publicado" if "DMARC: presente" in note else "Ausente"
        dkim = "Detectado" if "Selectores DKIM detectados" in note else "No detectado"
        para(f"SPF: {spf}", bold=False)
        para(f"DMARC: {dmarc}")
        para(f"DKIM: {dkim}")
        for line in note.splitlines():
            if line.startswith(("SPF:", "DMARC:", "Selectores", "Sin selectores", "Mecanismo", "Politica")):
                continue
            if line.strip():
                bullet(line.strip())
    else:
        no_data()

    heading("DNS Security", 2)
    para(PHRASES["dns"])
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
        if rows:
            table(["Nameserver", "Zone Transfer (AXFR)"], rows, col_widths=[3.5, 2.5], red_cols=(1,))
    dnssec = [f for f in findings if f.dork_name == "DNSSEC"]
    if dnssec:
        para(f"DNSSEC: {dnssec[0].title}")
    caa_note = [f for f in findings if f.dork_name.startswith("Registros DNS")]
    if caa_note:
        m = re.search(r"CAA: (.*)", caa_note[0].note or "")
        if m:
            para(f"CAA: {'Ausente' if m.group(1).strip() in ('-', '') else 'Presente'}")

    heading("TLS Security", 2)
    para(PHRASES["tls"])
    certs = [f for f in findings if f.dork_name == "Certificado TLS"]
    for f in certs:
        if f.title == "No se pudo conectar por HTTPS":
            bullet("No se pudo establecer conexión HTTPS con el host", _host(f, domain))
            continue
        lines = [ln for ln in (f.note or "").splitlines() if ln.strip()]
        for ln in lines:
            if ln.startswith(("Emisor:", "CN:", "Caducidad:", "Cifrado:", "SAN:")):
                bullet(ln)
        issues = [ln for ln in lines if any(m in ln for m in _TLS_CERT_ISSUE_MARKERS)]
        if issues:
            for ln in issues:
                bullet("Hallazgo:", ln)
        else:
            bullet("Sin hallazgos en la configuración TLS.")
    if not certs:
        no_data()

    heading("Web Security — HTTP Headers", 2)
    para(PHRASES["web"])
    hdr = [f for f in findings if f.dork_name == "Cabeceras de seguridad HTTP"]
    if hdr:
        rows = []
        for f in hdr:
            server = re.search(r"Server: (.+)", f.note or "")
            missing = re.search(r"Ausentes: (.+)", f.note or "")
            ausentes = re.sub(r"\s*\((alta|media|baja)\)", "", missing.group(1)).strip() if missing else "ninguna"
            rows.append([f.url or _host(f, domain), "OK", server.group(1) if server else "-", ausentes if ausentes != "-" else "ninguna"])
        table(["URL", "Estado", "Server", "Cabeceras ausentes"], rows, col_widths=[1.98, 0.72, 1.26, 2.34])
    else:
        no_data()
    heading("Recomendaciones", 2)
    para(PHRASES["controls_recs"])
    d.add_page_break()

    # ---------- 3. Exposure Management ----------
    heading("3. Exposure Management", 1)
    section_badge(["tls_web"])
    section_chart(["tls_web"])
    heading("Puertos y servicios (por IP)", 2)
    para(PHRASES["exposure"])
    ports = [f for f in findings if f.category == "ports" and _port_number(f)]
    if ports:
        by_host = {}
        for f in ports:
            by_host.setdefault(_host(f, domain), []).append(f)
        for h, fs in by_host.items():
            ip = re.search(r"tcp://(\d+\.\d+\.\d+\.\d+)", fs[0].url or "")
            heading(f"{ip.group(1) if ip else '—'}   {h}", 3)
            rows = []
            for f in sorted(fs, key=_port_number):
                m = re.match(r"Puerto \d+/\w+ \((.*)\)", f.dork_name)
                svc = m.group(1) if m else "-"
                rows.append([_port_number(f), svc, f.title or "—", criticidad(_port_number(f))])
            table(["Puerto", "Servicio", "Producto / Versión", "Criticidad"], rows, col_widths=[0.86, 1.81, 2.48, 1.15])
    else:
        no_data("No se detectaron puertos abiertos en el top 100 o no se ejecutó el escaneo de puertos (categoría 'ports').")
    heading("Cloud Exposure", 2)
    para(PHRASES["cloud"])
    buckets = [f for f in findings if f.category == "bucket"]
    if buckets:
        table(["Recurso", "Estado", "URL"], [[f.dork_name, f.title or "-", f.url or "-"] for f in buckets],
              col_widths=[1.69, 2.35, 2.26], red_cols=(1,))
    else:
        para("Sin exposición cloud pública confirmada.")
    heading("Recomendaciones", 2)
    para(PHRASES["exposure_recs"])
    d.add_page_break()

    # ---------- 4. Technology & Vulnerability ----------
    heading("4. Technology & Vulnerability Exposure", 1)
    section_badge(["vuln"])
    section_chart(["vuln"])
    para(PHRASES["tech"])
    vulns = [f for f in findings if f.category == "vuln"]
    rows = _cve_rows(vulns, domain)
    n_cve = sum(1 for r in rows if r[0].startswith("CVE-"))
    n_edb = sum(1 for r in rows if r[3].startswith("PoC disponible (ExploitDB)"))
    n_spl = sum(1 for r in rows if r[3].startswith("PoC disponible (Sploitus)"))
    para(f"Resumen: {n_cve} CVE(s) verificados en NVD, {n_edb} exploit(s) en ExploitDB y "
         f"{n_spl} PoC(s) en Sploitus asociados a las tecnologías y servicios identificados.",
         bold=True, size=9)
    techs = [f for f in findings if f.category == "tech"]
    if techs:
        heading("Tecnologías y plugins detectados", 2)
        table(["Tecnología / plugin", "Versión", "URL"],
              [[f.dork_name.replace("Tecnologia detectada: ", ""), f.title or "-", f.url or "-"] for f in techs],
              col_widths=[2.41, 1.48, 2.41])
    if rows:
        by_host = {}
        for ident, product, host, estado in rows:
            by_host.setdefault(host, []).append((ident, product, estado))
        for h, items in by_host.items():
            heading(h, 3)
            table(["Identificador", "Producto", "Estado"],
                  [[i, p, e] for i, p, e in items], col_widths=[1.91, 2.48, 1.91])
    else:
        no_data("No se encontraron CVEs ni exploits públicos para las tecnologías y versiones identificadas.")
    eol = [f for f in vulns if f.dork_name.startswith("Fin de soporte")]
    if eol:
        heading("Tecnologías sin soporte del fabricante (EOL)", 2)
        table(["Producto", "Detalle"], [[f.dork_name.replace("Fin de soporte (EOL): ", ""), f.note] for f in eol],
              col_widths=[1.94, 4.36])
    heading("Recomendaciones", 2)
    para(PHRASES["tech_recs"])
    d.add_page_break()

    # ---------- 5. Identity & User Exposure ----------
    heading("5. Identity & User Exposure", 1)
    section_badge(["leaks", "identity"])
    section_chart(["leaks", "identity"])
    heading("Employee Email Exposure", 2)
    para(PHRASES["identity"])
    emails = [f for f in findings if f.category == "email"]
    rows = []
    for f in emails:
        for e in f.emails:
            rows.append(["Fuentes públicas", "email corporativo", e, "Baja"])
    if rows:
        table(["Fuente", "Hallazgo", "Evidencia / URL", "Severidad"], rows, col_widths=[1.32, 1.5, 2.63, 0.85])
    else:
        no_data("No se detectaron correos corporativos expuestos en las fuentes consultadas.")

    heading("Exposed Credentials", 2)
    para(PHRASES["creds"])
    leaks = [f for f in findings if f.secrets]
    if leaks:
        table(["Recurso", "Datos expuestos", "URL"],
              [[f.dork_name, leak_detail(f), f.url or "-"] for f in leaks],
              col_widths=[1.72, 2.29, 2.29], red_cols=(1,))
    else:
        para("No se detectaron credenciales expuestas en las fuentes consultadas.")

    heading("File Sharing Exposure", 2)
    para(PHRASES["file_sharing"])
    docs = [f for f in findings if f.category == "document"]
    if docs:
        table(["Autor", "Metadatos", "Recurso", "URL"],
              [[f.author or "-", f.software or "-", f.filetype or "-", f.url or "-"] for f in docs],
              col_widths=[1.41, 1.69, 0.75, 2.44])
    else:
        no_data("No se encontraron documentos públicos con metadatos.")
    heading("Recomendaciones", 2)
    para(PHRASES["identity_recs"])
    d.add_page_break()

    # ---------- 6. Brand Reputation ----------
    heading("6. Brand Reputation", 1)
    section_badge(["reputation", "squatting"])
    section_chart(["reputation", "squatting"])
    heading("Valoración de reputación", 2)
    para(PHRASES["brand_reputation"])
    dom_rep = [f for f in findings if f.category == "reputation" and not (f.title and re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title))]
    if dom_rep:
        flagged = any(_num(f.note, r"malicioso=(\d+)") > 0 for f in dom_rep)
        para(f"Reputación de dominio: {'Indicios de mala reputación' if flagged else 'Sin indicios de mala reputación'}")
    else:
        para("Reputación de dominio: no consultada (requiere api key de VirusTotal o AbuseIPDB).", italic=True, color=MUTED)
    ipr = [f for f in findings if f.category == "reputation" and f.title and re.match(r"^\d+\.\d+\.\d+\.\d+$", f.title)]
    bad = [f.title for f in ipr if _num(f.note, r"confianza de abuso=(\d+)%") >= 50 or _num(f.note, r"malicioso=(\d+)") > 0]
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
    para(PHRASES["squatting"])
    sq = _pairs(squat_f)
    if sq:
        table(["Dominio", "IP"], sq, col_widths=[3.5, 2.0])
    else:
        para("No se detectaron dominios de squatting activos (registrados y resolviendo).")
    heading("Typosquatting", 2)
    para(PHRASES["typosquat"])
    ts = _pairs(typo_f)
    if ts:
        table(["Dominio", "IP"], ts, col_widths=[3.5, 2.0])
    else:
        para("No se detectaron variantes tipográficas del dominio activas.")
    heading("Recomendaciones", 2)
    para(PHRASES["brand_recs"])

    buf = io.BytesIO()
    d.save(buf)
    chart_data = {
        "score": health["total"],
        "categories": [{"key": k, "label": c["label"], "riskPct": 100.0 if c["points"] else 0.0}
                        for k, c in health["categories"].items()],
    }
    embed_risk_charts(chart_data, buf, path)
    return health
