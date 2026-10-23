"""
Plantillas de dorks. Cada entrada define:
  - name: etiqueta legible
  - query: plantilla con {domain}
  - category: "document" (candidato a descarga + extraccion de metadatos),
              "platform" (mencion en servicio externo, solo se lista la URL)
              "leak" (candidato a leak, se verifica localmente antes de aceptarlo)
              "email" (busqueda abierta de direcciones @dominio)
  - downloadable: si True, frib1trecon intentara descargar el fichero encontrado

Nota sobre los dorks "leak": operadores estilo Google como OR, intitle: o
inurl: combinados no se interpretan igual (o se ignoran) en los motores
que hay detras de SearXNG (Brave, DuckDuckGo, Qwant...), que tratan la
consulta como una busqueda de relevancia en vez de una expresion booleana
estricta. Eso generaba mucho ruido: paginas genericas de la plataforma que
ni mencionaban el dominio. Por eso la consulta remota se deja lo mas
simple posible (site: + frase exacta del dominio) y la verificacion real
se hace despues en local (engine.py) segun "leak_filter":
  - "secret_pattern": exige un patron de credencial real (password, api_key,
    clave privada...) en el fragmento o la pagina completa.
  - "url_admin": exige que la URL contenga admin/login/panel/dashboard.
  - "index_of": exige que el titulo o el fragmento contengan "index of".
"""

DOCUMENT_FILETYPES = [
    "pdf", "xlsx", "xls", "docx", "doc", "csv", "pptx",
    # imagenes: ademas de metadatos normales (Software/Make/Model de la
    # camara), pueden llevar coordenadas GPS embebidas si no se limpiaron
    # antes de subirlas (hallazgo clasico con fotos corporativas)
    "jpg", "jpeg", "png", "tiff",
]

# ficheros que casi nunca son "documentos ofimaticos" con metadatos embebidos,
# pero que son oro puro si aparecen indexados (config/backups/logs). "txt" va
# aqui (no en DOCUMENT_FILETYPES): un .txt no tiene metadatos de office que
# extraer, pero es un clasico sitio donde queda una password/API key/nota
# interna olvidada, asi que se trata como fichero sensible (grep de patrones
# de credenciales) igual que sql/log/env/bak.
SENSITIVE_FILETYPES = [
    "sql", "log", "env", "bak", "txt",
    "xml", "conf", "ini", "yml", "yaml", "json",
]

# el 3er elemento es el host que realmente se espera en la URL del
# resultado: el "site:" del dork es solo una pista para el buscador, no un
# filtro estricto (algunos motores detras de SearXNG lo ignoran si el resto
# de la consulta "parece" relevante), asi que engine.py vuelve a comprobarlo
# en local contra la URL real antes de aceptar el hallazgo.
PLATFORM_DORKS = [
    ("Google Drive", "site:drive.google.com \"{domain}\"", "drive.google.com"),
    ("Google Docs", "site:docs.google.com \"{domain}\"", "docs.google.com"),
    ("Amazon S3", "site:s3.amazonaws.com \"{domain}\"", "s3.amazonaws.com"),
    ("DigitalOcean Spaces", "site:digitaloceanspaces.com \"{domain}\"", "digitaloceanspaces.com"),
    ("Dropbox", "site:dropbox.com \"{domain}\"", "dropbox.com"),
    ("Pastebin", "site:pastebin.com \"{domain}\"", "pastebin.com"),
    ("Trello", "site:trello.com \"{domain}\"", "trello.com"),
    ("Ficheros compartidos OneDrive", "site:1drv.ms \"{domain}\"", "1drv.ms"),
    ("Notion publico", "site:notion.site \"{domain}\"", "notion.site"),
    # apps moviles: no son un "leak", pero son objetivo valioso para analisis
    # de vulnerabilidades posterior (APK/IPA descompilado, API keys embebidas,
    # endpoints hardcodeados...), asi que se listan como hallazgo igual que
    # el resto de plataformas.
    ("Google Play Store (app movil)", "site:play.google.com \"{domain}\"", "play.google.com"),
    ("Apple App Store (app movil)", "site:apps.apple.com \"{domain}\"", "apps.apple.com"),
]

# mapa host->etiqueta para reclasificar en local (engine.py) un resultado
# que llega por el dork de OTRA plataforma pero cuya URL real pertenece a
# una de estas: el buscador a veces no respeta el site: pedido, y mas que
# descartar ese hallazgo (que puede ser valioso, p.ej. una app en Play
# Store encontrada via el dork de Google Drive) se reetiqueta con la
# plataforma correcta en vez de perderlo.
PLATFORM_HOST_LABELS = {host: label for label, _template, host in PLATFORM_DORKS}

# menciones en sitios de "pegado de texto" / foros de desarrollo donde
# suelen aparecer credenciales, trazas de error o configuraciones pegadas
# por error por empleados. Consulta remota simple (site: + dominio); el
# filtrado real de "es un leak de verdad" se hace en local (ver engine.py).
LEAK_DORKS = [
    ("GitHub", "site:github.com \"{domain}\"", "secret_pattern"),
    ("GitHub Gist", "site:gist.github.com \"{domain}\"", "secret_pattern"),
    ("GitLab", "site:gitlab.com \"{domain}\"", "secret_pattern"),
    ("Bitbucket", "site:bitbucket.org \"{domain}\"", "secret_pattern"),
    ("Ghostbin/Controlc", "(site:ghostbin.com OR site:controlc.com) \"{domain}\"", "secret_pattern"),
    ("JSFiddle/CodePen", "(site:jsfiddle.net OR site:codepen.io) \"{domain}\"", "secret_pattern"),
    ("StackOverflow", "site:stackoverflow.com \"{domain}\"", "secret_pattern"),
    ("Directorios abiertos (index of)", "site:{domain} \"index of\"", "index_of"),
    ("Paneles de administracion expuestos", "site:{domain} (inurl:admin OR inurl:login OR inurl:panel)", "url_admin"),
    # busqueda dedicada de ficheros con pinta de contraseñas/claves
    # olvidadas en el propio dominio (p.ej. un "passwords.txt" o
    # "claves.cfg" que alguien subio y nunca borro). El patron real
    # (password=/clave=/etc.) se verifica despues en local igual que el
    # resto de leak_filter=secret_pattern, esto solo hace mas probable que
    # el buscador devuelva justo esas paginas en vez de ruido generico.
    ("Ficheros con password/claves expuestos",
     "site:{domain} (password OR contraseña OR clave OR credenciales)", "secret_pattern"),
]

# busqueda abierta (sin site:) de menciones del email corporativo en
# cualquier pagina indexada: paginas de contacto, directorios de empresa,
# foros, noticias, perfiles... via SearXNG
EMAIL_DORKS = [
    ("Menciones de email en la web", "\"@{domain}\""),
    ("Emails en paginas de contacto/equipo", "\"@{domain}\" (contacto OR contact OR staff OR equipo OR email)"),
]

# perfiles de empleados en LinkedIn que mencionan el dominio (funciona
# mejor cuanto mas aparezca el dominio textualmente en el perfil, p.ej. en
# la seccion de contacto o en la web de la empresa enlazada). No se
# descarga la pagina de LinkedIn (requiere login para casi todo, scrapearla
# activamente violaria sus protecciones); solo se analiza el fragmento que
# ya devuelve el buscador. Categoria opt-in: no se lanza por defecto, hay
# que pedirla con --categories people o con --all.
LINKEDIN_DORKS = [
    ("Perfiles de empleados en LinkedIn (dominio)", "site:linkedin.com/in \"{domain}\""),
    # la mayoria de empleados ponen "en Empresa"/"at Company" en su perfil,
    # no el dominio literal ("biosabor.com") -> buscar tambien por el
    # nombre de empresa (adivinado quitando el TLD) encuentra muchos mas
    ("Perfiles de empleados en LinkedIn (nombre empresa)", "site:linkedin.com/in \"{company_guess}\""),
]


def build_dorks(domain: str):
    """Devuelve la lista completa de dorks (dicts) para un dominio dado."""
    dorks = []

    for ext in DOCUMENT_FILETYPES:
        dorks.append({
            "name": f"Documentos .{ext}",
            "query": f"site:{domain} filetype:{ext}",
            "category": "document",
            "downloadable": True,
            "ext": ext,
        })

    for ext in SENSITIVE_FILETYPES:
        dorks.append({
            "name": f"Ficheros sensibles .{ext}",
            "query": f"site:{domain} filetype:{ext}",
            "category": "sensitive",
            "downloadable": True,
            "ext": ext,
        })

    for label, template, expected_host in PLATFORM_DORKS:
        dorks.append({
            "name": f"Mencion en {label}",
            "query": template.format(domain=domain),
            "category": "platform",
            "downloadable": False,
            "ext": None,
            "platform_host": expected_host,
        })

    for label, template, leak_filter in LEAK_DORKS:
        dorks.append({
            "name": f"Posible leak: {label}",
            "query": template.format(domain=domain),
            "category": "leak",
            "downloadable": False,
            "ext": None,
            "leak_filter": leak_filter,
        })

    for label, template in EMAIL_DORKS:
        dorks.append({
            "name": label,
            "query": template.format(domain=domain),
            "category": "email",
            "downloadable": False,
            "ext": None,
        })

    company_guess = domain.split(".")[0].capitalize()
    for label, template in LINKEDIN_DORKS:
        dorks.append({
            "name": label,
            "query": template.format(domain=domain, company_guess=company_guess),
            "category": "people",
            "downloadable": False,
            "ext": None,
        })

    return dorks
