================================================================
 FRIB1TRECON - Herramienta de reconocimiento OSINT para Linux
================================================================

QUE ES
------
Herramienta de reconocimiento OSINT que, dado un dominio, busca:
  - Nivel de riesgo general (0-100%): se calcula siempre sobre lo que se
    haya encontrado en el escaneo (no es una categoria mas, resume las
    demas). 7 categorias de riesgo con peso fijo (leaks 25%, seguridad
    DNS/email 15%, TLS/cabeceras 15%, CVEs/EOL 15%, reputacion maliciosa
    15%, typosquatting/domain squatting 10%, exposicion de identidad 5%):
    si cualquier hallazgo dispara una categoria se suma su peso completo.
    Umbrales: 0-20% bajo, 20-40% medio, 40-65% alto, 65%+ critico.
    Aparece en la CLI, en todas las exportaciones (tambien en los
    informes maestro) y como banner en la web.
  - Postura DNS y WHOIS (activa por defecto, gratis, sin api keys): registros
    NS/MX/TXT/CAA, autenticacion de correo (SPF, DKIM via selectores
    comunes, DMARC con su politica), DNSSEC, e intento de transferencia de
    zona (AXFR) contra cada nameserver — si alguno la permite se reporta
    como leak critico, expone TODA la zona DNS de un tiron. Tambien datos
    de registro WHOIS (registrador, fechas de creacion/expiracion,
    nameservers, organizacion si no esta redactada por GDPR).
  - Postura TLS/HTTPS y cabeceras de seguridad (activa por defecto, gratis,
    sin api keys): certificado (emisor, caducidad, SAN, cifrado negociado),
    soporte de protocolos obsoletos (TLSv1.0/1.1), cabeceras de seguridad
    HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy) y flags de cookies (Secure/
    HttpOnly). Todo pasivo: una conexion TLS normal y un GET normal, lo
    mismo que hace cualquier navegador.
  - Documentos ofimaticos publicados (pdf, xlsx, xls, docx, doc, csv, pptx)
    y extrae sus metadatos (autor, ultimo editor, software usado, empresa,
    responsable, fechas de creacion/modificacion, rutas internas filtradas,
    equipos/servidores internos filtrados en rutas UNC, emails detectados
    dentro del documento), ademas de imagenes publicadas (jpg, jpeg, png,
    tiff) de las que extrae coordenadas GPS embebidas si no se limpiaron
    antes de subirlas (hallazgo clasico con fotos corporativas).
  - Ficheros sensibles (sql, log, env, bak, txt, xml,
    conf, ini, yml, yaml, json) y comprueba si contienen contrasenas, api
    keys, claves AWS, claves privadas, IPs/infraestructura interna, etc.
    El .txt se trata aqui (no como documento ofimatico): no tiene
    metadatos que extraer, pero es el sitio clasico donde queda olvidada
    una nota con credenciales.
  - Busqueda dedicada de ficheros con pinta de contraseñas/claves
    olvidadas en el propio dominio (site:dominio + password/contraseña/
    clave/credenciales), verificado despues en local igual que el resto
    de leaks (patron de credencial real).
  - Menciones del dominio en plataformas externas: Google Drive, Google
    Docs, S3, DigitalOcean Spaces, Dropbox, Pastebin, Trello, OneDrive,
    Notion, Google Play Store y Apple App Store (para saber si la empresa
    tiene apps publicadas, objetivo valioso para analisis de
    vulnerabilidades posterior).
  - Posibles leaks en GitHub, GitHub Gist, GitLab, Bitbucket, Ghostbin,
    JSFiddle, StackOverflow, directorios abiertos ("index of") y paneles de
    administracion expuestos (verificados en local, no solo por la
    busqueda: patron de credencial real, TruffleHog si esta instalado, o
    URL de verdad del dominio). Si el secreto esta en una pagina que no
    menciona el dominio literalmente (busqueda por relevancia, no exacta),
    se marca con un aviso para revisar a mano si pertenece de verdad.
    Los directorios abiertos ("index of") ademas se DESCARGAN de verdad y
    se parsea el listado real de ficheros (no solo el fragmento del
    buscador): los que tienen pinta sensible por nombre o extension
    (.txt, .sql, .env, .bak, .zip, .pem, .key...) se bajan y analizan en
    busca de credenciales, hasta un limite de 8 por directorio para no
    disparar peticiones sin control.
  - (opt-in, con --all o --categories external) Subdominios historicos via
    crt.sh + Certspotter (certificate transparency, ambos gratis) y URLs
    archivadas con pinta de haber sido sensibles (backups, configs,
    paneles) via Wayback Machine (gratis) que ya no estan enlazadas en la
    web actual. Tambien analiza en local (sin peticiones nuevas) todo lo
    recopilado buscando infraestructura cloud conocida (AWS, Azure, Google
    Cloud, DigitalOcean, Cloudflare, Heroku, Akamai, Fastly).
  - (opt-in, con --all o --categories vuln) Fingerprinting de tecnologias
    web (via `whatweb`) sobre la pagina principal del dominio: CMS,
    framework, servidor, librerias JS... con su version. Esas tecnologias,
    mas el software/version detectado en los metadatos de documentos
    (p.ej. "Apache 2.2.3"), se cruzan contra NVD (National Vulnerability
    Database), ExploitDB local (via `searchsploit`, sin peticiones de red)
    y Sploitus en busca de CVEs/exploits conocidos. Las tecnologias
    detectadas por fingerprinting ademas se comprueban contra
    endoflife.date (API publica gratis, sin api key) para saber si esa
    version ya esta fuera de soporte (EOL).
  - Diagrama de red (red.dot, y red.png si tienes graphviz instalado):
    dominio -> subdominios -> IPs (Shodan) -> hostnames, mas proveedores
    cloud, tecnologias web y software vulnerable detectados, leaks,
    menciones en plataformas, emails, documentos y personas — todo
    enlazado visualmente. Para grafos grandes (muchos nodos) cambia
    automaticamente a un motor de layout mas compacto (`fdp`) en vez del
    jerarquico por defecto, para que la imagen resultante tenga una
    relacion de aspecto razonable y quepa bien en una pagina del informe
    Word (donde ademas se incrusta un mini-esquema encima de cada seccion,
    no solo el diagrama completo al final).
  - (opt-in, con --recursive) Tras encontrar subdominios (crt.sh/Shodan),
    relanza automaticamente un escaneo mas ligero (documentos, sensibles y
    leaks) contra cada uno, hasta 10 por defecto. Un solo nivel de
    profundidad: no se buscan subdominios de los subdominios.
  - Emails corporativos mencionados en cualquier pagina indexada (no solo
    en documentos): paginas de contacto, directorios de empresa, foros,
    noticias... via SearXNG en vez de scrapear buscadores directamente.
  - (opt-in, con --all o --categories people) Empleados de la empresa en
    LinkedIn (nombre + puesto), agrupados en un organigrama aproximado por
    nivel de seniority. OJO: LinkedIn no expone relaciones de jefatura en
    busqueda publica, asi que esto NO son lineas de mando reales, es una
    agrupacion por palabras clave del puesto (direccion/mandos/resto).
  - (opt-in, con --all o --categories external) Hosts/puertos/CVEs expuestos
    via Shodan (InternetDB, gratis, sin api key), buckets S3/GCS/Azure con
    LISTADO PUBLICO probando activamente nombres candidatos derivados del
    dominio contra los 3 proveedores (sin api key; se descartan los que
    solo "existen" de forma privada, para no generar ruido con nombres
    comunes ya registrados por terceros), y, si aportas tu propia api key,
    tambien ficheros en buckets via GrayHatWarfare, menciones en
    leaks/pastes/darkweb (IntelX), mas subdominios (DNSDumpster), y
    reputacion del dominio/IP: cuantos motores antivirus/antiphishing lo
    marcan malicioso (VirusTotal) y reportes de abuso tipo botnet/spam/
    fuerza bruta (AbuseIPDB). Ninguna
    api key va hardcodeada en el codigo: siempre son flags de la CLI o
    variables de entorno que pone quien ejecuta el escaneo.
  - Si tienes TruffleHog instalado, se usa automaticamente ademas de las
    regex propias para verificar leaks: cientos de detectores especificos
    (AWS, Stripe, Slack...) con verificacion activa de si la clave funciona.
  - (opt-in ACTIVO, solo con --categories ports, NO entra en --all)
    Puertos abiertos y versiones de servicios con nmap (-sT -sV, top 100).
    Envia trafico DIRECTO al objetivo: usalo solo con dominios propios o
    autorizados. Para cada servicio con producto y version busca CVEs/PoCs
    y fin de soporte (EOL). Requiere nmap (lo instala install.sh).
  - (opt-in, con --all o --categories typosquat) Typosquatting y domain
    squatting: genera cientos de variantes del dominio (estilo dnstwist:
    omision/repeticion/transposicion de letras, teclas adyacentes QWERTY,
    homoglifos, guiones... + mismo nombre en otros TLDs y combosquatting
    con palabras de phishing como login/secure/verify) y las resuelve
    todas por DNS en paralelo para ver cuales estan registradas de
    verdad. Mas lento que el resto de categorias (1000+ resoluciones
    DNS), por eso no esta activo por defecto.

Caracteristicas:
  - No scrapea Google directamente (asi se evita el bloqueo de IP que
    sufren las herramientas que si lo hacen). Usa SearXNG, un metabuscador
    que te instalas tu mismo en local, que agrega varios motores de
    busqueda por detras.
  - Ademas usa User-Agent aleatorio, tiempos de espera aleatorios entre
    peticiones y reintentos con backoff, para no levantar sospechas
    (siempre activo, se use o no --all).
  - Al terminar, te pregunta si quieres guardarte los documentos
    descargados o descartarlos (ya con los metadatos extraidos).
  - Guarda todo automaticamente organizado por dominio, con un informe en
    texto, un informe en Word, un Excel con todos los metadatos (incluida
    una hoja de Organigrama), y los datos en bruto en JSON/CSV.


REQUISITOS
----------
- Linux basado en Debian/Ubuntu/Kali (usa "apt").
- Acceso a "sudo" la primera vez (para instalar Docker y exiftool si no
  los tienes ya).
- Conexion a internet.


INSTALACION (una sola vez por maquina)
---------------------------------------
1. Copia la carpeta "frib1trecon" entera a la maquina donde quieras usarlo.
2. Abre una terminal dentro de esa carpeta y ejecuta:

       ./install.sh

   Esto instala automaticamente lo que falte (Docker, docker-compose,
   python3-venv, exiftool...), te anade al grupo "docker", crea el entorno
   Python y levanta SearXNG. Te pedira tu contrasena de sudo si hace falta
   instalar algo.

3. Si es la primera vez que te anade al grupo "docker", al final te avisara
   con un mensaje para que cierres sesion y la vuelvas a abrir (o ejecutes
   "newgrp docker"). No es obligatorio hacerlo en el momento: esa misma
   ejecucion ya funciona igualmente por debajo con sudo.

Si en el paso 2 ya le pasas un dominio, hace la instalacion Y el analisis
en el mismo comando (ver "COMO SE USA" mas abajo).


================================================================
 COMO SE USA
================================================================

FORMA MAS SENCILLA (instala si hace falta y analiza el dominio):

       ./install.sh site.com

Tambien acepta pegar la URL completa (https://site.com/alguna/ruta): se
extrae solo el hostname automaticamente, asi que da igual si copias y
pegas la URL del navegador o escribes el dominio a secas.

Esto deja los resultados en:

       frib1trecon_output/site.com/
           informe.txt        -> resumen legible, para abrir y leer
           informe.docx       -> lo mismo en Word, para adjuntar a un informe
           informe.xlsx       -> excel con todos los metadatos
                                  (hojas: Documentos, Sensibles,
                                  Plataformas_OSINT, Emails_OSINT,
                                  Organigrama, Fuentes_Externas, DNS_WHOIS,
                                  TLS_Cabeceras, Typosquatting,
                                  Tecnologias, Vulnerabilidades, Resumen)
           resultados.json    -> datos en bruto
           resultados.csv     -> datos en bruto
           red.dot            -> diagrama de red (fuente Graphviz, se
                                  puede abrir/editar a mano)
           red.png            -> el mismo diagrama renderizado como
                                  imagen (necesita graphviz instalado)
           documentos/        -> los ficheros descargados (si dijiste
                                  que si al preguntarte)
           informe.tex        -> el mismo contenido que informe.txt/.docx/
                                  .xlsx, pero en LaTeX (cabecera con dos
                                  logos, banda de color por seccion, misma
                                  paleta que el resto de informes)
           informe.pdf        -> el .tex de arriba ya compilado a PDF, solo
                                  si tienes pdflatex instalado (si no, se
                                  deja igual el .tex para compilarlo donde
                                  quieras; install.sh lo instala solo)
           informe.md         -> el texto en bruto de informe.tex/.pdf en
                                  Markdown, para poder retocar la redaccion
                                  sin tocar sintaxis LaTeX
           cyber_health_check.docx -> informe EJECUTIVO para entregar al
                                  cliente (portada, indice, metodologia,
                                  resumen ejecutivo con plan de accion
                                  inmediata -que sanear / que revisar- y
                                  una seccion por categoria de riesgo con
                                  indicadores, graficos nativos editables
                                  y recomendaciones; ver --logos-dir para
                                  personalizar portada/logos)
           cyber_health_check.tex  -> el mismo informe ejecutivo en LaTeX
                                  (misma plantilla visual que informe.tex:
                                  cabecera con dos logos, caja de
                                  confidencialidad, indice, cajas de
                                  definicion)
           cyber_health_check.pdf  -> el .tex de arriba ya compilado a PDF
                                  (mismas condiciones que informe.pdf)
           cyber_health_check.md   -> el texto en bruto del informe
                                  ejecutivo en Markdown (mismo proposito
                                  que informe.md)

Durante la ejecucion te preguntara:

       ¿Quieres guardar los documentos descargados en disco?

Si respondes que NO, igualmente se extraen y se guardan todos los
metadatos (en el excel/txt/json), solo que no se queda el fichero
original ocupando espacio en tu disco.


SI YA TIENES TODO INSTALADO (sin pasar por install.sh):

       .venv/bin/python -m frib1trecon.cli site.com

MODO ASISTENTE (si lo lanzas sin NINGUN argumento, en una terminal):

       .venv/bin/python -m frib1trecon.cli

Te pregunta paso a paso el dominio, si quieres el analisis completo o
elegir categorias, si seguir subdominios, la carpeta de logos, la carpeta
de salida, y si quieres meter alguna api key ahora (todo opcional, Enter
para el valor por defecto). En cuanto pasas el dominio o cualquier flag
directamente, se comporta como siempre, sin preguntar nada de mas.


OPCIONES MAS USADAS (se anaden despues del dominio):

  --yes                No preguntar nada, usar valores por defecto
                        (util para scripts automaticos / cron).

  --save-docs           Guardar siempre los documentos descargados,
                        sin preguntar.

  --no-save-docs        Descartar siempre los documentos tras sacar
                        los metadatos, sin preguntar.

  --no-download         Solo listar las URLs encontradas, sin descargar
                        ni analizar nada. El modo mas rapido y discreto.

  --min-delay 5 --max-delay 12
                        Ir mas despacio entre peticiones (mas discreto
                        todavia). Por defecto es entre 2.5 y 6 segundos.

  --out-dir OTRA_CARPETA
                        Cambiar donde se guardan los resultados (por
                        defecto se usa frib1trecon_output/ en la carpeta
                        actual).

  --logos-dir CARPETA_LOGOS
                        Personalizar la portada y las cabeceras de los
                        informes en DOCX/LaTeX (cyber_health_check.docx/
                        .tex e informe.tex) con tus propias imagenes.
                        No afecta a informe.docx/.txt/.xlsx (esos nunca
                        tuvieron portada personalizable). La carpeta
                        puede tener hasta tres ficheros, cada uno opcional
                        (si falta alguno, simplemente no aparece):
                          portada.png / portada.jpg    -> imagen de portada
                          cliente.png / cliente.jpg    -> logo del cliente,
                                                           esquina superior
                                                           derecha de cada
                                                           pagina
                          pentester.png / pentester.jpg -> tu logo/el del
                                                           auditor, esquina
                                                           superior izquierda
                                                           de cada pagina
                        o: export LOGOS_DIR=/ruta/a/la/carpeta
                        Sin esta opcion se usa el logo por defecto de
                        frib1trecon en la portada, como hasta ahora.

  --no-latex-pdf        No compilar informe.pdf/cyber_health_check.pdf
                        desde sus .tex generados (los .tex se generan
                        siempre; esto solo evita la compilacion con
                        pdflatex, por si no lo tienes instalado o no te
                        interesa el PDF).

  --categories document,sensitive,platform,leak,email,dns,tls,people,external,vuln,typosquat
                        Lanzar solo esas categorias (separadas por comas),
                        en vez de las ~37 por defecto (document, sensitive,
                        platform, leak, email, dns, tls). Las categorias
                        "people" (LinkedIn), "external" (Shodan/crt.sh/...),
                        "vuln" (tecnologias web + CVEs/exploits) y
                        "typosquat" (variantes del dominio, mas lento: 1000+
                        resoluciones DNS) no se incluyen por defecto, hay
                        que pedirlas explicitamente aqui o con --all.

  --all                  Lanzar absolutamente todo, incluida la busqueda
                        de empleados en LinkedIn (organigrama aproximado
                        por nivel de seniority). Las protecciones
                        anti-bloqueo (User-Agent aleatorio, delays,
                        backoff) ya estan siempre activas en cada
                        peticion, se use o no --all.

  --fail-on-leak        Salir con codigo 1 si se encuentra algun leak o
                        credencial (0 si no hay ninguno, 2 si hubo un
                        error/SearXNG no respondio). Pensado para que un
                        script o pipeline de CI pueda decidir automatica-
                        mente si algo fallo.

  -q, --quiet            Sin el progreso linea a linea: solo avisos,
                        leaks encontrados en vivo y el resumen final.
                        Ideal para cron (el log queda corto y legible).

  -v, --verbose          Ademas del progreso normal, muestra tambien los
                        candidatos a leak/email que se descartaron tras
                        comprobarlos en local (util para depurar si un
                        dork esta siendo demasiado estricto o laxo).

  --log-file RUTA        Ademas de pantalla, va guardando cada evento en
                        texto plano (sin colores) en ese fichero.

Ejemplos:

       ./install.sh site.com --yes --no-save-docs

       .venv/bin/python -m frib1trecon.cli site.com --no-download

       .venv/bin/python -m frib1trecon.cli site.com --min-delay 5 --max-delay 12

       .venv/bin/python -m frib1trecon.cli site.com --categories leak,sensitive

       .venv/bin/python -m frib1trecon.cli site.com --yes --quiet --fail-on-leak
           (pensado para cron/CI: codigo de salida 1 si aparece un leak)

       .venv/bin/python -m frib1trecon.cli site.com --all
           (analisis completo, incluye organigrama aproximado de LinkedIn)


COMPROBAR QUE SEARXNG FUNCIONA (opcional, para depurar):

       curl 'http://127.0.0.1:8080/search?q=test&format=json' | head -c 300


SI UN DORK DEVUELVE 0 RESULTADOS DE REPENTE (SOLUCION DE PROBLEMAS)
--------------------------------------------------------------------
SearXNG solo trae activados por defecto 2-3 motores reales (Brave,
DuckDuckGo y "Google CSE", este ultimo casi inutil sin una API key
propia). Si escaneas el mismo dominio varias veces seguidas, o usas un
--min-delay muy bajo, esos motores pueden marcarse como "suspendidos"
por rate-limit durante un buen rato, y a partir de ahi las busquedas
devuelven 0 resultados aunque el dominio si tenga documentos indexados.

Para comprobarlo:

       curl 'http://127.0.0.1:8080/search?q=test&format=json' | \
           python3 -c "import json,sys; print(json.load(sys.stdin)['unresponsive_engines'])"

Si sale una lista con motores y un motivo tipo "Suspended: too many
requests", ese es el problema. Se soluciona:

  1. Reiniciando el contenedor (borra el estado de suspension, que es
     solo en memoria):

       cd frib1trecon && sudo docker compose restart searxng

  2. Y, para que no vuelva a pasar, usando delays razonables. El propio
     motor de frib1trecon nunca deja bajar --min-delay de 1.5s (si lo
     intentas, veras un aviso en amarillo y lo sube solo), pero aun asi
     evita lanzar el mismo dominio muchas veces seguidas en pocos
     minutos.

  3. Si quieres mas margen de entrada, vuelve a ejecutar
     "python3 setup_searxng.py" (o "./install.sh") tras actualizar el
     proyecto: ahora activa tambien Yahoo, Qwant, Mwmbl, Yep y Yandex
     como motores de reserva, para que si uno se satura los demas sigan
     dando resultados.


FUENTES EXTERNAS: SHODAN / CRT.SH / WAYBACK / GRAYHATWARFARE / INTELX / TRUFFLEHOG / MALTEGO
--------------------------------------------------------------------------
Todo esto es opt-in: no se lanza en un analisis normal, hay que pedirlo con
--all o --categories external (ver OPCIONES MAS USADAS). Ninguna de estas
fuentes necesita que actives nada para que frib1trecon arranque: si no hay
api key, esa fuente concreta se omite sola sin fallar.

  Shodan        Gratis, no necesita api key (usa InternetDB). Si quieres
                mas detalle (banners, org...), pon tu api key:
                  export SHODAN_API_KEY="tu-key"
                o pasala directo: --shodan-key tu-key

  crt.sh        Gratis, no necesita api key. Busca todos los subdominios
                que alguna vez tuvieron un certificado SSL emitido (via los
                logs publicos de Certificate Transparency). Es un servicio
                comunitario conocido por caerse/saturarse a menudo: si
                falla, se omite solo sin interrumpir el resto del escaneo
                (puedes volver a lanzar mas tarde si te interesa).

  Wayback Machine Gratis, no necesita api key. Busca URLs archivadas bajo
                el dominio que ya no estan enlazadas en la web actual, y se
                queda solo con las que tienen pinta de haber sido sensibles
                (backups, configs, paneles de admin, ficheros .sql/.env/
                .ini/.yml...). Util para encontrar cosas que se borraron
                del sitio pero nunca se borraron de internet.

  GrayHatWarfare Busca el dominio en ficheros de buckets S3/Azure/GCP mal
                configurados y expuestos publicamente. Necesita api key
                (gratis registrandote en buckets.grayhatwarfare.com):
                  export GHW_API_KEY="tu-key"
                o: --ghw-key tu-key

  IntelX        Busca el dominio en su indice de leaks/pastes/darkweb y en
                su "phonebook" (emails/subdominios relacionados). Necesita
                api key (intelx.io/account?tab=developer, casi siempre de
                pago):
                  export INTELX_API_KEY="tu-key"
                o: --intelx-key tu-key

  VirusTotal    Reputacion del dominio y de su IP: cuantos motores
                antivirus/antiphishing lo marcan malicioso, categorias
                detectadas (phishing, malware...), puntuacion de la
                comunidad. Necesita api key (virustotal.com/gui/join-us,
                hay tier gratuito: 4 peticiones/min, 500/dia):
                  export VT_API_KEY="tu-key"
                o: --vt-key tu-key

  AbuseIPDB     Reputacion de abuso de la IP: reportes acumulados de la
                comunidad de botnets, spam, escaneos de puertos, fuerza
                bruta... Necesita api key (abuseipdb.com/register, hay
                tier gratuito):
                  export ABUSEIPDB_API_KEY="tu-key"
                o: --abuseipdb-key tu-key

  Censys        Hosts y puertos expuestos por dominio (search.censys.io).
                Necesita API ID y secret:
                  export CENSYS_API_ID="tu-id"  export CENSYS_API_SECRET="tu-secret"
                o: --censys-id tu-id --censys-secret tu-secret

  FOFA          Hosts y puertos por dominio (fofa.info). Necesita email y key:
                  export FOFA_EMAIL="tu-email"  export FOFA_API_KEY="tu-key"
                o: --fofa-email tu-email --fofa-key tu-key

  HaveIBeenPwned  Busca los correos encontrados en brechas conocidas.
                Necesita api key de pago (haveibeenpwned.com/API/Key):
                  export HIBP_API_KEY="tu-key"
                o: --hibp-key tu-key

  DomScan       Selectores DKIM del dominio. Necesita api key:
                  export DOMSCAN_API_KEY="tu-key"
                o: --domscan-key tu-key

  OTX AlienVault  DNS pasivo: subdominios e IPs que OTX ha visto resolver
                historicamente para el dominio (no consulta al objetivo,
                consulta la base de OTX). Gratis, solo hace falta
                registrarse en otx.alienvault.com y copiar la api key del
                perfil:
                  export OTX_API_KEY="tu-key"
                o: --otx-key tu-key

  TruffleHog    Si esta instalado en el sistema (se detecta solo, no hace
                falta configurar nada), se usa ademas de las regex propias
                para verificar los posibles leaks: cientos de detectores
                especificos (AWS, Stripe, Slack, GitHub...) con
                verificacion activa de si la credencial encontrada
                realmente funciona. Instalacion:
                  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

  Maltego       No tiene API/SDK que se pueda llamar desde un script (es
                una aplicacion de escritorio de pago con su propio sistema
                de "transforms"). Lo maximo integrable: cada analisis
                genera un maltego.csv con las entidades encontradas
                (Domain, Email, Person, URL, IPAddress, Server) listo para
                importar a mano en Maltego (su importador de CSV te deja
                mapear cada columna "EntityType" al tipo de entidad real).

  OSINT Framework (osintframework.com) y la lista de nixintel
  (start.me/p/rx6Qj8/nixintel-s-osint-resource-list) son paginas de
  enlaces/marcadores, no herramientas con API: no hay nada que un script
  pueda "integrar" ahi. Son buen punto de partida para complementar a mano
  lo que no cubre frib1trecon (recon de infraestructura activo, redes
  sociales mas alla de LinkedIn, imagenes, geolocalizacion...).

Ejemplo completo:
       export SHODAN_API_KEY="..."
       export GHW_API_KEY="..."
       .venv/bin/python -m frib1trecon.cli site.com --all


RECURSIVIDAD POR SUBDOMINIOS (--recursive)
---------------------------------------------
Lo mas completo que ofrece frib1trecon: tras descubrir subdominios via
crt.sh/Shodan (necesita que la categoria "external" este activa, con --all
o --categories external), relanza automaticamente un escaneo mas ligero
(por defecto: document, sensitive, leak) contra cada uno. Un solo nivel de
profundidad: los subdominios de los subdominios no se vuelven a seguir, y
cada host solo se escanea una vez aunque aparezca repetido en varias
fuentes.

  --recursive                    Activarlo.
  --max-subdomains N             Tope de subdominios a seguir (por defecto
                                  10, para no disparar el tiempo total:
                                  cada uno son ~26 dorks mas).
  --recursive-categories a,b,c   Que categorias usar en los subdominios
                                  (por defecto document,sensitive,leak).

Cada subdominio escaneado deja su propia carpeta completa (informe.txt/
.docx/.xlsx, resultados.json/.csv, maltego.csv, red.dot/.png) dentro de
frib1trecon_output/<dominio>/subdominios/<subdominio>/.

AVISO DE TIEMPO: con --all --recursive, un dominio con 10 subdominios
puede tardar fácilmente mas de 30-40 minutos (10 subdominios x ~26 dorks x
2.5-6s de delay cada uno). Usa --max-subdomains para acotarlo, o
--no-download para ir mucho mas rapido (solo lista URLs, no descarga ni
analiza nada).

Ejemplo:
       .venv/bin/python -m frib1trecon.cli site.com --all --recursive --max-subdomains 5


USO RESPONSABLE
---------------
Es una herramienta de reconocimiento pasivo: solo consulta contenido que
ya esta indexado publicamente, no ataca al servidor del dominio. Aun asi:
  - Usala solo contra dominios propios o con autorizacion.
  - No pongas los delays a 0 ni lances muchos dominios seguidos: respeta
    los limites de los motores que SearXNG consulta por detras.
