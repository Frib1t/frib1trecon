<p align="center">
  <img src="assets/frib1trecon_logo.png" alt="frib1trecon" width="120">
</p>

# frib1trecon

**Reconocimiento OSINT pasivo para Linux** — dorking, metadatos, leaks públicos,
postura DNS/TLS, vulnerabilidades conocidas y typosquatting, con informes
listos para entregar (TXT, Word, Excel, **DOCX/LaTeX/PDF ejecutivo**) y una
interfaz web opcional.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Debian%20%7C%20Kali%20%7C%20Ubuntu-informational?logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/estado-activo-success" alt="Status">
  <img src="https://img.shields.io/badge/reconocimiento-100%25%20pasivo%20por%20defecto-orange" alt="OSINT">
  <img src="https://img.shields.io/badge/busquedas-v%C3%ADa%20SearXNG%20propio-7b2ff7" alt="SearXNG">
</p>

<p align="center">
  <img src="docs/screenshots/demo.gif" alt="Demo de frib1trecon encontrando un leak" width="820">
</p>

<p align="center"><sub>Datos sintéticos de ejemplo — no corresponden a ningún dominio real.</sub></p>

---

## Índice

- [¿Qué hace?](#qué-hace)
- [Capturas](#capturas)
- [Instalación](#instalación)
- [Modo asistente](#modo-asistente)
- [Uso manual](#uso-manual)
- [Interfaz web](#interfaz-web-frib1trecon-web)
- [Qué genera](#qué-genera)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Desinstalación](#desinstalación)
- [Uso responsable](#uso-responsable)

---

## ¿Qué hace?

Por cada dominio que le des, `frib1trecon` busca todo lo que un atacante
externo podría encontrar **sin tocar tu servidor** (salvo que actives
explícitamente el escaneo de puertos): documentos públicos con metadatos,
credenciales filtradas, postura DNS/TLS, tecnologías vulnerables,
typosquatting, y mucho más. Todo calculado en un **nivel de riesgo 0-100%**
y volcado en informes listos para entregar.

Para no arriesgarte a que te bloqueen la IP por scraping directo, las
búsquedas pasan por **SearXNG**, un metabuscador que te alojas tú mismo en
Docker (agrega Brave/DuckDuckGo/Yahoo/Qwant/Mwmbl/Yep/Yandex — nunca pega
directo a Google/Bing). Cada petición sale además con User-Agent aleatorio,
delays con jitter, backoff exponencial y rotación opcional de proxies/varias
instancias SearXNG.

| 🔎 Reconocimiento pasivo (por defecto) | 🔑 Leaks y exposición | 🛡️ Vulnerabilidades | 📊 Informes |
|---|---|---|---|
| DNS/WHOIS, SPF/DKIM/DMARC, DNSSEC, AXFR | Credenciales en documentos/pastes/repos | CVEs vía NVD + ExploitDB + Sploitus | Nivel de riesgo 0-100% ponderado |
| TLS, protocolos obsoletos, cabeceras HTTP | Ficheros compartidos históricos aún vivos | Software sin soporte (EOL) | TXT / DOCX / XLSX / **LaTeX+PDF** / JSON / CSV |
| Subdominios (crt.sh, Certspotter, fuerza bruta, OTX) | Buckets S3/GCS/Azure públicos | Fingerprinting CMS (WP/Drupal/Joomla/Liferay) | **Cyber Health Check**: DOCX + **LaTeX/PDF** ejecutivo, con plan de acción |
| Typosquatting + domain squatting (1000+ variantes) | GitHub/GitLab/Pastebin/directorios abiertos | Puertos y servicios (nmap, opt-in activo) | Maltego CSV + diagrama de red interactivo |

---

## Capturas

<table>
<tr>
<td align="center" width="50%">
<img src="docs/screenshots/web-form.png" alt="Formulario web"><br>
<sub>Interfaz web — formulario de análisis</sub>
</td>
<td align="center" width="50%">
<img src="docs/screenshots/web-report.png" alt="Resultados web"><br>
<sub>Interfaz web — resultados con nivel de riesgo</sub>
</td>
</tr>
</table>

<p align="center">
<img src="docs/screenshots/cli-output.svg" alt="Salida de la CLI" width="760"><br>
<sub>Salida de la CLI (datos de ejemplo, no corresponden a ningún dominio real)</sub>
</p>

> Las capturas usan **datos sintéticos** (`ejemplo-cliente.com`, IPs de
> rango de documentación RFC 5737) generados solo para enseñar el formato
> de salida — no son el resultado de ningún escaneo real.

---

## Instalación

Copia la carpeta `frib1trecon/` (y, si la quieres, `frib1trecon-web/` al
lado) a la máquina destino (Debian/Kali/Ubuntu) y ejecuta:

```bash
./install.sh site.com
```

`install.sh` hace todo solo, sin pasos manuales:

1. **Paquetes del sistema** que falten: `docker.io`, `docker-compose-v2`,
   `python3-venv`, `python3-pip`, `exiftool`, `curl` (pide `sudo` solo si
   algo falta).
2. **Paquetes opcionales** si están en los repos de tu distro: `graphviz`
   (diagrama de red en PNG), `exploitdb` (búsqueda de exploits local),
   `whatweb` (fingerprinting web), `nmap` (escaneo de puertos),
   `texlive-latex-base`/`texlive-latex-extra` (compila el informe LaTeX a
   PDF), `whois` (datos de registro del dominio). Si alguno no existe en tu
   distro, el resto sigue igual, solo con menos resultados en esa función.
3. Arranca Docker y te añade al grupo `docker` (si no estabas) para no
   depender de `sudo` en adelante.
4. Instala **TruffleHog** en `~/.local/bin` (sin sudo, sin tocar el
   sistema) para verificar leaks con mucha más precisión que las regex
   propias.
5. Crea el entorno virtual Python e instala dependencias — tanto de la CLI
   como de `frib1trecon-web/` si esa carpeta existe al lado.
6. Levanta **SearXNG** en Docker (con tu mismo UID, para que nunca haga
   falta un `sudo chown` después) y habilita su modo JSON.
7. Verifica que todo funciona de verdad (SearXNG responde, las
   dependencias Python importan, las herramientas opcionales están donde
   se espera) antes de darse por terminado.
8. Ejecuta `frib1trecon` contra el dominio indicado.

Es **idempotente**: si lo vuelves a ejecutar, se salta lo que ya esté
instalado.

Para solo instalar, sin lanzar ningún análisis todavía:

```bash
./install.sh
```

> Si tienes **más de una copia** del proyecto en la misma máquina (por
> ejemplo tu carpeta de trabajo y una carpeta `subida/` para GitHub),
> `install.sh` funciona igual desde cualquiera de las dos — cada una crea
> su propio entorno virtual Python. Lo único que comparten es la instancia
> de SearXNG (la usa la que se lanzó en último lugar), que es justo lo que
> se quiere: un solo buscador, no hace falta duplicarlo.

---

## Modo asistente

Lanzado **sin ningún argumento**, en una terminal interactiva, `frib1trecon`
te pregunta paso a paso en vez de fallar pidiendo el dominio:

```bash
.venv/bin/python -m frib1trecon.cli
```

Dominio, categorías (completo o a medida), si seguir subdominios
descubiertos, carpeta de logos para el informe, carpeta de salida, y si
quieres meter alguna api key ahora — todo opcional, **Enter acepta el valor
por defecto**. En cuanto pasas el dominio o cualquier flag directamente, se
comporta exactamente igual que siempre, sin preguntar nada de más.

---

## Uso manual

```bash
.venv/bin/python -m frib1trecon.cli site.com --all --recursive
```

```bash
# elegir categorías concretas en vez de todas
.venv/bin/python -m frib1trecon.cli site.com --categories leak,sensitive,vuln

# sin preguntas, para scripts/cron — y exit code 1 si aparece un leak
.venv/bin/python -m frib1trecon.cli site.com --yes --quiet --fail-on-leak

# solo listar URLs encontradas, sin descargar nada (más rápido y discreto)
.venv/bin/python -m frib1trecon.cli site.com --no-download

# personalizar portada/cabeceras del informe con tus logos
# (hasta 3 ficheros opcionales: portada.png, cliente.png, pentester.png)
.venv/bin/python -m frib1trecon.cli site.com --logos-dir ./mis_logos

# ir más despacio / usar proxies y varias instancias SearXNG
.venv/bin/python -m frib1trecon.cli site.com --min-delay 5 --max-delay 12 \
    --searxng http://127.0.0.1:8080 --proxy http://127.0.0.1:9050
```

Referencia completa de opciones, códigos de salida y formato de salida en
[`README.txt`](README.txt).

---

## Interfaz web (`frib1trecon-web/`)

Si copiaste también `frib1trecon-web/` al lado de `frib1trecon/`,
`install.sh` la deja lista sola:

```bash
cd ../frib1trecon-web && .venv/bin/python app.py
# -> http://127.0.0.1:5000
```

Mismo motor que la CLI (nunca se duplica lógica), con extras propios de la
web:

- **Subida directa de logos** (portada/cliente/pentester) como ficheros,
  sin tocar el servidor a mano.
- Diagrama de red como **grafo interactivo** al estilo VirusTotal Graph:
  fondo oscuro, un icono distinto por tipo de nodo (🌐 dominio, 🦠 CVE,
  💀 leak, ✉️ documento, 🔒 fichero sensible...), arrastrar nodos, buscar,
  mostrar/ocultar categorías.
- Todas las opciones de categorías, api keys, recursividad, proxies y
  compilación del PDF de los informes LaTeX, desde el propio formulario.

---

## Qué genera

Por cada dominio, en su **propia carpeta** `frib1trecon_output/<dominio>/`
(la web hace exactamente lo mismo en `scans/<dominio>/`): nunca se mezclan
resultados de dos dominios distintos, estén en la CLI o en la web.

| Fichero | Contenido |
|---|---|
| `informe.txt` | Resumen legible de un vistazo |
| `informe.docx` | Informe en Word con mini-diagramas de red por sección |
| `informe.xlsx` | Excel con una hoja por categoría |
| `resultados.json` / `.csv` | Datos en bruto |
| `maltego.csv` | Entidades listas para importar en Maltego |
| `red.dot` / `.png` / `.json` | Diagrama de red (fuente, render y datos) |
| `informe.tex` / `.pdf` | El informe técnico (mismo contenido que `informe.txt/docx/xlsx`) en LaTeX, compilado a PDF si tienes `pdflatex` |
| `informe.md` | El texto en bruto del informe técnico en Markdown — para retocar la redacción sin tocar LaTeX |
| **`cyber_health_check.docx`** | Informe ejecutivo de entrega al cliente (portada, metodología, 6 categorías con recomendaciones) |
| **`cyber_health_check.tex` / `.pdf`** | El mismo informe ejecutivo en LaTeX, compilado a PDF si tienes `pdflatex` |
| `cyber_health_check.md` | El texto en bruto del informe ejecutivo en Markdown — mismo propósito que `informe.md` |
| `documentos/` | Ficheros descargados, solo si dijiste que sí |

Con `--recursive`, ese mismo juego de ficheros en la carpeta del dominio ya
incluye el dominio + todos los subdominios juntos (un único informe
completo); cada subdominio además conserva su propia carpeta completa en
`subdominios/<subdominio>/`.

---

## Estructura del proyecto

```
install.sh                 -> instalador todo-en-uno para máquinas nuevas
setup_searxng.py           -> arranca SearXNG en Docker y habilita su modo JSON
frib1trecon/
  cli.py                   -> entrada de línea de comandos (argparse + modo asistente)
  engine.py                -> orquestador del pipeline completo, recursividad por subdominios
  report.py                -> tablas en pantalla + export TXT/JSON/CSV/Excel/Word + diagrama de red
  report_export.py         -> punto único de exportación compartido por CLI y web
  cyber_health_report.py   -> informe ejecutivo DOCX de entrega al cliente
  latex_report.py          -> el mismo informe ejecutivo en LaTeX/PDF/MD
  latex_technical_report.py -> informe técnico (igual que informe.txt/docx/xlsx) en LaTeX/PDF/MD
  latex_common.py          -> preámbulo/paleta/escapado LaTeX compartido por los dos de arriba
  docx_charts.py           -> gráficos nativos de Word (editables) para el informe ejecutivo
  dorks.py                 -> plantillas de dorks (filetype:, site:plataforma, leaks OSINT)
  search.py                -> cliente SearXNG con UA aleatorio, jitter y backoff
  downloader.py            -> descarga de ficheros con límite de tamaño y UA aleatorio
  metadata.py               -> exiftool + fallback pypdf/docx/openpyxl/pptx + grep de credenciales
  dns_whois.py              -> NS/MX/TXT/CAA, SPF/DKIM/DMARC, DNSSEC, AXFR, WHOIS
  tls_headers.py            -> certificado TLS, protocolos obsoletos, cabeceras de seguridad HTTP
  typosquatting.py          -> variantes dnstwist + domain squatting, resolución DNS en paralelo
  subdomain_bruteforce.py   -> subdominios por fuerza bruta DNS (sin api key)
  takeover.py                -> subdomain takeover por CNAME colgante
  cloud_buckets.py           -> enumeración activa de buckets S3/GCS/Azure mal configurados
  eol_check.py                -> fin de soporte de tecnologías vía endoflife.date
  file_sharing.py             -> ficheros sensibles archivados y aún accesibles (Wayback/urlscan.io)
  wayback_check.py            -> URLs archivadas con parámetros sensibles, verificadas en vivo
  sensitive_paths.py          -> rutas sensibles habituales (.env, .git/config, backups...)
  cms_detect.py / cms_checks.py -> identificación de CMS y comprobaciones específicas por CMS
  waf_detect.py               -> detección de WAF/CDN de protección
  fingerprint.py              -> fingerprinting de tecnologías web (whatweb)
  vuln_lookup.py              -> NVD + ExploitDB local (searchsploit) + Sploitus
  external_osint.py           -> Shodan, crt.sh/Certspotter, Wayback, IntelX, GrayHatWarfare...
  keyed_sources.py            -> Censys/FOFA/HIBP/DomScan/OTX (todas con api key opcional del usuario)
  ports_services.py           -> escaneo de puertos y servicios con nmap (activo, opt-in)
  http_client.py / ua.py      -> cliente HTTP y lista de User-Agents compartidos por los checks activos
frib1trecon-web/
  app.py                      -> interfaz Flask, reutiliza frib1trecon/ directamente
  templates/ , static/        -> formulario, resultados, grafo interactivo
```

---

## Desinstalación

`frib1trecon` no toca nada fuera de su propia carpeta ni de un contenedor
Docker con nombre propio — desinstalarlo es sencillo:

```bash
# 1. Para y elimina el contenedor de SearXNG
cd frib1trecon && docker compose down

# 2. (opcional) elimina también la imagen de SearXNG descargada
docker rmi searxng/searxng:latest

# 3. Elimina los entornos virtuales Python
rm -rf frib1trecon/.venv frib1trecon-web/.venv

# 4. Elimina la config local de SearXNG y los resultados de escaneos
rm -rf frib1trecon/searxng frib1trecon/frib1trecon_output frib1trecon-web/scans

# 5. (si instalaste TruffleHog con install.sh) elimina el binario
rm -f ~/.local/bin/trufflehog

# 6. Elimina la propia carpeta del proyecto
cd .. && rm -rf frib1trecon frib1trecon-web
```

Los paquetes del sistema que `install.sh` pudo instalar (`nmap`, `whatweb`,
`graphviz`, `exploitdb`, `whois`, `texlive-latex-base`/`-extra`, `docker.io`)
**no se desinstalan solos** a propósito: son herramientas de uso general que
seguramente quieras conservar para otras cosas. Si de verdad quieres
quitarlas: `sudo apt-get remove nmap whatweb graphviz exploitdb whois
texlive-latex-base texlive-latex-extra`.

---

## Uso responsable

Es una herramienta de reconocimiento **pasivo** por defecto (solo consulta
contenido ya indexado públicamente o APIs públicas tipo NVD/Shodan, no ataca
el servidor del dominio objetivo). Aun así:

- Úsala solo contra dominios propios o con autorización explícita.
- El escaneo de puertos (`--categories ports`) y las comprobaciones de
  CMS/rutas sensibles/WAF SÍ envían tráfico directo al objetivo: actívalas
  solo si el dominio es tuyo o tienes permiso para tráfico activo.
- Respeta los ToS de los motores que SearXNG consulta por detrás: no bajes
  los delays a 0 ni lances cientos de dominios en paralelo.
- Si vas a compartir tu instancia SearXNG con más gente, cambia el binding
  de `127.0.0.1` en `docker-compose.yml` y añade autenticación.
