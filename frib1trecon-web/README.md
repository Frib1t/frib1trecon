# frib1trecon-web

Interfaz web de [frib1trecon](../frib1trecon). Vive en su propia carpeta,
con su propio entorno virtual, para no tocar ni interferir con la CLI
(`frib1trecon/`) — reutiliza su logica importando `frib1trecon.engine`/
`frib1trecon.report` via `sys.path`, sin duplicar codigo ni compartir
proceso. CLI y web producen exactamente los mismos informes porque
comparten el mismo motor.

## Requisitos

- SearXNG ya arrancado (lo levanta `frib1trecon/install.sh` o
  `frib1trecon/setup_searxng.py`). frib1trecon-web no lo gestiona, solo lo consulta.
- Las mismas dependencias que la CLI (`../frib1trecon/requirements.txt`) +
  Flask.
- Opcionales (igual que en la CLI): TruffleHog, `graphviz` (diagrama de
  red en PNG) y `exploitdb`/`searchsploit` (busqueda de exploits local).

## Instalacion

`frib1trecon/install.sh` ya deja `frib1trecon-web/` lista sola si la carpeta
existe junto a `frib1trecon/`. A mano:

```bash
cd frib1trecon-web
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Uso

```bash
.venv/bin/python app.py
```

Abre http://127.0.0.1:5000 — solo escucha en localhost por defecto (esta
herramienta maneja documentos y metadatos de terceros, no la expongas en
red sin anadir autenticacion antes).

**Importante**: si editas codigo en `frib1trecon/frib1trecon/` o en
`frib1trecon-web/`, hay que reiniciar `app.py` para que los cambios surtan
efecto — Flask importa los modulos una sola vez al arrancar, no los
recarga en caliente.

Desde el formulario puedes:
- Elegir si guardar los documentos descargados o descartarlos tras extraer
  metadatos.
- Activar "solo listar URLs" para un analisis rapido sin descargas.
- Buscar empleados en LinkedIn (organigrama aproximado).
- Buscar CVEs/exploits conocidos (NVD + ExploitDB + Sploitus) para el
  software detectado en documentos.
- Consultar fuentes externas (Shodan/crt.sh/Certspotter/Wayback gratis +
  GrayHatWarfare/IntelX/DNSDumpster/VirusTotal/AbuseIPDB con tu api key)
  — esto tambien activa la deteccion de infraestructura cloud
  (AWS/Azure/GCP...).
- Seguir subdominios descubiertos (recursivo, 1 nivel) y escanearlos
  tambien, con limite configurable.
- Ajustar los delays minimo/maximo entre peticiones y apuntar a otra
  instancia SearXNG si tienes mas de una.

El escaneo corre en un hilo en segundo plano; la pagina de progreso se
actualiza sola (polling cada 1.5s) mostrando cada dork y cada fichero
procesado en vivo, para que nunca parezca que se ha quedado colgado
aunque tarde varios minutos (es deliberadamente lento para no bloquearse
contra los motores de busqueda). Al terminar, redirige a una pagina con
las tablas de resultados (documentos, sensibles, plataformas/leaks,
emails, organigrama, fuentes externas/cloud, vulnerabilidades) y enlaces
de descarga: `informe.txt/.docx/.xlsx`, `resultados.json/.csv`,
`maltego.csv`, `red.dot/.png/.json`. Si activaste la recursividad,
ademas aparecen los equivalentes `-maestro` con todos los hosts juntos.

### Grafo de red interactivo

Cada informe incluye un boton "Ver grafo de red interactivo" que abre
`/job/<id>/graph`: el mismo diagrama de red (dominio, subdominios, IPs,
cloud, vulnerabilidades, leaks, plataformas, emails, documentos, ficheros
sensibles y personas) pero navegable en el navegador con
[vis-network](https://visjs.github.io/vis-network/) — arrastra nodos, haz
zoom, busca por nombre, haz clic en un nodo para ver su detalle, y usa las
casillas por categoria para mostrar/ocultar solo lo que te interesa.

## Estructura

```
app.py                       -> servidor Flask (rutas, jobs en memoria + hilo por escaneo)
templates/index.html          -> formulario
templates/job_running.html    -> pagina de progreso en vivo (polling JS)
templates/job_done.html       -> tablas de resultados + descargas
templates/graph.html          -> grafo de red interactivo (vis-network)
templates/help.html           -> pagina de ayuda
static/style.css              -> estilos
scans/<dominio>/              -> salida de cada escaneo (no se sube a git)
```

Una sola carpeta por dominio en `scans/` (igual que la CLI con
`frib1trecon_output/<dominio>/`): nunca se mezclan resultados de dominios
distintos. Si vuelves a escanear el mismo dominio, se sobrescribe su
carpeta — el id de job sigue existiendo como identificador interno de cada
ejecucion (`/job/<id>`), pero ya no forma parte de la ruta en disco.

## Limitaciones conocidas

- Al estar agrupado por dominio (no por job), lanzar dos escaneos del
  mismo dominio en paralelo (dos pestañas a la vez, por ejemplo) hace que
  ambos escriban en la misma carpeta — evita escanear el mismo dominio dos
  veces a la vez.
- Los jobs viven en memoria (`dict` de Python): si reinicias `app.py`
  pierdes el historial de escaneos anteriores (los ficheros ya generados
  en `scans/` siguen ahi, pero la pagina `/job/<id>` deja de funcionar).
  Para un uso serio a largo plazo, cambia `JOBS` por algo persistente
  (SQLite, por ejemplo).
- Servidor de desarrollo de Flask (no pensado para producción ni para
  exponerse a internet tal cual).
