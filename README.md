<p align="center">
  <img src="frib1trecon/assets/frib1trecon_logo.png" alt="frib1trecon" width="120">
</p>

<h1 align="center">frib1trecon</h1>

<p align="center">
  <strong>Reconocimiento OSINT pasivo para Linux</strong> — dorking, metadatos,
  leaks públicos, postura DNS/TLS, vulnerabilidades conocidas y typosquatting,
  con informes listos para entregar (TXT, Word, Excel, DOCX/LaTeX/PDF
  ejecutivo) y una interfaz web opcional.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Debian%20%7C%20Kali%20%7C%20Ubuntu-informational?logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/estado-activo-success" alt="Status">
  <img src="https://img.shields.io/badge/reconocimiento-100%25%20pasivo%20por%20defecto-orange" alt="OSINT">
  <img src="https://img.shields.io/badge/licencia-Apache%202.0-lightgrey" alt="Licencia Apache 2.0">
</p>

<p align="center">
  <img src="frib1trecon/docs/screenshots/demo.gif" alt="Demo de frib1trecon encontrando un leak" width="820">
</p>

<p align="center"><sub>Datos sintéticos de ejemplo — no corresponden a ningún dominio real.</sub></p>

---

## Estructura del repositorio

Este repositorio contiene dos proyectos hermanos, pensados para usarse juntos
pero con entornos virtuales independientes:

| Carpeta | Qué es | README |
|---|---|---|
| [`frib1trecon/`](frib1trecon/) | CLI: el motor de reconocimiento, instalador (`install.sh`) y generación de todos los informes | [frib1trecon/README.md](frib1trecon/README.md) |
| [`frib1trecon-web/`](frib1trecon-web/) | Interfaz web opcional (Flask) sobre el mismo motor — mismos informes, sin terminal | [frib1trecon-web/README.md](frib1trecon-web/README.md) |

`frib1trecon-web` importa directamente el motor de `frib1trecon` (no duplica
lógica ni comparte proceso), así que ambas carpetas deben vivir una al lado
de la otra, tal como están en este repo.

## Instalación rápida

```bash
git clone https://github.com/Frib1t/frib1trecon.git
cd frib1trecon/frib1trecon
# ^ el primer "frib1trecon" es el repo clonado; el segundo, la carpeta de la CLI
./install.sh
```

`install.sh` instala dependencias, levanta tu propia instancia de SearXNG
(Docker) y deja `frib1trecon-web/` lista si la carpeta existe junto a
`frib1trecon/` — ver cada README para el detalle completo (uso, categorías,
API keys opcionales, interfaz web).

## Licencia

[Apache License 2.0](LICENSE).
