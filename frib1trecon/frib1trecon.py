#!/usr/bin/env python3
"""
Punto de entrada directo: permite lanzar la herramienta como
    .venv/bin/python frib1trecon.py site.com [opciones]
en vez de `python3 -m frib1trecon.cli site.com` (ambas formas funcionan
igual, esta es solo mas corta de escribir/recordar).
"""
from frib1trecon.cli import main

if __name__ == "__main__":
    main()
