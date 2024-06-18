#!/usr/bin/python
"""
TorCrawl.py es un script de Python para rastrear y extraer (webpages regulares o onion)
a través de la red TOR.

usage: python torcrawl.py [options]
python torcrawl.py -u l0r3m1p5umD0lorS1t4m3t.onion
python torcrawl.py -v -w -u http://www.github.com -o github.htm
python torcrawl.py -v -u l0r3m1p5umD0lorS1t4m3t.onion -c -d 2 -p 5
python torcrawl.py -v -w -u http://www.github.com -c -d 2 -p 5 -e -f GitHub

General:
-h, --help         : Ayuda
-v, --verbose      : Mostrar más información sobre el progreso
-u, --url *.onion  : URL de la página web para rastrear o extraer
-w, --without      : Sin el uso de Relay TOR

Extract:
-e, --extract           : Extraer el código de la página a la terminal o archivo.
                          (Por defecto: terminal)
-i, --input filename    : Archivo de entrada con URL(s) (separados por línea)
-o, --output [filename] : Salida de la(s) página(s) a archivo(s) (para una página)
-y, --yara              : Búsqueda de palabras clave con Yara para la categorización de páginas
                            leídas desde la carpeta /res. 
                            'h' busca en todo el objeto html.
                            't' busca solo en el texto.

Crawl:
-c, --crawl       : Rastrea el sitio web (Salida por defecto en /links.txt)
-d, --cdepth      : Establecer profundidad del rastreo (Por defecto: 1)
-z, --exclusions  : Rutas que no deseas incluir (TODO)
-s, --simultaneous: Cuántas páginas visitar al mismo tiempo (TODO)
-p, --pause       : La duración de la pausa del rastreador entre páginas.
                    (Por defecto: 0)
-f, --folder      : El directorio raíz que contendrá los archivos generados
-l, --log         : Archivo log con las URLs visitadas y su código de respuesta.

GitHub: github.com/MikeMeliz/TorCrawl.py
Licencia: GNU General Public License v3.0

"""

import argparse
import os
import socket
import sys
import datetime

import socks  # pysocks necesita instalación con pip install pysocks

from Conexiones import devuelve_ip
from Conexiones import tor_corriendo
from Conexiones import extraer_dominio
from Conexiones import carpeta_salida
from Conexiones import url_estandarización
# Módulos de TorCrawl
from Crawler import Crawler
from Scraper import scraper


# Configurar el socket y la conexión con la red TOR
def connect_tor():
    try:
        port = 9050
        # Configurar el proxy de socks y envolver el módulo urllib
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', port)
        socket.socket = socks.socksocket

        # Realizar resolución DNS a través del socket
        def getaddrinfo(*args):  # noqa
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

        socket.getaddrinfo = getaddrinfo  # noqa
    except socks.HTTPError as err:
        error = sys.exc_info()[0]
        print(f"Error: {error} \n No se pudo establecer conexión con TOR\n HTTPError: {err}")


def main():
    # Obtener argumentos con argparse.
    parser = argparse.ArgumentParser(
        description="Este buscador es un script de Python que nos permite rastrear y extraer datos de TOR o la red normal.")

    # General
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Muestra más información en todo el proceso, errores, procesos...'
    )
    parser.add_argument(
        '-u',
        '--url',
        help='URL en la que ejecutar el script'
    )
    parser.add_argument(
        '-w',
        '--without',
        action='store_true',
        help='Ejecución en la red de Internet.'
    )

    # Extract
    parser.add_argument(
        '-e',
        '--extract',
        action='store_true',
        help='Extraer páginas a la terminal o archivo.'
    )
    parser.add_argument(
        '-i',
        '--input',
        help='Archivo de entrada de URLS (separados por líneas)'
    )
    parser.add_argument(
        '-o',
        '--output',
        help='Páginas de salida por archivo'
    )

    # Crawl
    parser.add_argument(
        '-c',
        '--crawl',
        action='store_true',
        help='Rastrea el sitio web (Por defecto el archivo /links.txt)'
    )
    parser.add_argument(
        '-d',
        '--cdepth',
        help='Establecer profundidad del rastreador (Por defecto en: 1)'
    )
    parser.add_argument(
        '-p',
        '--pause',
        help='Duración del retardo del rastreador entre páginas.'
    )
    parser.add_argument(
        '-l',
        '--log',
        action='store_true',
        help='Crea un archivo log en el que se ven las páginas que se han visitado con su código de respuesta'
    )
    parser.add_argument(
        '-f',
        '--folder',
        help='El directorio en el cual se van a generar los archivos.'
    )
    parser.add_argument(
        '-y',
        '--yara',
        help='Buscar palabras clave con Yara y solo extraer documentos que contienen un match.\'h\' Busca en todos los objetos html. \'t\' Busca solo en el texto.'
    )

    args = parser.parse_args()

    # Parsear argumentos a variables o iniciar variables.
    archivo_entrada = args.input if args.input else ''
    archivo_salida = args.output if args.output else ''
    profundidad = int(args.cdepth) if args.cdepth else 0
    retardo = int(args.pause) if args.pause else 1
    yara_lista = args.yara if args.yara else None

    # Conectar a TOR
    if not args.without:
        tor_corriendo(args.verbose)
        connect_tor()

    if args.verbose:
        devuelve_ip()
        print(('URL: ' + args.url))

    sitioweb = ''
    ruta_salida = ''

    # Canonicalización de la URL web y crear la ruta para la salida.
    if len(args.url) > 0:
        sitioweb = url_estandarización(args.url, args.verbose)
        if args.folder is not None:
            ruta_salida = carpeta_salida(args.folder, args.verbose)
        else:
            ruta_salida = carpeta_salida(extraer_dominio(sitioweb), args.verbose)

    if args.crawl:
        crawler = Crawler(sitioweb, profundidad, retardo, ruta_salida, args.log, args.verbose)
        lst = crawler.crawl()

        now = datetime.datetime.now().strftime("%Y%m%d")
        with open(ruta_salida + '/' + now + '_links.txt', 'w+', encoding='UTF-8') as file:
            for item in lst:
                file.write(f"{item}\n")
        print(f"## File created on {os.getcwd()}/{ruta_salida}/links.txt")

        if args.extract:
            archivo_entrada = ruta_salida + "/links.txt"
            scraper(sitioweb, args.crawl, archivo_salida, archivo_entrada, ruta_salida, yara_lista)
    else:
        scraper(sitioweb, args.crawl, archivo_salida, archivo_entrada, ruta_salida, yara_lista)


# Stub to call main method.
if __name__ == "__main__":
    main()
