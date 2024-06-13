#!/usr/bin/python
"""
TorCrawl.py is a python script to crawl and extract (regular or onion)
webpages through TOR network.

usage: python torcrawl.py [options]
python torcrawl.py -u l0r3m1p5umD0lorS1t4m3t.onion
python torcrawl.py -v -w -u http://www.github.com -o github.htm
python torcrawl.py -v -u l0r3m1p5umD0lorS1t4m3t.onion -c -d 2 -p 5
python torcrawl.py -v -w -u http://www.github.com -c -d 2 -p 5 -e -f GitHub

General:
-h, --help         : Help
-v, --verbose      : Show more informations about the progress
-u, --url *.onion  : URL of Webpage to crawl or extract
-w, --without      : Without the use of Relay TOR

Extract:
-e, --extract           : Extract page's code to terminal or file.
                          (Defualt: terminal)
-i, --input filename    : Input file with URL(s) (seperated by line)
-o, --output [filename] : Output page(s) to file(s) (for one page)
-y, --yara              : Yara keyword search page categorisation
                            read in from /res folder. 
                            'h' search whole html object.
                            't' search only the text.

Crawl:
-c, --crawl       : Crawl website (Default output on /links.txt)
-d, --cdepth      : Set depth of crawl's travel (Default: 1)
-z, --exclusions  : Paths that you don't want to include (TODO)
-s, --simultaneous: How many pages to visit at the same time (TODO)
-p, --pause       : The length of time the crawler will pause
                    (Default: 0)
-f, --folder	  : The root directory which will contain the
                    generated files
-l, --log         : Log file with visited URLs and their response code.

GitHub: github.com/MikeMeliz/TorCrawl.py
License: GNU General Public License v3.0

"""

import argparse
import os
import socket
import sys
import datetime

import socks  # noqa - pysocks hay que hacer pip install

from Conexiones import devuelve_ip
from Conexiones import tor_corriendo
from Conexiones import extraer_dominio
from Conexiones import carpeta_salida
from Conexiones import url_estandarización
# TorCrawl Modules
from Crawler import Crawler
from Scraper import scraper


# Set socket and connection with TOR network
def connect_tor():

    try:
        port = 9050
        # Set socks proxy and wrap the urllib module
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', port)
        socket.socket = socks.socksocket

        # Perform DNS resolution through the socket
        def getaddrinfo(*args):  # noqa
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '',
                     (args[0], args[1]))]

        socket.getaddrinfo = getaddrinfo  # noqa
    except socks.HTTPError as err:
        error = sys.exc_info()[0]
        print(f"Error: {error} \n No se pudo establecer conexión con TOR\n HTTPError: {err}")


def main():
    # Get arguments with argparse.
    parser = argparse.ArgumentParser(
        description="Este buscadores un script de python que nos permite crawlear y scrapear datos de TOR o la red normal.")

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
        help='Crawl sitioweb (Por defecto el archivo /links.txt)'
    )
    parser.add_argument(
        '-d',
        '--cdepth',
        help='Establecer profundidad del crawler (Por defecto en: 1)'
    )
    parser.add_argument(
        '-p',
        '--cpause',
        help='Duración del retardo del crawler entre páginas.'
    )
    parser.add_argument(
        '-l',
        '--log',
        action='store_true',
        help='Crea un archivo log en el que se ve las páginas que se han visitado con su código de respuesta'
    )
    parser.add_argument(
        '-f',
        '--folder',
        help='El directorio en el cual se van a generar los archivos.'
    )
    parser.add_argument(
        '-y',
        '--yara',
        help='Checkear por palabras y solo extrae documentos que contienen un match.\'h\' Busca en todos los objetos html. \'t\' Busca solo en el texto.'
    )

    args = parser.parse_args()

    # Parse arguments to variables else initiate variables.
    archivo_entrada = args.entrada if args.entrada else ''
    archivo_salida = args.salida if args.salida else ''
    profundidad = args.profundidad if args.profundidad else 0
    retardo = args.retardo if args.retardo else 1
    yara_lista = args.yara if args.yara else None

    # Connect to TOR
    if args.without is False:
        tor_corriendo(args.verbose)
        connect_tor()

    if args.verbose:
        devuelve_ip()
        print(('URL: ' + args.url))

    sitioweb = ''
    ruta_salida = ''

    # Canonicalization of web url and create path for output.
    if len(args.url) > 0:
        sitioweb = url_estandarización(args.url, args.verbose)
        if args.carpeta is not None:
            ruta_salida = carpeta_salida(args.carpeta, args.verbose)
        else:
            ruta_salida = carpeta_salida(extraer_dominio(sitioweb), args.verbose)

    if args.crawl:
        crawler = Crawler(sitioweb, profundidad, retardo, ruta_salida, args.log,
                          args.verbose)
        lst = crawler.crawl()

        now = datetime.datetime.now().strftime("%Y%m%d")
        with open(ruta_salida + '/' + now + '_links.txt', 'w+', encoding='UTF-8') as file:
            for item in lst:
                file.write(f"{item}\n")
        print(f"## File created on {os.getcwd()}/{ruta_salida}/links.txt")

        if args.extract:
            archivo_entrada = ruta_salida + "/links.txt"
            scraper(sitioweb, args.crawl, archivo_salida, archivo_entrada, ruta_salida,
                      yara_lista)
    else:
        scraper(sitioweb, args.crawl, archivo_salida, archivo_entrada, ruta_salida,
                  yara_lista)


# Stub to call main method.
if __name__ == "__main__":
    main()