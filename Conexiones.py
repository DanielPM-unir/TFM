import os
import re
import subprocess
import sys
from json import load
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import urlopen


def url_estandarización(sitioweb, verbose):
    if not sitioweb.startswith("http"):
        if not sitioweb.startswith("www."):
            sitioweb = "www." + sitioweb
            if verbose:
                print((" URL arreglada: " + sitioweb))
        sitioweb = "http://" + sitioweb
        if verbose:
            print((" URL arreglada: " + sitioweb))
    return sitioweb


def extraer_dominio(url, eliminar_http=True):
    uri = urlparse(url)
    if eliminar_http:
        nombre_dominio = f"{uri.netloc}"
    else:
        nombre_dominio = f"{uri.scheme}://{uri.netloc}"
    return nombre_dominio


def carpeta_salida(sitioweb, verbose):
    ruta_salida = sitioweb
    if not os.path.exists(ruta_salida):
        os.makedirs(ruta_salida)
    if verbose:
        print(f" Carpeta creada: {ruta_salida}")
    return ruta_salida


def tor_corriendo(verbose):
    checkeo_tor = subprocess.check_output(['ps', '-e'])

    def buscar_palabra_entera(word):
        return re.compile(r'\b({0})\b'.format(word),flags=re.IGNORECASE).search

    if buscar_palabra_entera('tor')(str(checkeo_tor)):
        if verbose:
            print(" TOR está corriendo")
    else:
        print(" TOR no está corriendo.\n activa TOR mediante cmd con \'service tor start\' o añade el argumento -w")
        sys.exit(2)


def devuelve_ip():
    ruta = 'https://api.ipify.org/?format=json'
    try:
        mi_ip = load(urlopen(ruta))['ip']
        print(f'Tu IP: {mi_ip}')
    except HTTPError as err:
        error = sys.exc_info()[0]
        print(f"Error: {error} \n  no se pudo obtener la IP. \n## ¿Está la api {ruta} activa?\n HTTPError: {err}")