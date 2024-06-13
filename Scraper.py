import io
import os
import urllib.error
import urllib.parse
import urllib.request
from urllib.error import HTTPError
from urllib.error import URLError
from http.client import InvalidURL
from http.client import IncompleteRead

from bs4 import BeautifulSoup


def text(response=None):
    soup = BeautifulSoup(response, features="lxml")
    for s in soup(['script', 'style']):
        s.decompose()

    return ' '.join(soup.stripped_strings)

def check_yara(raw=None, yara=0):
    try:
        import yara as _yara #hay que instalar
    except OSError:
        print("YARA module error: " + 
              "Try this solution: https://stackoverflow.com/a/51504326")

    file_path = os.path.join('res/keywords.yar')

    if raw is not None:
        if yara == 1:
            raw = text(response=raw).lower()

        file = os.path.join(file_path)
        rules = _yara.compile(file)
        matches = rules.match(data=raw)
        if len(matches) != 0:
            print("YARA: Match!")
        return matches


def cinex(archivo_entrda, ruta_salida, yara=None):
    file = io.TextIOWrapper
    try:
        file = open(archivo_entrda, 'r')
    except IOError as err:
        print(f"Error: {err}\n No se puede abrir el archivo: {archivo_entrda}")

    for line in file:

        # Generate the name for every file.
        try:
            page_name = line.rsplit('/', 1)
            cl_page_name = str(page_name[1])
            cl_page_name = cl_page_name[:-1]
            if len(cl_page_name) == 0:
                archivo_salida = "index.htm"
            else:
                archivo_salida = cl_page_name
        except IndexError as error:
            print(f"Error: {error}")
            continue

        # Extraer página a archivo.
        try:
            content = urllib.request.urlopen(line, timeout=10).read()

            if yara is not None:
                full_match_keywords = check_yara(content, yara)

                if len(full_match_keywords) == 0:
                    print('No hay ningún match.')
                    continue

            with open(ruta_salida + "/" + archivo_salida, 'wb') as results:
                results.write(content)
            print(f"Archivo creado en: {os.getcwd()}/{ruta_salida}/{archivo_salida}")
        except HTTPError as e:
            print(f"Cinex Error: {e.code}, No se puede acceder a : {e.url}")
            continue
        except InvalidURL as e:
            print(f" URL inválida: {line} \n Omitiendo...")
            continue
        except IncompleteRead as e:
            print(f"Lectura incompleta en la línea: {line}")
            continue
        except IOError as err:
            print(f"Error: {err}\n No se pudo escribir en el archivo de salida: {archivo_salida}")
    file.close()


def intermex(archivo_entrada, yara):
    try:
        with open(archivo_entrada, 'r') as file:
            for line in file:
                content = urllib.request.urlopen(line).read()
                if yara is not None:
                    full_match_keywords = check_yara(raw=content, yara=yara)

                    if len(full_match_keywords) == 0:
                        print(f"No se encontraron ningún match: {line}")
                print(content)
    except (HTTPError, URLError, InvalidURL) as err:
        print(f" Error a la hora de conectar: {err}")
    except IOError as err:
        print(f"Error: {err}\n Archivo no válido.")


def outex(sitioweb, archivo_salida, ruta_salida, yara):
    # Extraer página a archivo.
    try:
        archivo_salida = ruta_salida + "/" + archivo_salida
        content = urllib.request.urlopen(sitioweb).read()

        if yara != None:
            full_match_keywords = check_yara(raw=content, yara=yara)

            if len(full_match_keywords) == 0:
                print(f"No se han encontrado ningún match en: {sitioweb}")

        with open(archivo_salida, 'wb') as file:
            file.write(content)
        print(f"Archivo creado en: {os.getcwd()}/{archivo_salida}")
    except (HTTPError, URLError, InvalidURL) as err:
        print(f" Error HTTP: {err}")
    except IOError as err:
        print(f"Error: {err}\n No se pudo escribir en el archivo de salida: {archivo_salida}")


def termex(sitioweb, yara):
    try:
        content = urllib.request.urlopen(sitioweb).read()
        if yara is not None:
            full_match_keywords = check_yara(content, yara)

            if len(full_match_keywords) == 0:
                # No match.
                print(f"No se han encontrado ningún match en: {sitioweb}")
                return

        print(content)
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"Error: ({err}) {sitioweb}")
        return


def scraper(sitioweb, crawl, archivo_salida, archivo_entrada, ruta_salida, yara_lista):
    if len(archivo_entrada) > 0:
        if crawl:
            cinex(archivo_entrada, archivo_salida, yara_lista)
        else:
            intermex(archivo_entrada, yara_lista)
    else:
        if len(archivo_salida) > 0:
            outex(sitioweb, archivo_salida, ruta_salida, yara_lista)
        else:
            termex(sitioweb, yara_lista)