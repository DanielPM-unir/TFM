import http.client
import sys
import time
import urllib.request
import re
from urllib.error import URLError, HTTPError
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self,sitioweb,profundidad, retardo, verbose, log, ruta_salida):
        self.sitioweb = sitioweb
        self.profundidad = profundidad
        self.retardo = retardo
        self.ruta_salida = str(ruta_salida)
        self.verbose = verbose
        self.log = log
        


    def estandarización(self, url):

        if url.startswith(self.sitioweb):   #mirar funcion starts with
            return url
        elif url.startswith('/'):
            if self.sitioweb[-1] == '/':
                url_final = self.sitioweb [:-1] + url
            else:
                url_final = self.sitioweb + url
            return url_final
        elif re.search('^.*\\.(html|htm|aspx|php|doc|css|js|less)$', url, re.IGNORECASE):
            if self.sitioweb[-1] == '/':
                url_final = self.sitioweb + url
            else:
                url_final = self.sitioweb + "/" + url
            return url_final
        


        pass

    def crawl(self):
        #queremos que nos retorne una lista de los links que encuentra -> lo tenemos que escalar a la bbdd.
        lista = set()
        lista_limpia = []
        lista_limpia.insert(0,self.sitioweb)
        lista_limpia_indice = 0
        if isinstance(self.ruta_salida, str):
            ruta_log = self.ruta_salida + '/log.txt'
        else:
            print("Error: ruta_salida no está definida correctamente como una cadena.")

        print(f" El crawler está activo en el sitio {self.sitioweb} con la profundidad {self.profundidad} y {self.retardo} segundos de delay.")

        #definir profundidad

        for index in range(0, int(self.profundidad)):
            for item in lista_limpia:
                pagina_html = http.client.HTTPResponse
                #comprobar primer elemento ahora
                if lista_limpia_indice > 0:
                    try:
                        if item != None:
                            pagina_html = urllib.request.urlopen(item)
                    except(HTTPError, URLError) as error:
                        print(f"Error al intentar acceder a la página, para ver el error, por favor, ejecuta el modo -v verbose.")
                        if self.verbose:
                            print(error)
                        continue
                else:
                    try:
                        pagina_html = urllib.request.urlopen(self.sitioweb)
                        lista_limpia_indice += 1
                    except(HTTPError, URLError) as error:
                        print(f"Error al intentar acceder a la página, para ver el error, por favor, ejecuta el modo -v verbose.")
                        if self.verbose:
                            print(error)
                        lista_limpia_indice += 1
                        continue
                try:
                    sopa = BeautifulSoup(pagina_html, features="html.parser")
                except TypeError as error2:
                    print(f"Error encontrado, {lista_limpia_indice}::{lista_limpia[lista_limpia_indice]}")
                    continue

                for url in sopa.findAll('a'):
                    url = url.get('href')  #revisar el get
                    #aqui meter funcion de excluir links.
                    ver_url = self.estandarización(url)
                    if ver_url != None:
                        lista.add(ver_url)

                for url in sopa.findAll('area'):
                    url = url.get('href')  #revisar el get
                    #aqui meter funcion de excluir links.
                    ver_url = self.estandarización(url)
                    if ver_url != None:
                        lista.add(ver_url)


                #limpiar la lista de duplicados
                lista_limpia = lista_limpia + list(set(lista))
                lista_limpia = list(set(lista_limpia))

                if self.verbose:
                    sys.stdout.write(" El número de resultados es" + str(len(lista_limpia)))
                    sys.stdout.flush()

                #controlar el tiempo de retardo
                if (lista_limpia.index(item) != len(lista_limpia) -1) and float(self.retardo) > 0:
                    time.sleep(float(self.retardo))

                #logs    
                if self.log:
                    codigo_respuesta = pagina_html.getcode() 
                    with open(ruta_log, 'w+', encoding='UTF-8') as archivo_log:
                        archivo_log.write(f"[{str(codigo_respuesta)}] {str(item)} \n")
            print(f"## Fase {str(index + 1)} completada con: {str(len(lista_limpia))} resultado(s)")
        return lista_limpia