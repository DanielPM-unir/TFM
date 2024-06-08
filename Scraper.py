

def Scraper():
    cm = Conexiones(10)

    api = "http://ip-api.com/json/"
    conexión = cm.request(url)
    print("IP de TOR:")
    print("=======")
    print(api.data.decode('utf-8'))
    print()