
import Scraper
import requests

def main():
    print ("esto no puede estar vacio")


if __name__ == "__main__":
  print("Tu IP es :")
  print(" ")
  api = "http://ip-api.com/json/"
  petición = requests.get(api)
  print(petición.text)
  print()
  #Scraper.Scraper()