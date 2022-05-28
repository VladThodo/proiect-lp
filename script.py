"""

Vela Cristian-Rusalin, Todosin Vlad-Alexandru

Scriptul foloseste libraria pyshark (un wrapper Python pentru tshark).
Pentru rularea acestuia este necesar ca tshark sa fie instalat pe sistemul local.

2022

Referinte cod sursa reutilizat:

https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info

"""

import atexit
import pyshark
import argparse
import sys
from colorama import Fore, Style
import csv


def salvare_date():
    # Salvam datele intr-un CSV (cumva)
    print(Style.BRIGHT + Fore.YELLOW + "\nDatele au fost salvate in..")
    print(Style.RESET_ALL + Fore.RESET)


def printare_dns(pkt):
    try:
        if pkt.dns.qry_name:
            print(Style.BRIGHT + Fore.GREEN + 'Cerere DNS de la: ' + Style.NORMAL + Fore.WHITE + '%s: %s' % (pkt.ip.src, pkt.dns.qry_name))
    except AttributeError as e:
        #ignore packets that aren't DNS Request
        pass
    try:
        if pkt.dns.resp_name:
            print(Style.BRIGHT + Fore.YELLOW + 'Raspuns DNS de la: ' + Style.NORMAL + Fore.WHITE + '%s: %s --> %s' % (pkt.ip.src, pkt.dns.resp_name, pkt.dns.a))
    except AttributeError as e:
        #ignore packets that aren't DNS Response
        pass


atexit.register(salvare_date)

parser = argparse.ArgumentParser(description='Monitorizeaza pachetele ce intra/ies din sistem')
parser.add_argument('--dns', action="store_true", help='Afiseaza doar cererile/raspunsurile DNS')
parser.add_argument('--full', action="store_true", help='Afiseaza informatii pe larg despre fiecare pachet')

args = parser.parse_args()

# Verificam daca parametrii de rulare ai programului au fost setati corect sau inchidem programul in caz contrar

if args.dns and args.full:
    print(Style.BRIGHT + Fore.RED + "Nu se pot accepta cele doua argumente simultan.")
    sys.exit()


capture = pyshark.LiveCapture(interface='wlo1')


def print_callback(pkt):
    if args.dns:
        printare_dns(pkt)
    elif args.full:
        print(Style.BRIGHT + Fore.RED + "\n\nA fost primit un pachet de %s octeti\n" % pkt.length)
        pkt.pretty_print()


capture.apply_on_packets(print_callback)

