"""

Vela Cristian-Rusalin, Todosin Vlad-Alexandru

Scriptul foloseste libraria pyshark (un wrapper Python pentru tshark).
Pentru rularea acestuia este necesar ca tshark sa fie instalat pe sistemul local.

2022

Referinte cod sursa reutilizat si documentatie folosita:

https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info
https://docs.python.org/3/library/atexit.html

"""

import atexit
import pyshark
import argparse
import sys
from colorama import Fore, Style
import csv

CSV_FILE = "capture.csv"
NET_INTERFACE = "wlo1"


# Functie apelata in momentul in care programul se inchide
#

def salvare_date():
    # Salvam datele intr-un CSV (cumva)
    print(Style.BRIGHT + Fore.YELLOW + "\nDatele au fost salvate in..")
    print(Style.RESET_ALL + Fore.RESET)


def printare_dns(pkt):
    try:
        if pkt.dns.qry_name:
            print(Style.BRIGHT + Fore.GREEN + 'Cerere DNS de la: ' + Style.NORMAL + Fore.WHITE + '%s: %s' % (pkt.ip.src, pkt.dns.qry_name))
    except AttributeError as e:
        # pachetul nu este de tip DNS
        pass
    try:
        if pkt.dns.resp_name:
            print(Style.BRIGHT + Fore.YELLOW + 'Raspuns DNS de la: ' + Style.NORMAL + Fore.WHITE + '%s: %s --> %s' % (pkt.ip.src, pkt.dns.resp_name, pkt.dns.a))
    except AttributeError as e:
        # pachetul nu este de tip DNS
        pass


atexit.register(salvare_date)

parser = argparse.ArgumentParser(description='Monitorizeaza pachetele ce intra/ies din sistem')
parser.add_argument('--dns', action="store_true", help='Afiseaza doar cererile/raspunsurile DNS')
parser.add_argument('--full', action="store_true", help='Afiseaza informatii pe larg despre fiecare pachet')
parser.add_argument('--brief', action="store_true", help="Afiseaza informatii pe scurt despre fiecare pachet (lungime/IP sursa, IP destinatie - daca sunt disponibile)")
parser.add_argument('--interfata', type=str, help="Interfata de internet de unde se doreste vizualizarea pachetelor (standard: wlo1)")
parser.add_argument('-f', type=str, help="Fisierul in care se stocheaza datele in format CSV (standard: capture.csv)")

args = parser.parse_args()

# Verificam daca parametrii de rulare ai programului au fost setati corect sau inchidem programul in caz contrar

if args.dns and args.full or args.dns and args.brief or args.full and args.brief or args.full and args.brief and args.dns:
    print(Style.BRIGHT + Fore.RED + "Nu se pot accepta argumentele simultan.")
    sys.exit()


if args.f:
    CSV_FILE = args.f

if args.interfata:
    NET_INTERFACE = args.interfata

capture = pyshark.LiveCapture(interface='wlo1')


def print_callback(pkt):
    if args.dns:
        printare_dns(pkt)
    elif args.full:
        print(Style.BRIGHT + Fore.RED + "\n\nA fost primit un pachet de %s octeti\n" % pkt.length)
        pkt.pretty_print()
    elif args.brief:
        print(Style.BRIGHT + Fore.RED + "\n\nA fost primit un pachet de %s octeti\n" % pkt.length)


capture.apply_on_packets(print_callback)

