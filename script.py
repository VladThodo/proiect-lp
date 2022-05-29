"""

Vela Cristian-Rusalin, Todosin Vlad-Alexandru

Scriptul foloseste libraria pyshark (un wrapper Python pentru tshark).
Pentru rularea acestuia este necesar ca tshark sa fie instalat pe sistemul local.

2022

Referinte cod sursa reutilizat si documentatie folosita:

https://www.geeksforgeeks.org/working-csv-files-python/
https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info
https://docs.python.org/3/library/atexit.html

"""

import atexit
import pyshark
import argparse
import sys
from colorama import init, Fore, Style
import csv

CSV_FILE = "capture.csv"
NET_INTERFACE = "wlo1"
CAPTURE_LIST = []


# Functie apelata in momentul in care programul se inchide
#

def salvare_date():
    # Salvam datele intr-un CSV
    print(Style.RESET_ALL + Fore.RESET)

    if len(CAPTURE_LIST) > 0:
        try:
            with open(CSV_FILE, 'w') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerows(CAPTURE_LIST)
            print(Style.BRIGHT + Fore.YELLOW + "\nDatele au fost salvate in "+CSV_FILE)
        except:
            print(Style.BRIGHT + Fore.RED + "\nA fost intampinata o problema la scrierea datelor")




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


init()
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
    if args.brief:
        capture = pyshark.LiveCapture(interface=NET_INTERFACE, only_summaries=True)
    else:
        capture = pyshark.LiveCapture(interface=NET_INTERFACE)
else:
    if args.brief:
        capture = pyshark.LiveCapture(only_summaries=True)
    else:
        capture = pyshark.LiveCapture()


def print_callback(pkt):
    if args.dns:
        printare_dns(pkt)
    elif args.full:
        print(Style.BRIGHT + Fore.RED + "\n\nA fost primit un pachet de %s octeti\n" % pkt.length)
        pkt.pretty_print()
    elif args.brief:
        print(pkt)
    else:
        print(pkt)
    CAPTURE_LIST.append(pkt)


capture.apply_on_packets(print_callback)

