# Proiect Limbaje de Programare 2

### Descriere

Script ce analizeaza pachetele ce intra/ies din reteaua sistemului pe care ruleaza. Bazat pe pyshark, un wrapper Python pentru tshark (necesita wireshark instalat pe sistemul pe care ruleaza).

### Dependente

Module utilizate:
 - Colorama
 - Pyshark
 - Atexit
 - CSV
 - Argparse
 - Sys

### Utilizare

Argumente:
 - `-f FILE` permite selectarea fisierului in care vor fi salvate datele in format CSV
 - `--interfata INTERFATA` permite selectarea interfetei de la care se va efectua captura
 - `--dns` analizeaza doar cererile si raspunsurile de tip DNS
 - `--full` afiseaza informatii detaliate despre fiecare pachet in parte
 - `--brief` afiseaza informatii pe scurt despre fiecare pachet
 - `--help` afiseaza argumentele suportate si o scurta descriere a functionalitatii scriptului
 

### Rulare:

Intregul proiect poate fi clonat local folosind:

```
git clone https://github.com/VladThodo/proiect-lp.git
```
Si mai apoi rulat, daca sunt indeplinite dependentele, folosind:

```
cd proiect-lp
python3 script.py
```

Sau, dupa caz:

```
cd proiect-lp
python script.py
```

In lipsa oricaror argumente, scriptul afiseaza informatii detaliate despre pachetele capturate de la prima interfata detectata de tshark in sistem si salveaza datele in fisierul `capture.csv`.


### Colaboratori 

<a href="https://github.com/VladThodo/proiect-lp/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=VladThodo/proiect-lp" />
</a>
