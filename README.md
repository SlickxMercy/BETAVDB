# BETAVDB

###
```bash

pip install httpx requests colorama loguru pycryptodome
```
```bash 
cd storage/download/
```
```bash
git clone https://github.com/SlickxMercy/BETAVDB
```
#### Fuerza bruta 
```bash
cd storage/download/BETAVDB 
```
```bash
python hikvision.py scan -H target.txt -u user.txt -p pass.txt -P 80 -t 15 -c 100
```
```
python hikvision.py hikvision
```
```
python hikvision.py cve2017
```
```
python hikvision.py cve2021
```

### BETAVDB 
Escáner de cámaras web y explotación de vulnerabilidades Hikvision con cuatro modos:
  1. scan: Escaneo asíncrono para obtener snapshots usando combinaciones de credenciales.(Lento)
  2. cve2017: Explotación de CVE-2017-7921 (descifrado del archivo de configuración).(aun no funciona)
  3. cve2021: Explotación de CVE-2021-33044 (bypass de autenticación).(aun no funciona)
  4. hikvision: Explotación de la vulnerabilidad de weak password en dispositivos Hikvision.(Es una versión mas optimizada y mejorada por lo cual la recomiendo)
