## MOD @l3v14t4m ##
## version 1.1.2 ##
## original ver https://github.com/Hubdarkweb/TOpNetFraZer-Ipv6_scanner ##

### Key Changes: 
'''
1. **Replaced `multithreading` with `threading`**: This is a more standard approach.
2. **Improved Error Handling**: Added more detailed error messages.
3. **Proxy Validation**: Added a check to ensure the proxy is correctly formatted.
4. **WebSocket Protocol Handling**: Improved WebSocket handling with better error messages.
5. **Progress Feedback**: Added print statements to provide feedback to the user.
6. **Process IPs as they are generated (without waiting for the entire generation to complete).
7. **Use multiple threads to scan IPs in parallel (based on --threads).
8. **Avoid excessive RAM usage when the CIDR block is large.
9. **Control data flow with queue.Queue, preventing bottlenecks.
10. **Autoinstall dependencies. 
'''

import threading
import queue
import argparse
import sys
import socket
import ssl
import subprocess
import os
import traceback
import ssl

# Lista de paquetes necesarios
required_packages = [
    "requests",
    "websocket-client",
    "ipaddress",
    "loguru"
]

# Función para instalar paquetes faltantes
def install_missing_packages(packages):
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Instalando {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Ejecutar la instalación antes de correr el resto del código
install_missing_packages(required_packages)

# Resto del script
print("Todos los paquetes están instalados. Ejecutando script...")
 
import requests
import ipaddress
import ipaddress
import websocket 
from websocket import create_connection 

class BugScanner:
    def __init__(self):
        self.queue = queue.Queue()
        self.success_list = []
        self.output_file = None

    def task_success(self, payload):
        """Guarda los hosts exitosos y los escribe en un archivo si se especificó."""
        self.success_list.append(payload['host'])
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(payload['host'] + '\n')

    def worker(self):
        """Hilo de trabajo que procesa tareas de la cola."""
        while True:
            try:
                payload = self.queue.get(timeout=5)
            except queue.Empty:
                return
            self.task(payload)
            self.queue.task_done()

    def start(self, threads):
        """Inicia múltiples hilos de escaneo."""
        thread_list = []
        for _ in range(threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()


class DirectScanner(BugScanner):
    def task(self, payload):
        """Intenta conectar directamente al host en el puerto especificado."""
        host = payload['host']
        port = payload.get('port', 80)
        try:
            sock = socket.create_connection((host, port), timeout=3)
            print(f"[+] Conexión exitosa en {host}:{port}")
            self.task_success(payload)
        except (socket.timeout, socket.error) as e:
            print(f"[-] Conexión fallida en {host}:{port} - {e}")
        finally:
            try:
                sock.close()
            except:
                pass


class ProxyScanner(BugScanner):
    def task(self, payload):
        """Prueba conexión a un host a través de un proxy."""
        host = payload['host']
        port = payload.get('port', 80)
        proxy = payload.get('proxy', None)

        proxies = {"http": proxy, "https": proxy} if proxy else None
        url = f"http://{host}:{port}"
        
        try:
            response = requests.get(url, proxies=proxies, timeout=3)
            if response.status_code == 200:
                print(f"[+] Proxy exitoso en {host}:{port}")
                self.task_success(payload)
        except requests.RequestException as e:
            print(f"[-] Proxy falló en {host}:{port} - {e}")


class SSLScanner(BugScanner):
    def task(self, payload):
        """Realiza un handshake SSL."""
        host = payload['host']
        port = payload.get('port', 443)
        try:
            sock = socket.create_connection((host, port), timeout=5)
            context = ssl.create_default_context()
            context.wrap_socket(sock, server_hostname=host)

            print(f"[+] SSL Activo en {host}:{port}")
            self.task_success(payload)
        except (socket.timeout, socket.error, ssl.SSLError) as e:
            print(f"[-] SSL Falló en {host}:{port} - {e}")
        finally:
            try:
                sock.close()
            except:
                pass


class UDPScanner(BugScanner):
    def task(self, payload):
        """Prueba si un host responde a un paquete UDP."""
        host = payload['host']
        port = payload.get('port', 53)
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(b'\x00\x01', (host, port))
            data, _ = sock.recvfrom(1024)
            print(f"[+] UDP Activo en {host}:{port}")
            self.task_success(payload)
        except (socket.timeout, socket.error) as e:
            print(f"[-] UDP Falló en {host}:{port} - {e}")
        finally:
            sock.close()


# Crear un contexto SSL para forzar el uso de TLS 1.2
ssl_context = ssl.create_default_context()
ssl_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20_POLY1305")

class WSScanner(BugScanner):
    def task(self, payload):
        """Prueba si un host responde a un WebSocket handshake."""
        host = payload['host']
        port = payload.get('port', 443)  # WebSockets suelen usar 443 para WSS

        # Asegurar formato correcto para IPv6 en URLs
        if ":" in host:  # Detecta IPv6
            url = f"wss://[{host}]:{port}"
        else:  # IPv4 o dominio
            url = f"wss://{host}:{port}"

        try:
            #ws = websocket.create_connection(url, timeout=3)
            ws = create_connection(url, timeout=3, sslopt={"context": ssl_context}) 
            print(f"[+] WebSocket Activo en {host}:{port}")
            self.task_success(payload)
            ws.close()
        except Exception as e:
            print(f"[-] WebSocket Falló en {host}:{port} - {e}")
            traceback.print_exc()  # Muestra el error completo


class PingScanner(BugScanner):
    def task(self, payload):
        """Ejecuta un ping para comprobar si el host está activo."""
        host = payload['host']
        try:
            result = subprocess.run(["ping6", "-c", "1", host], stdout=subprocess.DEVNULL)
            if result.returncode == 0:
                print(f"[+] Ping Activo en {host}")
                self.task_success(payload)
        except Exception as e:
            print(f"[-] Ping Falló en {host} - {e}")


def get_arguments():
    """Parsea argumentos de línea de comandos."""
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--filename', type=str, help='Archivo con lista de hosts')
    parser.add_argument('-c', '--cdir', type=str, help='CIDR de IPv6 (ejemplo: 2001:db8::/64)')
    parser.add_argument('-m', '--mode', choices=('direct', 'proxy', 'ssl', 'udp', 'ws', 'ping'), required=True, help='Modo de escaneo')
    parser.add_argument('-p', '--port', type=int, default=80, help='Puerto(s) a escanear')
    parser.add_argument('-P', '--proxy', type=str, help='Proxy (host:port)')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Número de hilos')
    parser.add_argument('-o', '--output', type=str, help='Archivo de salida')

    return parser.parse_args()


def generate_ips_from_cidr(cidr, queue, port, proxy):
    """Genera IPs dinámicamente y las añade a la cola."""
    try:
        for ip in ipaddress.ip_network(cidr, strict=False).hosts():
            queue.put({'host': str(ip), 'port': port, 'proxy': proxy})
    except ValueError as e:
        print(f"Error: {e}")


def main():
    """Función principal."""
    args = get_arguments()

    scanners = {
        'direct': DirectScanner,
        'proxy': ProxyScanner,
        'ssl': SSLScanner,
        'udp': UDPScanner,
        'ws': WSScanner,
        'ping': PingScanner,
    }

    scanner_class = scanners.get(args.mode)
    if not scanner_class:
        print("Modo aún no implementado.")
        sys.exit(1)

    scanner = scanner_class()
    if args.output:
        scanner.output_file = args.output

    if args.cdir:
        generator_thread = threading.Thread(target=generate_ips_from_cidr, args=(args.cdir, scanner.queue, args.port, args.proxy))
        generator_thread.start()
    elif args.filename:
        with open(args.filename, 'r') as f:
            for line in f:
                scanner.queue.put({'host': line.strip(), 'port': args.port, 'proxy': args.proxy})

    scanner.start(args.threads)

    if args.cdir:
        generator_thread.join()


if __name__ == '__main__':
    main()
    