import multithreading
import websocket
import argparse
import sys
import subprocess
import socket
import ssl
import ipaddress

class BugScanner(multithreading.MultiThreadRequest):
    def convert_host_port(self, host, port):
        """Format IPv6 address properly for URLs."""
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def get_url(self, host, port, uri=None):
        """Generate a valid URL for the scanner."""
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}' + (f'/{uri}' if uri is not None else '')

class DirectScanner(BugScanner):
    def task(self, payload):
        """Performs HTTP scanning."""
        method = payload['method']
        host = payload['host']
        port = payload['port']

        try:
            response = self.request(method, self.get_url(host, port), retry=1, timeout=3, allow_redirects=False)
        except Exception:
            return  # Ignore failures

        if response:
            self.task_success(payload)

class ProxyScanner(DirectScanner):
    proxy = []

    def request(self, *args, **kwargs):
        """Use a proxy for requests."""
        proxy = self.get_url(self.proxy[0], self.proxy[1])
        return super().request(*args, proxies={'http': proxy, 'https': proxy}, **kwargs)

class SSLScanner(BugScanner):
    def task(self, payload):
        """Perform an SSL handshake to check if SSL is enabled."""
        host = payload['host']

        try:
            sock = socket.create_connection((host, 443), timeout=5, family=socket.AF_INET6)
            context = ssl.create_default_context()
            context.wrap_socket(sock, server_hostname=host)
            self.task_success(payload)
        except Exception:
            pass  # Ignore failures

class PingScanner(BugScanner):
    def ping_host(self, host):
        """Ping an IPv6 host."""
        param = '-n' if subprocess.os.name == 'nt' else '-c'
        ping_cmd = 'ping6' if subprocess.os.name != 'nt' else 'ping -6'
        command = [ping_cmd, param, '1', host]

        try:
            return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
        except Exception:
            return False

    def task(self, payload):
        """Execute a ping task."""
        host = payload['host']
        if self.ping_host(host):
            self.task_success(payload)

class UdpScanner(BugScanner):
    def scan_udp_port(self, host, port):
        """Check if a UDP port is open on an IPv6 host."""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, int(port)))
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        except socket.error:
            return False
        finally:
            sock.close()

    def task(self, payload):
        """Run UDP scan on IPv6 host."""
        if self.scan_udp_port(payload['host'], payload['port']):
            self.task_success(payload)

class WebSocketScanner(BugScanner):
    def task(self, payload):
        """Check if WebSocket is open on an IPv6 host."""
        host = payload['host']
        url = f"ws://[{host}]"

        try:
            ws = websocket.create_connection(url)
            ws.send("ping")
            ws.recv()
            self.task_success(payload)
            ws.close()
        except Exception:
            pass  # Ignore failures

def get_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', type=str, help='Filename containing hosts')
    parser.add_argument('-c', '--cdir', type=str, help='IPv6 CIDR (e.g., 2001:db8::/64)')
    parser.add_argument('-m', '--mode', choices=('direct', 'proxy', 'ssl', 'udp', 'ws', 'ping'), default='direct', type=str, help='Scan mode')
    parser.add_argument('-M', '--method', default='head', type=str, help='HTTP method')
    parser.add_argument('-p', '--port', default='80', type=str, help='Port(s)')
    parser.add_argument('-P', '--proxy', default='', type=str, help='Proxy (host:port)')
    parser.add_argument('-T', '--threads', type=int, help='Number of threads')
    parser.add_argument('-o', '--output', type=str, help='Output file')

    return parser.parse_args(), parser

def generate_ips_from_cidr(cidr):
    """Generate IPv6 addresses from a CIDR block."""
    ip_list = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_list.append(str(ip))
    except ValueError as e:
        print("Error:", e)
    return ip_list

def main():
    """Main function to initialize the scanner."""
    arguments, parser = get_arguments()

    if not arguments.filename and not arguments.cdir:
        parser.print_help()
        sys.exit()

    method_list = arguments.method.split(',')
    if arguments.filename:
        host_list = open(arguments.filename).read().splitlines()
    elif arguments.cdir:
        ip_list = generate_ips_from_cidr(arguments.cdir)
        host_list = [str(ip) for ip in ip_list]

    port_list = arguments.port.split(',')
    proxy = arguments.proxy.split(':')

    # Select scanner mode
    if arguments.mode == 'direct':
        scanner = DirectScanner()
    elif arguments.mode == 'ssl':
        scanner = SSLScanner()
    elif arguments.mode == 'ping':
        scanner = PingScanner()
    elif arguments.mode == 'ws':
        scanner = WebSocketScanner()
    elif arguments.mode == 'proxy':
        if len(proxy) != 2:
            sys.exit('--proxy requires host:port')
        scanner = ProxyScanner()
        scanner.proxy = proxy
    elif arguments.mode == 'udp':
        scanner = UdpScanner()
    else:
        sys.exit('Mode not available!')

    # Configure scanner
    scanner.method_list = method_list
    scanner.host_list = host_list
    scanner.port_list = port_list
    scanner.threads = arguments.threads
    scanner.start()

    # Save results if needed
    if arguments.output:
        with open(arguments.output, 'w+') as file:
            file.write('\n'.join([str(x) for x in scanner.success_list()]) + '\n')

if __name__ == '__main__':
    main()
      
