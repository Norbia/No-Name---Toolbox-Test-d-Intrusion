import nmap
import socket
import psutil
import subprocess
import os
import shutil
import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()

class NetworkInfo:
    def __init__(self):
        self.my_ip_address = socket.gethostbyname(socket.gethostname())
        self.my_hostname = socket.gethostbyaddr(self.my_ip_address)[0]
        self.interfaces = self.get_network_interfaces_info()

    def get_network_interfaces_info(self):
        interfaces = psutil.net_if_addrs()
        network_interfaces_list = []
        for interface, addresses in interfaces.items():
            for address in addresses:
                if address.family == socket.AF_INET:
                    network_interfaces_list.append({
                        "name": interface,
                        "ip_address": address.address,
                        "netmask": address.netmask,
                    })
        return network_interfaces_list

    def print_available_interfaces(self):
        console.print("Interfaces réseau disponibles:", style="bold blue")
        for idx, interface in enumerate(self.interfaces, start=1):
            console.print(f"{idx}. {interface['name']} ({interface['ip_address']})", style="green")

    def select_interface(self):
        self.print_available_interfaces()
        if len(self.interfaces) == 1:
            console.print(f"Interface unique détectée : {self.interfaces[0]['name']} ({self.interfaces[0]['ip_address']})", style="bold green")
            return self.interfaces[0]
        
        choice = input("Choisissez le numéro de l'interface réseau pour la découverte d'hôtes [1]: ") or "1"
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(self.interfaces):
                selected_interface = self.interfaces[choice_idx]
                return selected_interface
            else:
                console.print("Choix invalide.", style="bold red")
                return None
        except ValueError:
            console.print("Choix invalide.", style="bold red")
            return None

    def format_netmask_for_nmap(self, netmask):
        netmask_octets = list(map(int, netmask.split('.')))
        cidr = sum(bin(octet).count('1') for octet in netmask_octets)
        return str(cidr)

    def host_discovery(self, selected_interface, timeout=120):
        ip_address = selected_interface['ip_address']
        netmask = selected_interface['netmask']
        cidr = self.format_netmask_for_nmap(netmask)
        scan_range = f"{ip_address}/{cidr}"

        nm = nmap.PortScanner()
        console.print(f"\nScan réseau Host-Discovery en cours pour {scan_range}...", style="bold yellow")

        try:
            nm.scan(hosts=scan_range, arguments="-sn", timeout=timeout)
        except nmap.PortScannerError as e:
            console.print(f"Erreur Nmap: {e}", style="bold red")
            return None

        host_discovery_data = []
        for host in nm.all_hosts():
            hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else None
            mac_address = nm[host]['addresses'].get('mac', 'N/A')
            status = nm[host]['status']['state']
            latency = nm[host]['status']['reason']
            vendor = nm[host]['vendor'].get(mac_address, 'Unknown')
            host_discovery_data.append([hostname, host, status, latency, mac_address, vendor])

        columns = ['Hostname', 'IP Address', 'Status', 'Latency', 'MAC Address', 'Vendor']
        host_discovery_df = pd.DataFrame(host_discovery_data, columns=columns)
        host_discovery_df['Hostname'] = host_discovery_df['Hostname'].replace("", "Unknown")
        host_discovery_df = host_discovery_df.sort_values('IP Address', ascending=True)
        
        table = Table(title="Host Discovery Results")
        for col in columns:
            table.add_column(col, justify="center")

        for row in host_discovery_df.itertuples(index=False):
            table.add_row(*map(str, row))

        console.print(table)
        return host_discovery_df

    def port_scan(self, target_ip, timeout=300):
        nm = nmap.PortScanner()
        console.print(f"\nScan de ports en cours pour {target_ip}...", style="bold yellow")

        try:
            nm.scan(target_ip, arguments='-T4 -O -F -sV -v -A --version-light', timeout=timeout)
        except nmap.PortScannerError as e:
            console.print(f"Erreur Nmap: {e}", style="bold red")
            return None

        port_scan_data = []
        for proto in nm[target_ip].all_protocols():
            lport = nm[target_ip][proto].keys()
            for port in sorted(lport):
                state = nm[target_ip][proto][port]['state']
                service = nm[target_ip][proto][port]['name']
                version = nm[target_ip][proto][port].get('version', 'N/A')
                script_output = []
                if 'script' in nm[target_ip][proto][port]:
                    scripts = nm[target_ip][proto][port]['script']
                    for script in scripts:
                        output = scripts[script]
                        script_output.append(f"{script}: {output}")
                port_scan_data.append([target_ip, port, state, service, version, "\n".join(script_output)])

        columns = ['IP Address', 'Port', 'State', 'Service', 'Version', 'Script Output']
        port_scan_df = pd.DataFrame(port_scan_data, columns=columns)
        
        table = Table(title="Port Scan Results")
        for col in columns:
            table.add_column(col, justify="center")

        for row in port_scan_df.itertuples(index=False):
            table.add_row(*map(str, row))

        console.print(table)
        return port_scan_df

    def search_cve(self, target_ip):
        try:
            cve_result = subprocess.run(['nmap', '--script', 'vuln', target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if cve_result.returncode != 0:
                console.print(f"Erreur lors de l'exécution de Nmap sur {target_ip}. Retour du processus : {cve_result.returncode}", style="bold red")
                console.print(f"Erreur de sortie : {cve_result.stderr}", style="bold red")
                return []
            console.print("Sortie brute de la commande Nmap :", style="bold blue")
            console.print(cve_result.stdout)
            return []
        except Exception as e:
            console.print(f"Erreur lors de la recherche de CVEs sur {target_ip}: {e}", style="bold red")
            return []

    def exploit_cve(self, cve_id):
        try:
            exploit_result = subprocess.run(['searchsploit', '--cve', cve_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if exploit_result.returncode != 0:
                console.print(f"Erreur lors de l'exécution de searchsploit pour CVE {cve_id}. Retour du processus : {exploit_result.returncode}", style="bold red")
                console.print(f"Erreur de sortie : {exploit_result.stderr}", style="bold red")
                return []
            console.print("Sortie brute de la commande searchsploit :", style="bold blue")
            console.print(exploit_result.stdout)
            return exploit_result.stdout.splitlines()
        except Exception as e:
            console.print(f"Erreur lors de l'exploitation de CVE {cve_id}: {e}", style="bold red")
            return []

    def download_exploit(self, selected_payload, destination_folder):
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        payload_filename = os.path.basename(selected_payload)
        temp_path = os.path.join(os.getcwd(), payload_filename)
        destination_path = os.path.join(destination_folder, payload_filename)
        if os.path.exists(destination_path):
            console.print(f"Le payload {payload_filename} existe déjà dans {destination_folder}", style="bold yellow")
            return destination_path
        command = ["searchsploit", "-m", selected_payload]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                shutil.move(temp_path, destination_path)
                console.print(f"Payload {payload_filename} téléchargé avec succès dans {destination_folder}", style="bold green")
                return destination_path
            else:
                console.print(f"Erreur lors du téléchargement du payload: {result.stderr}", style="bold red")
        except subprocess.CalledProcessError as e:
            console.print(f"Erreur lors de l'exécution de searchsploit : {e}", style="bold red")
        return None

    def execute_payload(self, payload_path, target_ip):
        try:
            if os.path.exists(payload_path):
                command = ["python3", payload_path, target_ip]
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode == 0:
                    console.print(f"Payload exécuté avec succès :\n{result.stdout}", style="bold green")
                else:
                    console.print(f"Erreur lors de l'exécution du payload :\n{result.stderr}", style="bold red")
            else:
                console.print(f"Le fichier payload {payload_path} n'existe pas.", style="bold red")
        except subprocess.CalledProcessError as e:
            console.print(f"Erreur lors de l'exécution du payload {payload_path}: {e}", style="bold red")
        except FileNotFoundError as e:
            console.print(f"Fichier introuvable lors de l'exécution du payload {payload_path}: {e}", style="bold red")
        except Exception as e:
            console.print(f"Erreur inattendue lors de l'exécution du payload {payload_path}: {e}", style="bold red")

