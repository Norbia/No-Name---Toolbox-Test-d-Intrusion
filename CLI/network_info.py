import nmap, socket, psutil, sys
from pycvesearch import CVESearch
#import requests
import pandas as pd
#import time
import subprocess
import re

# obtenir l'adresse à partir d'un nom de domaine (DNS)
#ip_address_dns = socket.gethostbyname('cyna-it.fr')
#hostname_dns = socket.gethostbyaddr(ip_address_dns)
#print("Ip d'un DNS: " + ip_address_dns)
#print(hostname_dns[0])

# recuperer les informations
#response = requests.get(f'http://ip-api.com/json/{ip_address_dns}')
#location_info = response.json()
#print(location_info)

class NetworkInfo:
    # Récupérer son adresse IP
    def __init__(self):
        self.my_ip_address = socket.gethostbyname(socket.gethostname())
        self.my_hostname = socket.gethostbyaddr(self.my_ip_address)[0]
        self.interfaces = self.get_network_interfaces_info()

    def get_network_interfaces_info(self):
        """Fonction pour récupérer les informations des interfaces réseaux de l'ordinateur local."""

        # Obtenir les adresses réseau et leurs interfaces associées
        interfaces = psutil.net_if_addrs()
        network_interfaces_list = []

        # Parcourir chaque interface et ses adresses associées
        for interface, addresses in interfaces.items():
            for address in addresses:
                if address.family == socket.AF_INET:
                    network_interfaces_list.append({
                        "name": interface,
                        "ip_address": address.address,
                        "netmask" : address.netmask,
                    })

        # Convertir la liste de dictionnaires en DataFrame
        #interfaces_df = pd.DataFrame(network_interfaces_data)
        # Mise en forme du DataFrame
        #interfaces_df = interfaces_df.dropna(subset=['Netmask'])
        #interfaces_df = interfaces_df.drop_duplicates(subset=['Interface'])

        # Affiche seulement les informations de l'interface principale
        #main_interface_info = interfaces_df[interfaces_df['IP Address'] == self.my_ip_address]
        #print(main_interface_info.head())
        return network_interfaces_list

    def print_available_interfaces(self):
        """Affiche les interfaces réseau disponibles avec leurs adresses IP."""
        print("Interfaces réseau disponibles:")
        for idx, interface in enumerate(self.interfaces, start=1):
            print(f"{idx}. {interface['name']} ({interface['ip_address']})")

    def select_interface(self):
        """Permet à l'utilisateur de choisir une interface réseau."""
        self.print_available_interfaces()
        choice = input("Choisissez le numéro de l'interface réseau pour la découverte d'hôtes : ")
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(self.interfaces):
                selected_interface = self.interfaces[choice_idx]
                return selected_interface
            else:
                print("Choix invalide.")
                return None
        except ValueError:
            print("Choix invalide.")
            return None
                   
    def format_netmask_for_nmap(self, netmask):
        """Convertit le netmask au format nmap CIDR."""
        netmask_octets = list(map(int, netmask.split('.')))
        cidr = sum(bin(octet).count('1') for octet in netmask_octets)
        return str(cidr)

    def host_discovery(self, selected_interface, timeout=120):
        """Effectue le host discovery en scannant le réseau de l'interface sélectionnée."""

        ip_address = selected_interface['ip_address']
        netmask = selected_interface['netmask']
        cidr = self.format_netmask_for_nmap(netmask)
        scan_range = f"{ip_address}/{cidr}"

        nm = nmap.PortScanner()
        print(f"\nScan réseau Host-Discovery en cours pour {scan_range}...")

        try:
            nm.scan(hosts=scan_range, arguments="-sn", timeout=timeout)
        except nmap.PortScannerError as e:
            print(f"Erreur Nmap: {e}")
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

        # Remplacer les valeurs vides dans la colonne 'Hostname' par 'Unknown'
        host_discovery_df['Hostname'] = host_discovery_df['Hostname'].replace("", "Unknown")

        host_discovery_df = host_discovery_df.sort_values('IP Address', ascending=True)
        print(host_discovery_df)
        return host_discovery_df
    
    def port_scan(self, target_ip, timeout=120):
        """Effectue le scan de ports sur la machine ciblé."""

        nm = nmap.PortScanner()
        print(f"\nScan de ports en cours pour {target_ip}...")

        try:
            nm.scan(target_ip, arguments='-T4 -O -F -sV -v -A --version-light', timeout=timeout)
        except nmap.PortScannerError as e:
            print(f"Erreur Nmap: {e}")
            return None

        port_scan_data = []

        for proto in nm[target_ip].all_protocols():
            lport = nm[target_ip][proto].keys()
            for port in sorted(lport):
                state = nm[target_ip][proto][port]['state']
                service = nm[target_ip][proto][port]['name']
                version = nm[target_ip][proto][port].get('version', 'N/A')

                # Obtenir les détails supplémentaires si disponibles
                script_output = []
                if 'script' in nm[target_ip][proto][port]:
                    scripts = nm[target_ip][proto][port]['script']
                    for script in scripts:
                        output = scripts[script]
                        script_output.append(f"{script}: {output}")

                port_scan_data.append([target_ip, port, state, service, version, "\n".join(script_output)])

        columns = ['IP Address', 'Port', 'State', 'Service', 'Version', 'Script Output']
        port_scan_df = pd.DataFrame(port_scan_data, columns=columns)
        print(port_scan_df)
        return port_scan_df
    
    def search_cve(self, target_ip):
        '''Recherche les CVE pour la machine ciblée.'''
        try:
            cve_result = subprocess.run(['nmap', '--script', 'vuln', target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if cve_result.returncode != 0:
                print(f"Erreur lors de l'exécution de Nmap sur {target_ip}. Retour du processus : {cve_result.returncode}")
                print(f"Erreur de sortie : {cve_result.stderr}")
                return []
            
            # Afficher la sortie brute sans traitement supplémentaire
            print("Sortie brute de la commande Nmap :")
            print(cve_result.stdout)

            return []

        except Exception as e:
            print(f"Erreur lors de la recherche de CVEs sur {target_ip}: {e}")
            return []    

class CLIInteraction:
    def __init__(self):
        self.network_info = NetworkInfo()

    def run(self):
        print("\nQue souhaitez-vous faire ?")
        print("1. Effectuer une découverte d'hôtes")
        print("2. Cibler une machine spécifique pour un scan de ports")
        print("3. Quitter")
        choice = input("Choix : ")

        match choice:
            case '1':
                interface = self.network_info.select_interface()
                if interface:
                    self.network_info.host_discovery(interface)
            case '2':
                target_ip = input("Entrez l'adresse IP de la machine à cibler : ")
                self.network_info.port_scan(target_ip)
                self.ask_for_cves_search(target_ip)
            case '3':
                print("\n[x] Fermeture du programme !")
                sys.exit()
            case _:
                print("Choix invalide. Veuillez choisir une option valide.")

        #self.network_info.generate_html_report(host_info_df, port_info_df, 'network_report.html')

    def ask_for_cves_search(self, target_ip):
        choice = input("\nVoulez-vous rechercher des CVE pour cette machine ? (o/n) : ")
        if choice.lower() == 'o':
            self.network_info.search_cve(target_ip)
        else:
            print("Aucune recherche de CVE effectuée.")


