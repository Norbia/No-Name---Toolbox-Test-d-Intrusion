import nmap, socket, psutil, sys
from pycvesearch import CVESearch
#import requests
import pandas as pd
#import time
import subprocess

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
        self.my_hostname = socket.gethostbyaddr(self.my_ip_address)
        print(f"Mon IP: {self.my_ip_address}")
        print(f"Mon Hostname: {self.my_hostname[0]}")
        self.host_discovery_df = None
        self.main_interface_info = None

    def get_network_interfaces_info(self):
        """Fonction pour récupérer les informations des interfaces réseaux de l'ordinateur local"""

        # Obtenir les adresses réseau et leurs interfaces associées
        interfaces = psutil.net_if_addrs()

        # Liste pour stocker les informations des interfaces réseaux
        network_interfaces_data = []

        # Parcourir chaque interface et ses adresses associées
        for interface_name, interface_addresses in interfaces.items():
            for address in interface_addresses:
                network_interfaces_data.append({
                    "Interface": interface_name,
                    "IP Address": address.address,
                    "Netmask" : address.netmask,
                    })

        # Convertir la liste de dictionnaires en DataFrame
        interfaces_df = pd.DataFrame(network_interfaces_data)
        # Mise en forme du DataFrame
        interfaces_df = interfaces_df.dropna(subset=['Netmask'])
        interfaces_df = interfaces_df.drop_duplicates(subset=['Interface'])

        # Affiche seulement les informations de l'interface principale
        self.main_interface_info = interfaces_df[interfaces_df['IP Address'] == self.my_ip_address]
        self.network_interfaces = interfaces_df
        print(self.main_interface_info.head())
        return interfaces_df, self.main_interface_info

    def get_ip_by_interface_name(self, interface_name):
        """Récupère l'adresse IP associée au nom de l'interface réseau donné."""
        selected_interface_info = self.network_interfaces[self.network_interfaces['Interface'] == interface_name]
        if not selected_interface_info.empty:
            ip_address = selected_interface_info.iloc[0]['IP Address']
            return ip_address
        else:
            return None

    def format_netmask_for_nmap(self, netmask):
        """Convertit le netmask au format nmap CIDR."""

        netmask_octets = list(map(int, netmask.split('.')))
        cidr = sum(bin(octet).count('1') for octet in netmask_octets)
        return str(cidr)

    def host_discovery(self, my_ip_address):
        """Fonction pour faire du Host Discovery"""

        # Récupérer les infos de l'interface principale
        interfaces_df, main_interface_info = self.get_network_interfaces_info()
        netmask = main_interface_info['Netmask'].values[0]

        # Netmask en format CIDR pour s'adapter au format de la commande nmap
        cidr = self.format_netmask_for_nmap(netmask)
        info_main_host = f"{my_ip_address}/{cidr}"
        print(info_main_host)

        nm = nmap.PortScanner()

        # Scanner le réseau pour découvrir les hôtes actifs
        print("\nScan réseau Host-Discovery en cours...")
        nm.scan(hosts=info_main_host, arguments="-sn")

        host_discovery_data = []

        for host in nm.all_hosts():  # nm.all_hosts == type(class 'list')

            hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else None
            mac_address = nm[host]['addresses'].get('mac', 'N/A')
            status = nm[host]['status']['state']
            latency = nm[host]['status']['reason']
            vendor = nm[host]['vendor'].get(mac_address, 'Unknown')
            print("Host\t{}\t{}".format(hostname, host, status, latency, mac_address, vendor))

            host_discovery_data.append([hostname, host, status, latency, mac_address, vendor])

        # Créer une DataFrame à partir de la liste de données des hôtes découverts
        columns = ['Hostname', 'IP Address', 'Status', 'Latency', 'MAC Address', 'Vendor']
        self.host_discovery_df = pd.DataFrame(host_discovery_data, columns=columns)

        # Remplacer les valeurs vides dans la colonne 'Hostname' par 'Unknown'
        self.host_discovery_df['Hostname'] = self.host_discovery_df['Hostname'].replace("", "Unknown")

        # Mise en forme du DataFrame
        self.host_discovery_df = self.host_discovery_df.sort_values('IP Address', ascending=True)
        print(self.host_discovery_df)
        return self.host_discovery_df

    def get_host_discovery_df(self):
        if self.host_discovery_df is None:
            self.host_discovery(self.my_ip_address)
        return self.host_discovery_df
    
    def port_scan(self, host_discovery_df, num_hosts=10):
        """Fonction pour effectuer un scan des ports des hôtes découverts"""

        nm = nmap.PortScanner()

        port_scan_data = []

        # Scanner seulement les num_hosts premiers hôtes découverts
        for ip in host_discovery_df['IP Address'].head(num_hosts):
            print(f"\nDébut du scan Nmap pour :\t{ip}")
            nm.scan(ip, arguments='-T4 -A -F')  

            for proto in nm[ip].all_protocols():
                lport = nm[ip][proto].keys()
                for port in sorted(lport):
                    state = nm[ip][proto][port]['state']
                    service = nm[ip][proto][port]['name']
                    version = nm[ip][proto][port].get('version', 'N/A')

                    # Obtenir les détails supplémentaires si disponibles
                    script_output = []
                    if 'script' in nm[ip][proto][port]:
                        scripts = nm[ip][proto][port]['script']
                        for script in scripts:
                            output = scripts[script]
                            script_output.append(f"{script}: {output}")

                    port_scan_data.append([ip, port, state, service, version, "\n".join(script_output)])
            print("\nAnalyse Nmap finie pour {}.".format(ip))
    
        # Créer une DataFrame à partir des données des ports scannés
        port_scan_columns = ['IP Address', 'Port', 'State', 'Service', 'Version', 'Script Output']
        port_scan_df = pd.DataFrame(port_scan_data, columns=port_scan_columns)
        print(port_scan_df)
        return port_scan_df

    def generate_html_report(self, host_info_df, port_info_df, filename):
        # Convertir les DataFrames en HTML
        host_info_html = host_info_df.to_html(index=False)
        port_info_html = port_info_df.to_html(index=False)
    
        # Construire le contenu HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                h1 {{ text-align: center; }}
                .section-title {{ font-size: 20px; margin-top: 40px; }}
            </style>
        </head>
        <body>
            <h1>Network Report</h1>
        
            <div class="section">
                <h2 class="section-title">Host Discovery Information</h2>
                {host_info_html}
            </div>
        
            <div class="section">
                <h2 class="section-title">Port Scan Information</h2>
                {port_info_html}
            </div>
        </body>
        </html>
        """

        # Vérification du contenu HTML
        print("Contenu HTML généré :")
        print(html_content)

        # Écrire le contenu HTML dans un fichier
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(html_content)
            print(f"Rapport HTML écrit dans le fichier {filename}")


def main():
    """Fonction principale"""
    network_info = NetworkInfo()
    host_info_df = network_info.host_discovery(network_info.my_ip_address)
    port_info_df = network_info.port_scan(host_info_df, num_hosts=10)

    #network_info.generate_html_report(host_info_df, port_info_df, 'network_report.html')

# Exécuter les fonctions
#HOST_INFO = host_discovery()
#PORT_INFO = port_scan(HOST_INFO, num_hosts=10)
#generate_html_report(HOST_INFO, PORT_INFO, 'network_report.html')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:  
        print("\n[x] Fermeture du programme !")
        sys.exit()