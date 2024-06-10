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

# Récupérer son adresse IP
my_ip_address = socket.gethostbyname(socket.gethostname())
my_hostname = socket.gethostbyaddr(my_ip_address)
print(f"Mon IP: {my_ip_address}")
print(f"Mon Hostname: {my_hostname[0]}")

# Initialiser la recherche CVE
cve_search = CVESearch('https://cve.circl.lu')

def get_network_interfaces_info():
    """Fonction pour récupérer les informations des interfaces réseaux de l'ordinateur local"""

    # Obtenir les adresses réseau et leurs interfaces associées
    interfaces = psutil.net_if_addrs()

    # Liste pour stocker les informations des interfaces réseaux
    network_interfaces_data = []

    # Parcourir chaque interface et ses adresses associées
    for interface, addresses in interfaces.items():
        for address in addresses:
            network_interfaces_data.append({
                "Interface": interface,
                "IP Address": address.address,
                "Netmask" : address.netmask,
                #'Broadcast IP': address.broadcast
                })

    # Convertir la liste de dictionnaires en DataFrame
    interfaces_df = pd.DataFrame(network_interfaces_data)
    # Mise en forme du DataFrame
    interfaces_df = interfaces_df.dropna(subset=['Netmask'])
    interfaces_df = interfaces_df.drop_duplicates(subset=['Interface'])

    # Affiche seulement les informations de l'interface principale
    main_interface_info = interfaces_df[interfaces_df['IP Address'] == my_ip_address]
    print(main_interface_info.head())
    return main_interface_info

def format_netmask_for_nmap(netmask):
    """Convertit le netmask au format nmap CIDR."""

    netmask_octets = list(map(int, netmask.split('.')))
    cidr = sum(bin(octet).count('1') for octet in netmask_octets)
    return str(cidr)

def host_discovery():
    """Fonction pour faire du Host Discovery"""

    # Récupérer les infos de l'interface principale
    main_interface_info = get_network_interfaces_info()
    netmask = main_interface_info['Netmask'].values[0]

    # Netmask en format CIDR pour s'adapter au format de la commande nmap
    cidr = format_netmask_for_nmap(netmask)
    info_main_host = f"{my_ip_address}/{cidr}"
    print(info_main_host)

    nm = nmap.PortScanner()

    # Scanner le réseau pour découvrir les hôtes actifs
    print("\nScan réseau Host-Discovery en cours...")
    nm.scan(hosts=info_main_host, arguments="-sn")

    host_discovery_data = []

    for host in nm.all_hosts(): # nm.all_hosts == type(class 'list')

        hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
        mac_address = nm[host]['addresses'].get('mac', 'N/A')
        status = nm[host]['status']['state']
        latency = nm[host]['status']['reason']
        vendor = nm[host]['vendor'].get(mac_address, 'Unknown')
        print("Host\t{}\t{}".format(hostname, host, status, latency, mac_address, vendor))

        host_discovery_data.append([hostname, host, status, latency, mac_address, vendor])

    # Créer une DataFrame à partir de la liste de données des hôtes découverts
    columns = ['Hostname', 'IP Address', 'Status', 'Latency', 'MAC Address', 'Vendor']
    host_discovery_df = pd.DataFrame(host_discovery_data, columns=columns)

    # Mise en forme du DataFrame
    host_discovery_df = host_discovery_df.sort_values('IP Address', ascending=True)
    print(host_discovery_df)
    return host_discovery_df

def port_scan(host_discovery_df, num_hosts=10):
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

def search_cves(ip_address):
    """Fonction pour rechercher les CVE sur un hôte en utilisant pycvesearch"""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments='--script vulners')
        cves_output = nm[ip_address]['script']['vulners']

        cves = []
        for cve_id in cves_output:
            cve_details = cve_search.id(cve_id)
            cves.append({
                'CVE': cve_id,
                'CVSS': cve_details.get('cvss', 'N/A'),
                'Summary': cve_details.get('summary', 'N/A')
            })
        return cves
    except Exception as e:
        print(f"Erreur lors de la recherche de CVEs sur {ip_address}: {e}")
        return []

def show_cves_details(cves):
    """Fonction pour afficher les détails des CVE"""
    if cves:
        print("CVEs trouvées sur l'hôte :")
        for cve in cves:
            print(f"CVE : {cve['CVE']}")
            print(f"CVSS : {cve['CVSS']}")
            print(f"Summary : {cve['Summary']}\n")
    else:
        print("Aucune CVE trouvée.")

def parse_cves_output(output):
    """Fonction pour analyser les résultats de recherche de CVE"""

    cves_details = {}
    lines = output.split('\n')
    current_cve = None

    for line in lines:
        if 'Nmap scan report for' in line:
            # Nouvel hôte trouvé, réinitialiser la CVE courante
            current_cve = None
        elif 'VULNERABLE' in line:
            # Ligne contenant une CVE
            parts = line.split()
            cve = parts[0]
            if cve.startswith('CVE-'):
                description = " ".join(parts[1:])
                cves_details[cve] = {
                    'description': description,
                    'cvss_score': None,
                    'cvss_vector': None,
                    'exploit': False
                }
                current_cve = cve
        elif 'CVSS' in line:
            # Ligne contenant des détails CVSS
            parts = line.split()
            if current_cve and len(parts) >= 3:
                cves_details[current_cve]['cvss_score'] = parts[1]
                cves_details[current_cve]['cvss_vector'] = parts[2]
        elif 'Available exploits' in line:
            # Ligne contenant des détails sur l'exploit
            if current_cve:
                cves_details[current_cve]['exploit'] = True

    return cves_details

def generate_html_report(host_info_df, port_info_df, filename):
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
    host_info_df = host_discovery()
    port_info_df = port_scan(host_info_df, num_hosts=10)

    for ip_address in host_info_df['IP Address']:
        print(f"Recherche de CVE sur {ip_address}...")
        cves = search_cves(ip_address)
        show_cves_details(cves)

    #generate_html_report(host_info_df, port_info_df, 'network_report.html')

# Exécuter les fonctions
#HOST_INFO = host_discovery()
#PORT_INFO = port_scan(HOST_INFO, num_hosts=10)
main()
#generate_html_report(HOST_INFO, PORT_INFO, 'network_report.html')
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:  
        print("\n[x] Fermeture du programme !")
        sys.exit()