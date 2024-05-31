import socket
#import requests
import psutil
import pandas as pd
import nmap
import ipaddress

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
    print("Scanning network for active hosts...")
    nm.scan(hosts=info_main_host, arguments="-sn")
    # nm.all_hosts == type(class 'list')

    host_discovery_data = []

    for host in nm.all_hosts():

        hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
        mac_address = nm[host]['addresses'].get('mac', 'N/A')
        status = nm[host]['status']['state']
        latency = nm[host]['status']['reason']
        vendor = nm[host]['vendor'].get(mac_address, 'Unknown')

        host_discovery_data.append([hostname, host, status, latency, mac_address, vendor])

        #Affichage CLI propre comme Zenmap
        print(f"Nmap scan report for {hostname} ({host})")
        print(f"Host is {status} ({latency} latency).")
        print(f"MAC Address: {mac_address} ({vendor})")
        print()

    # Créer une DataFrame à partir de la liste de données des hôtes découverts
    columns = ['Hostname', 'IP Address', 'Status', 'Latency', 'MAC Address', 'Vendor']
    host_discovery_df = pd.DataFrame(host_discovery_data, columns=columns)

    #Mise en forme du DataFrame
    host_discovery_df = host_discovery_df.sort_values('IP Address', ascending=True)
    print(host_discovery_df)
    return host_discovery_df

get_network_interfaces_info()
host_discovery()
