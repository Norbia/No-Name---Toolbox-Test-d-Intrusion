import socket
import psutil
import pandas as pd
import nmap
import random
from ipaddress import ip_network

def get_network_interfaces_info():
    """Fonction pour récupérer les informations des cartes réseaux"""
    interfaces = psutil.net_if_addrs()
    network_interfaces_data = []

    for interface, addresses in interfaces.items():
        for address in addresses:
            network_interfaces_data.append({
                "Interface": interface,
                "IP Address": address.address,
                "Netmask": address.netmask,
            })

    interfaces_df = pd.DataFrame(network_interfaces_data)
    interfaces_df = interfaces_df.dropna(subset=['Netmask'])
    interfaces_df = interfaces_df.drop_duplicates(subset=['Interface'])

    main_interface_info = interfaces_df[interfaces_df['IP Address'] == my_ip_address]
    return main_interface_info

def format_netmask_for_nmap(netmask):
    """Fonction pour convertir le netmask en format CIDR pour la compréhension de notre cher nmap python :)"""
    netmask_octets = list(map(int, netmask.split('.')))
    cidr = sum(bin(octet).count('1') for octet in netmask_octets)
    return str(cidr)

def sample_ips(ip_range, sample_size):
    """Fonction pour test les plages d'ip avec nmap"""
    network = ip_network(ip_range, strict=False)
    return random.sample(list(network.hosts()), sample_size)

def quick_scan(ip_list):
    nm = nmap.PortScanner()
    ip_range = ' '.join([str(ip) for ip in ip_list])
    nm.scan(hosts=ip_range, arguments="-sn")
    return nm.all_hosts()

def host_discovery(ip_ranges, sample_size=10):
    nm = nmap.PortScanner()
    host_discovery_data = []

    for ip_range in ip_ranges:
        print(f"Sampling IPs in range {ip_range}...")
        sampled_ips = sample_ips(ip_range, sample_size)

        print(f"Quick scanning sampled IPs in range {ip_range}...")
        if quick_scan(sampled_ips):
            print(f"Active hosts found in sampled IPs of range {ip_range}. Performing detailed scan...")
            nm.scan(hosts=ip_range, arguments="-sn")

            for host in nm.all_hosts():
                hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
                mac_address = nm[host]['addresses'].get('mac', 'N/A')
                status = nm[host]['status']['state']
                latency = nm[host]['status']['reason']
                vendor = nm[host]['vendor'].get(mac_address, 'Unknown')

                host_discovery_data.append([hostname, host, status, latency, mac_address, vendor])

                print(f"Nmap scan report for {hostname} ({host})")
                print(f"Host is {status} ({latency} latency).")
                print(f"MAC Address: {mac_address} ({vendor})")
                print()
        else:
            print(f"No active hosts found in sampled IPs of range {ip_range}. Skipping detailed scan...")

    columns = ['Hostname', 'IP Address', 'Status', 'Latency', 'MAC Address', 'Vendor']
    host_discovery_df = pd.DataFrame(host_discovery_data, columns=columns)
    host_discovery_df = host_discovery_df.sort_values('IP Address', ascending=True)
    print(host_discovery_df)
    return host_discovery_df

my_ip_address = socket.gethostbyname(socket.gethostname())
my_hostname = socket.gethostbyaddr(my_ip_address)
print(f"Mon IP: {my_ip_address}")
print(f"Mon Hostname: {my_hostname[0]}")

# Exemples de plages IP à scanner
ip_ranges = [
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.3.0/24",
    "192.168.4.0/24",
    "192.168.5.0/24",
    "192.168.6.0/24",
    "192.168.7.0/24",
    "192.168.8.0/24",
    "192.168.9.0/24",
    "192.168.10.0/24"
]

host_discovery(ip_ranges)
