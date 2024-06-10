import nmap
import sys
from pycvesearch import CVESearch

# Initialiser la recherche CVE
cve_search = CVESearch('https://cve.circl.lu')

def search_cves(ip_address):
    """Fonction pour rechercher les CVE sur un hôte en utilisant pycvesearch"""
    try:
        nm = nmap.PortScanner()
        print(f"Scanning {ip_address} for vulnerabilities...")
        nm.scan(hosts=ip_address, arguments='--script vuln')

        if 'hostscript' in nm[ip_address]:
            cves_output = nm[ip_address]['hostscript']
            cves = []
            for script in cves_output:
                if 'output' in script:
                    output_lines = script['output'].split('\n')
                    for line in output_lines:
                        if 'CVE-' in line:
                            parts = line.split()
                            cve_id = parts[0]
                            cve_details = cve_search.id(cve_id)
                            cves.append({
                                'CVE': cve_id,
                                'CVSS': cve_details.get('cvss', 'N/A'),
                                'Summary': cve_details.get('summary', 'N/A')
                            })
            return cves
        else:
            print(f"Aucun script de vulnérabilité trouvé pour l'adresse {ip_address}")
            return []
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

def main():
    """Fonction principale"""
    ip_address = input("Entrez l'adresse IP de l'hôte à analyser : ")
    print(f"Recherche de CVE sur {ip_address}...")
    cves = search_cves(ip_address)
    show_cves_details(cves)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:  
        print("\n[x] Fermeture du programme !")
        sys.exit()
