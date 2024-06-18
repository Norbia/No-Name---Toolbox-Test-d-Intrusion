import sys
import pandas as pd
from network_info import NetworkInfo
from html_report import HTMLReportGenerator

class CLIInteraction:
    """Gère l'affichage du programme en interface CLI"""
    def __init__(self):
        self.network_info = NetworkInfo()
        self.report_generator = HTMLReportGenerator()
        self.host_discovery_result = []
        self.port_scan_result = []

    def run(self):
        print("\nQue souhaitez-vous faire ?")
        print("1. Effectuer une découverte d'hôtes")
        print("2. Cibler une machine spécifique pour un scan de ports")
        print("3. Générer un rapport HTML")
        print("4. Quitter")
        choice = input("Choix : ")

        match choice:
            case '1':
                interface = self.network_info.select_interface()
                if interface:
                    result = self.network_info.host_discovery(interface)
                    if result is not None:
                        self.host_discovery_result.append(result)
                    else:
                        print("Erreur lors de la découverte d'hôtes.")
            case '2':
                target_ip = input("Entrez l'adresse IP de la machine à cibler : ")
                result = self.network_info.port_scan(target_ip)
                if self.port_scan_result is not None:
                    self.port_scan_result.append(result)
                    self.ask_for_cves_search(target_ip)
                else:
                    print("Erreur lors du scan de ports.")
            case '3':
                self.generate_report()
            case '4':
                print("\n[x] Fermeture du programme !")
                sys.exit()
            case _:
                print("Choix invalide. Veuillez choisir une option valide.")

    def ask_for_cves_search(self, target_ip):
        choice = input("\nVoulez-vous rechercher des CVE pour cette machine ? (o/n) : ")
        if choice.lower() == 'o':
            self.network_info.search_cve(target_ip)
        else:
            print("Aucune recherche de CVE effectuée.")
    
    def generate_report(self):
        if len(self.host_discovery_result) == 0 and len(self.port_scan_result) == 0: # Permet de vérifier si les listes  des résultats sont vides ou non
            print("Aucune donnée disponible pour générer un rapport.")
            return

        filename = input("Entrez le nom du fichier pour le rapport HTML : ")
        filename = filename + ".html"

        # Concaténer les résultats si non vides
        if len(self.host_discovery_result) > 0:
            self.host_discovery_df = pd.concat(self.host_discovery_result, ignore_index=True)
        else:
            self.host_discovery_df = pd.DataFrame()

        if len(self.port_scan_result) > 0:
            self.port_scan_df = pd.concat(self.port_scan_result, ignore_index=True)
        else:
            self.port_scan_df = pd.DataFrame()

        self.report_generator.generate_html_report(self.host_discovery_df, self.port_scan_df, filename)
