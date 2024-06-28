import sys
import pandas as pd
from network_info import NetworkInfo
from html_report import HTMLReport
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

class CLIInteraction:
    def __init__(self):
        self.network_info = NetworkInfo()
        self.report_generator = HTMLReport()
        self.actions_log = [] 
        self.host_discovery_result = pd.DataFrame()  
        self.port_scan_result = pd.DataFrame()  
        self.cve_search_result = pd.DataFrame()  

    def display_welcome_message(self):
        welcome_text = """
            ███    ██  ██████      ███    ██  █████  ███    ███ ███████ 
            ████   ██ ██    ██     ████   ██ ██   ██ ████  ████ ██      
            ██ ██  ██ ██    ██     ██ ██  ██ ███████ ██ ████ ██ █████   
            ██  ██ ██ ██    ██     ██  ██ ██ ██   ██ ██  ██  ██ ██      
            ██   ████  ██████      ██   ████ ██   ██ ██      ██ ███████ 
                                                                        
                                                                        
        """
        project_name = "[bold green]Projet SDV -- Toolbox Test d'Intrusion[/bold green]"
        subtitle = "[bold blue]Bienvenue dans l'outil de Pentest Automatique by Hannah DELATTRE ![/bold blue]"
        
        console.print(Panel(welcome_text, box=box.ROUNDED, title=project_name, title_align="center"))
        console.print(subtitle, justify="center")

    def log_action(self, action, result=None):
        self.actions_log.append((action, result))

    def run(self):
        self.display_welcome_message()

        while True:
            console.print("\nQue souhaitez-vous faire ?", style="bold blue")
            console.print("1. Effectuer une découverte d'hôtes")
            console.print("2. Cibler une machine spécifique pour un scan de ports")
            console.print("3. Rechercher des CVE pour une machine spécifique")
            console.print("4. Exploiter une CVE spécifique")
            console.print("5. Générer un rapport HTML")
            console.print("6. Quitter")
            choice = input("Choix [1-6]: ") or "1"

            match choice:
                case '1':
                    interface = self.network_info.select_interface()
                    if interface:
                        result = self.network_info.host_discovery(interface)
                        if result is not None:
                            self.host_discovery_result = result
                            self.log_action("Découverte d'hôtes", result)
                        else:
                            console.print("Erreur lors de la découverte d'hôtes.", style="bold red")
                case '2':
                    target_ip = input("Entrez l'adresse IP de la machine à cibler (ou 'menu' pour retourner au menu principal) : ")
                    if target_ip.lower() == 'menu':
                        continue
                    result = self.network_info.port_scan(target_ip)
                    if result is not None:
                        self.port_scan_result = result
                        self.log_action(f"Scan de ports pour {target_ip}", result)
                    else:
                        console.print("Erreur lors du scan de ports.", style="bold red")
                case '3':
                    target_ip = input("Entrez l'adresse IP de la machine pour rechercher des CVE (ou 'menu' pour retourner au menu principal) : ")
                    if target_ip.lower() == 'menu':
                        continue
                    cve_output = self.network_info.search_cve(target_ip)
                    if cve_output is not None:
                        self.cve_search_result = pd.DataFrame(cve_output)
                        self.log_action(f"Recherche de CVE pour {target_ip}", cve_output)
                        self.display_cves(cve_output)
                case '4':
                    cve_id = input("Entrez l'ID de la CVE à exploiter (ou 'menu' pour retourner au menu principal) : ")
                    if cve_id.lower() == 'menu':
                        continue
                    payloads = self.network_info.exploit_cve(cve_id)
                    if not payloads.empty:
                        self.log_action(f"Recherche de Payload pour : {cve_id}", payloads)
                        self.display_payloads(payloads)
                case '5':
                    self.generate_report()
                case '6':
                    console.print("\n[x] Fermeture du programme !", style="bold blue")
                    self.generate_report()
                    sys.exit()
                case _:
                    console.print("Choix invalide. Veuillez choisir une option valide.", style="bold red")

    def display_cves(self, cve_output):
        console.print("\nCVE détectées:", style="bold blue")
        console.print(cve_output)
        console.print("\n0. Retour au menu principal", style="bold yellow")
        choice = input("Appuyez sur 0 pour retourner au menu principal : ")
        if choice == '0':
            return

    def display_payloads(self, payloads):
        console.print("\nPayloads disponibles :", style="bold blue")
        if not payloads.empty: 
            for idx, row in payloads.iterrows():
                console.print(f"{idx + 1}. {row['Exploit Title']} | Path: {row['Path']}", style="green")
            console.print(f"{len(payloads) + 1}. Retour au menu principal", style="yellow")

            while True:
                user_input = input("\nChoisissez le numéro du payload à télécharger (ou 'menu' pour retourner au menu principal) : ")
                
                if user_input.lower() == 'menu':
                    return
                
                try:
                    payload_choice = int(user_input)
                    if payload_choice == len(payloads) + 1:
                        return
                    elif 1 <= payload_choice <= len(payloads):
                        selected_payload = payloads.iloc[payload_choice - 1]['Path']
                        download_folder = "payloads"
                        payload_path = self.network_info.download_exploit(selected_payload, download_folder)
                        self.log_action(f"Téléchargement du payload {selected_payload}", payload_path)
                        self.ask_to_execute_payload(payload_path)
                        break
                    else:
                        console.print("Numéro de payload invalide.", style="bold red")
                except ValueError:
                    console.print("Entrée invalide. Veuillez entrer un numéro valide.", style="bold red")
        else:
            console.print("Aucun exploit trouvé pour ce CVE.", style="bold yellow")

    def ask_to_execute_payload(self, payload_path):
            if payload_path:
                choice = input("\nVoulez-vous exécuter le payload téléchargé ? (o/n, ou 'menu' pour retourner au menu principal) : ") or "n"
                if choice.lower() == 'o':
                    target_ip = input("Entrez l'adresse IP cible pour le payload : ")
                    try:
                        self.network_info.execute_payload(payload_path, target_ip)
                        self.log_action(f"Exécution du payload {payload_path} sur {target_ip}")
                    except Exception as e:
                        console.print(f"Erreur lors de l'exécution du payload : {e}", style="bold red")
                else:
                    console.print("Exécution du payload annulée.", style="bold yellow")
            else:
                console.print("Aucun payload téléchargé. Exécution annulée.", style="bold red")

    def generate_report(self):
        if not self.actions_log:
            console.print("Aucune action enregistrée. Réalisez au moins une action avant de générer un rapport.", style="bold red")
            return

        report_path = self.report_generator.generate_report(self.actions_log)
        console.print(f"Rapport généré avec succès : {report_path}", style="bold green")
