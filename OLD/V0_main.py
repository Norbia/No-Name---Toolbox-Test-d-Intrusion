def collect_target_info():
    target_ip = input("Veuillez entrer l'adresse IP ou le nom d'hôte de la cible : ")
    return target_ip

def scan_method_selection():
    print("Veuillez choisir une méthode de scan :")
    print("1. Intense scan (-T4)")
    print("2. Intense scan, all TCP ports (-T4 -p 1-65535)")
    print("3. Intense scan plus UDP (-sS -sU -T4)")
    print("4. Intense scan, no ping (-T4 -Pn)")
    print("5. Ping scan (-sn)") # Host Discovery
    print("6. Quick scan (-T4 -F)")
    print("7. Quick scan plus (-sV -T4 -O -F --version-light)")

    scan_method_choice = input("Entrez le numéro correspondant à la méthode de scan choisie : ")
    return scan_method_choice

def main():
    print("Bienvenue dans la configuration de la toolbox d'intrusion.")
    target_ip = collect_target_info()
    scan_method_choice = scan_method_selection()
    print("Adresse IP ou nom d'hôte de la cible :", target_ip)
    print("Méthode de scan sélectionnée :", scan_method_choice)

main()
