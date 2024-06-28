# 🔧 No Name --- Toolbox-Test-d-Intrusion

## Description

Ce projet est un outil de pentest automatisé, développé dans le cadre d'un projet de fin d'année à l'école Sup de Vinci. Il permet d'effectuer des analyses de sécurité sur des réseaux et des systèmes cibles. Il comprend plusieurs fonctionnalités telles que la découverte d'hôtes, le scan de ports, la recherche de vulnérabilités (CVE), et l'exploitation des vulnérabilités trouvées. L'outil permet également de générer un rapport HTML détaillant les actions effectuées et leurs résultats.

## ⚙️ Fonctionnalités

1. 🔍 **Découverte d'hôtes** : Scanne le réseau pour détecter les hôtes actifs.
2. 🚪 **Scan de ports** : Analyse les ports ouverts sur une machine cible pour identifier les services en cours d'exécution.
3. 🛡️ **Recherche de CVE** : Recherche des vulnérabilités (CVE) pour une machine cible spécifique.
4. 💣 **Exploitation de CVE** : Recherche et télécharge les exploits disponibles pour une vulnérabilité spécifique.
5. 📝 **Génération de rapport HTML** : Génère un rapport HTML des actions effectuées et de leurs résultats.

## 📋 Prérequis

Pour exécuter ce projet, vous aurez besoin des éléments suivants :

- 🐍 Python 3.x
- 📦 Les modules Python suivants :
  - nmap
  - socket
  - psutil
  - subprocess
  - os
  - shutil
  - pandas
  - rich
- 🌐 Nmap installé sur votre machine
- 💾 Searchsploit nécessaire sur votre machine(inclus dans ExploitDB)

## 📥 Installation

Clonez le dépôt :

```bash
[git clone https://github.com/Norbia/No-Name---Toolbox-Test-d-Intrusion.git]
cd No-Name---Toolbox-Test-d-Intrusion
```

Installez les dépendances Python :

```bash
pip install -r requirements.txt
```

## 🚀 Utilisation
Pour utiliser l'outil, exécutez le script **`main.py`** :

```bash
python main.py
```

# 💬 Interactions avec l'outil
L'outil fournit une interface en ligne de commande interactive. Voici les étapes principales pour utiliser chaque fonctionnalité :

1. 🔍 **Découverte d'hôtes** :

  - Sélectionnez l'option "1. Effectuer une découverte d'hôtes" dans le menu principal.
  - Choisissez l'interface réseau à utiliser pour le scan.

2. 🚪 **Scan de ports** :

  - Sélectionnez l'option "2. Cibler une machine spécifique pour un scan de ports".
  - Entrez l'adresse IP de la machine cible.

3. 🛡️ **Recherche de CVE** :

  - Sélectionnez l'option "3. Rechercher des CVE pour une machine spécifique".
  - Entrez l'adresse IP de la machine cible.

4. 💣 **Exploitation de CVE** :

  - Sélectionnez l'option "4. Exploiter une CVE spécifique".
  - Entrez l'ID de la CVE à exploiter.
  - Sélectionnez et téléchargez le payload souhaité.
  - Exécutez le payload téléchargé sur la machine cible.
  
5. 📝 **Génération de rapport HTML** :

  - Sélectionnez l'option "5. Générer un rapport HTML".
  - Un fichier HTML détaillant les actions et résultats sera généré.

6. ❌ **Quitter** :

  - Sélectionnez l'option "6. Quitter" pour fermer l'outil et générer automatiquement un rapport HTML.

## 📂 Structure du projet
  - 🗂️ **`network_info.py`** : Contient la classe NetworkInfo qui gère les opérations réseau comme la découverte d'hôtes et le scan de ports.
  - 🗂️ **`cli_interaction.py`** : Contient la classe CLIInteraction qui gère les interactions avec l'utilisateur et l'interface en ligne de commande.
  - 🗂️ **`html_report.py`** : Contient la classe HTMLReport qui génère le rapport HTML.
  - 🗂️ **`main.py`** : Script principal pour démarrer l'outil.

## 🔄 Exemple de flux de travail
1. Lancer l'outil avec python main.py.
2. Sélectionner : "1. Effectuer une découverte d'hôtes".
3. Choisir une interface réseau pour scanner les hôtes.
4. Sélectionner : "2. Cibler une machine spécifique pour un scan de ports" et entrer l'adresse IP cible.
5. Sélectionner : "3. Rechercher des CVE pour une machine spécifique" et entrer l'adresse IP cible.
6. Sélectionner : "4. Exploiter une CVE spécifique" et entrer l'ID de la CVE.
7. Télécharger et exécuter le payload.
8. Sélectionner : "5. Générer un rapport HTML".
9. Quitter l'outil avec : "6. Quitter".
    
### ⚠️ Avertissement
Cet outil est destiné à des fins éducatives et de test uniquement. N'utilisez cet outil que sur des réseaux et des systèmes pour lesquels vous avez une autorisation explicite. L'utilisation non autorisée de cet outil peut être illégale et entraîner des conséquences juridiques.
