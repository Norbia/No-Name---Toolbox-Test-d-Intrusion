import sys
from cli_interaction import CLIInteraction
from rich.console import Console

console = Console()

def main():
    cli = CLIInteraction()
    try:
        cli.run()
    except KeyboardInterrupt:
        console.print("\n[x] Fermeture du programme !", style="bold blue")
        sys.exit()

    # Génération de rapport à la sortie du programme
    cli.generate_report()

if __name__ == "__main__":
    main()