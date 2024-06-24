import sys
from cli_interaction import CLIInteraction
from rich.console import Console

console = Console()

def main():
    cli = CLIInteraction()
    while True:
        cli.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[x] Fermeture du programme !", style="bold blue")
        sys.exit()
