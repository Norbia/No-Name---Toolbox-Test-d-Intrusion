import sys
from cli_interaction import CLIInteraction

def main():
    cli = CLIInteraction()
    while True:
        cli.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[x] Fermeture du programme !")
        sys.exit()
