import pandas as pd

class HTMLReportGenerator:
    def generate_html_report(self, host_info_df, port_info_df, filename):
        host_info_html = host_info_df.to_html(index=False)
        port_info_html = port_info_df.to_html(index=False)

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Projet-SDV Toolbox Test d'Intrusion : Rapport</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                h1 {{ text-align: center; }}
                .section-title {{ font-size: 20px; margin-top: 40px; }}
            </style>
        </head>
        <body>
            <h1>Network Report</h1>
        
            <div class="section">
                <h2 class="section-title">Découverte d'Hôtes actifs</h2>
                {host_info_html}
            </div>
        
            <div class="section">
                <h2 class="section-title">Port Scan Information</h2>
                {port_info_html}
            </div>
        </body>
        </html>
        """

        print("Contenu HTML généré :")
        print(html_content)

        with open(filename, 'w', encoding='utf-8') as file:
            file.write(html_content)
            print(f"Rapport HTML écrit dans le fichier {filename}")
