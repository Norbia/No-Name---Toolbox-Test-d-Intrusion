import pandas as pd

class HTMLReport:
    def generate_report(self, actions_log):
        report_content = self.generate_actions_log_section(actions_log)
        report_filename = "log_actions_report.html"
        with open(report_filename, 'w') as f:
            f.write(report_content)
        return report_filename

    def generate_actions_log_section(self, actions_log):
        html_content = """
        <!DOCTYPE html>
        <html>
            <head>
                <title>Rapport d'activités - Outil d'Intrusion</title>
                <style>
                    body { font-family: Arial, sans-serif; }
                    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    h1 { text-align: center; }
                    .section-title { font-size: 20px; margin-top: 40px; }
                </style>
            </head>
        <body>
            <h1>Rapport d'activités - Outil d'Intrusion</h1>
        """

        for action, result in actions_log:
            html_content += f"<h2>{action}</h2>"
            if isinstance(result, pd.DataFrame):
                html_content += result.to_html()
            elif isinstance(result, list):
                html_content += "<ul>"
                for item in result:
                    html_content += f"<li>{item}</li>"
                html_content += "</ul>"
            elif isinstance(result, str):
                html_content += f"<p>{result}</p>"
            else:
                html_content += "<p>Résultat non structuré</p>"
        
        html_content += """
        </body>
        </html>
        """
        return html_content
