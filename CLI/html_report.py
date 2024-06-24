import os
import pandas as pd
from datetime import datetime

class HTMLReport:
    def __init__(self, report_title="Network Scan Report"):
        self.report_title = report_title

    def generate_report(self, actions_log, output_dir="reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"network_scan_report_{timestamp}.html"
        report_path = os.path.join(output_dir, report_filename)

        html_content = self.build_html_content(actions_log, timestamp)

        with open(report_path, 'w') as f:
            f.write(html_content)

        return report_path

    def build_html_content(self, actions_log, timestamp):
        actions_html = self.actions_to_html(actions_log)

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{self.report_title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                h1 {{ color: #333; }}
                .section-title {{ color: #555; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h1>{self.report_title}</h1>
            <p>Rapport généré le {timestamp}</p>
            {actions_html}
        </body>
        </html>
        """
        return html_content

    def actions_to_html(self, actions_log):
        actions_html = "<h2 class='section-title'>Journal des actions</h2><table>"
        actions_html += "<thead><tr><th>Action</th><th>Résultat</th></tr></thead><tbody>"
        
        for action, result in actions_log:
            result_html = self.result_to_html(result)
            actions_html += f"<tr><td>{action}</td><td>{result_html}</td></tr>"

        actions_html += "</tbody></table>"
        return actions_html

    def result_to_html(self, result):
        if isinstance(result, pd.DataFrame):
            return self.df_to_html_table(result)
        elif isinstance(result, list):
            return "<ul>" + "".join(f"<li>{item}</li>" for item in result) + "</ul>"
        elif isinstance(result, str):
            return result
        else:
            return str(result)

    def df_to_html_table(self, df):
        table_html = "<table>\n<thead>\n<tr>"
        for column in df.columns:
            table_html += f"<th>{column}</th>"
        table_html += "</tr>\n</thead>\n<tbody>\n"
        for _, row in df.iterrows():
            table_html += "<tr>"
            for cell in row:
                table_html += f"<td>{cell}</td>"
            table_html += "</tr>\n"
        table_html += "</tbody>\n</table>\n"
        return table_html
