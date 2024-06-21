import pandas as pd
from pandastable import Table
import customtkinter
from network_info import NetworkInfo
import threading

class NetworkInterfaceFrame(customtkinter.CTkFrame):
    """Frame for displaying network interface information"""

    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.network_info = NetworkInfo()
        self.interfaces = self.network_info.get_network_interfaces_info()

        self.interface_label = customtkinter.CTkLabel(self, text="Select Network Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        interface_names = [interface['name'] for interface in self.interfaces]
        self.interfaces_var = customtkinter.StringVar(value=interface_names[0] if interface_names else "")
        self.interfaces_menu = customtkinter.CTkOptionMenu(self, values=interface_names, command=self.update_ip_address, variable=self.interfaces_var)
        self.interfaces_menu.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.ip_label = customtkinter.CTkLabel(self, text="IP Address:")
        self.ip_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.ip_var = customtkinter.StringVar(value=self.interfaces[0]['ip_address'] if self.interfaces else "")
        self.ip_address_label = customtkinter.CTkLabel(self, textvariable=self.ip_var)
        self.ip_address_label.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    def update_ip_address(self, *args):
        """Met à jour l'adresse IP en fonction de la carte réseau sélectionnée"""
        selected_interface = self.interfaces_var.get()
        for interface in self.interfaces:
            if interface['name'] == selected_interface:
                self.ip_var.set(interface['ip_address'])
                self.master.log_event(f"Interface changed to: {selected_interface} with IP: {interface['ip_address']}")
                break

class MenuFrame(customtkinter.CTkFrame):
    """Menu frame for the application"""

    def __init__(self, master, callback):
        super().__init__(master)
        self.master = master
        self.callback = callback

        self.grid_columnconfigure(0, weight=1)

        self.menu_label = customtkinter.CTkLabel(self, text="Network", font=("Arial", 16, "bold"))
        self.menu_label.grid(row=0, column=0, padx=10, pady=(5, 0), sticky="nw")

        self.host_discovery_button = customtkinter.CTkButton(self, text="Host Discovery", command=lambda: self.log_and_callback("Host Discovery"))
        self.host_discovery_button.grid(row=1, column=0, padx=10, pady=(2, 0), sticky="w")
        self.host_discovery_button.configure(fg_color="transparent")

        self.another_button = customtkinter.CTkButton(self, text="Another Feature", command=lambda: self.log_and_callback("Another Feature"))
        self.another_button.grid(row=2, column=0, padx=10, pady=(2, 0), sticky="w")
        self.another_button.configure(fg_color="transparent")

    def log_and_callback(self, action):
        """Fonction pour les logs"""
        self.master.log_event(f"Button clicked: {action}")
        self.callback(action)

class HostDiscoveryFrame(customtkinter.CTkFrame):
    """Frame for host discovery feature"""

    def __init__(self, master, app):
        super().__init__(master)
        self.master = master
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)

        self.label = customtkinter.CTkLabel(self, text="Click 'Scan now' to perform host discovery.")
        self.label.grid(row=0, rowspan=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.table_frame = None
        self.scan_button = customtkinter.CTkButton(self, text="Scan now", command=self.start_host_discovery)
        self.scan_button.grid(row=0, column=1, padx=10, pady=10, sticky="ne")
        self.host_discovery_results = None

        self.details_text = None
        self.scan_ports_button = None
        self.port_scan_results = {}

    def start_host_discovery(self):
        """Fonction pour démarrer la découverte des hôtes"""
        selected_interface_name = self.app.network_interface_frame.interfaces_var.get()
        selected_interface = None
        for interface in self.app.network_interface_frame.interfaces:
            if interface['name'] == selected_interface_name:
                selected_interface = interface
                break
        if selected_interface:
            self.label.configure(text="Découverte des hôtes en cours...")
            discovery_thread = threading.Thread(target=self.perform_host_discovery, args=(selected_interface,))
            discovery_thread.start()
        else:
            self.label.configure(text="Veuillez sélectionner une interface réseau valide.")

    def perform_host_discovery(self, selected_interface):
        """Effectuer la découverte des hôtes et mettre à jour l'interface utilisateur"""
        df = self.app.network_info.host_discovery(selected_interface)
        if df is not None:
            self.host_discovery_results = df
            self.show_host_discovery(df)
        else:
            self.label.configure(text="Aucun hôte découvert.")
        
    def show_host_discovery(self, df):
        """Display host discovery results in a table"""
        if self.table_frame:
            self.table_frame.destroy()

        self.table_frame = customtkinter.CTkFrame(self)
        self.table_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=0, sticky="nsew")

        self.label.grid_forget()  # Remove the label from the grid

        # Define the function to handle row selection
        def on_row_select(event):
            selected_row = pt.get_row_clicked(event)
            if selected_row is not None:
                selected_machine = df.iloc[selected_row]
                self.show_host_details(selected_machine)

        pt = Table(self.table_frame, dataframe=df, editable=False)
        pt.bind("<Double-1>", on_row_select)  # Double clique pour afficher les détails
        pt.show()

    def show_host_details(self, machine_details):
        """Show detailed information of the selected machine"""
        detail_text = (
            f"Machine Details:\n"
            f"----------------\n"
            f"Hostname:        {machine_details['Hostname']}\n"
            f"IP Address:      {machine_details['IP Address']}\n"
            f"Status:          {machine_details['Status']}\n"
            f"Latency:         {machine_details['Latency']}\n"
            f"MAC Address:     {machine_details['MAC Address']}\n"
            f"Vendor:          {machine_details['Vendor']}\n"
        )
        
        if self.details_text:
            self.details_text.destroy()

        self.details_text = customtkinter.CTkTextbox(self, height=10)
        self.details_text.insert("1.0", detail_text)
        self.details_text.configure(state="disabled", font=("Arial", 12))
        self.details_text.grid(row=2, column=0, columnspan=1, padx=10, pady=10, sticky="nsew")

        ip_address = machine_details['IP Address']

        # Check if port scan results already exist for this IP
        if ip_address in self.port_scan_results:
            port_results = self.port_scan_results[ip_address]
            self.display_port_scan_results(port_results)
        else:
            if self.scan_ports_button:
                self.scan_ports_button.destroy()

        self.scan_ports_button = customtkinter.CTkButton(self, text="Scan Ports", command=lambda: self.scan_ports(machine_details))
        self.scan_ports_button.grid(row=2, column=0, columnspan=1, padx=20, pady=20, sticky="ne")

    def scan_ports(self, machine_details):
        """Function to scan ports of the selected machine"""
        self.scan_ports_button.configure(state="disabled")
        ip_address = machine_details['IP Address']
        self.details_text.configure(state="normal")
        self.details_text.insert("end", "\n\nPort scan in progress...")
        self.details_text.configure(state="disabled")
    
        port_scan_thread = threading.Thread(target=self.perform_port_scan, args=(ip_address,))
        port_scan_thread.start()

    def perform_port_scan(self, ip_address):
        """Perform port scan and update UI"""
        port_results = self.app.network_info.port_scan(ip_address)
        if port_results is not None:
            result_text = (
                "Port Scan Results:\n"
                "-------------------\n"
            )
            for index, row in port_results.iterrows():
                result_text += f"Port {row['Port']}: {row['State']} ({row['Service']} {row['Version']})\n"
                if row['Script Output']:
                    script_output_formatted = "\n    ".join(row['Script Output'].split("\n"))
                    result_text += f"    {script_output_formatted}\n"
        else:
            result_text = "No open ports found."

        self.port_scan_results[ip_address] = result_text  # Cache the port scan results
        self.display_port_scan_results(result_text)
        self.scan_ports_button.configure(state="normal")

    def display_port_scan_results(self, result_text):
        """Display port scan results in the details text box"""
        if self.details_text:
            self.details_text.configure(state="normal")
            self.details_text.insert("end", f"\n\n{result_text}")
            self.details_text.configure(state="disabled")

class MainFrame(customtkinter.CTkFrame):
    """Main frame for displaying content"""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.label = customtkinter.CTkLabel(self, text="")
        self.label.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")

        self.host_discovery_frame = HostDiscoveryFrame(self, app)  # Initialize HostDiscoveryFrame with app instance

    def show_welcome_message(self):
        """Affiche la frame principale de Bienvenue"""
        self.label.configure(text="Welcome to the SDV Project - Pentest Toolbox application!")

    def show_host_discovery_frame(self):
        """Affiche la frame principale du Host Discovery"""
        self.label.configure(text="")
        self.host_discovery_frame.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")

    def hide_host_discovery_frame(self):
        """Masque la frame du Host Discovery"""
        self.host_discovery_frame.grid_remove()  # Utilise grid_remove() pour masquer la frame

class App(customtkinter.CTk):
    """Main class to manage application display"""

    def __init__(self):
        super().__init__()

        self.title("SDV Project - Pentest Toolbox")
        self.geometry("1200x900")
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure((1, 2), weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self.header_frame = customtkinter.CTkFrame(self, fg_color="green")
        self.header_frame.grid(row=0, column=0, columnspan=3, sticky="news")
        self.header_frame.grid_columnconfigure(0, weight=1)
        self.header_frame.grid_rowconfigure(0, weight=1)
        self.header_label = customtkinter.CTkLabel(self.header_frame, text="Header")
        self.header_label.grid(row=0, column=0, padx=0, pady=0, sticky="ew")

        self.network_interface_frame = NetworkInterfaceFrame(self)
        self.network_interface_frame.grid(row=0, column=0, columnspan=2, padx=0, pady=0, sticky="nw")

        self.menu_frame = MenuFrame(self, self.show_frame)
        self.menu_frame.grid(row=1, padx=0, pady=(10, 0), sticky="nw")

        self.main_frame = MainFrame(self, self)  # Pass 'self' as 'app' argument
        self.main_frame.grid(row=1, column=1, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.main_frame.show_welcome_message()

        self.network_info = NetworkInfo()

    def log_event(self, message):
        """Affiche tous les actions effectués"""
        print(message)

    def show_frame(self, frame_name):
        """Affiche toutes les frames principales"""
        self.log_event(f"Showing frame: {frame_name}")
        if frame_name == "Host Discovery":
            self.main_frame.show_host_discovery_frame()
        else:
            self.main_frame.show_welcome_message()
            self.main_frame.hide_host_discovery_frame()  # Appel pour masquer la frame HostDiscoveryFrame

if __name__ == "__main__":
    app = App()
    app.mainloop()
