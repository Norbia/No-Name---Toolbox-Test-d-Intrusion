import pandas as pd
from pandastable import Table, TableModel
from network_info import NetworkInfo
import customtkinter


class WidgetName(customtkinter.CTkFrame):
    """Base class for frames with default size of a Frame"""
    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.title = title

class HeaderFrame(WidgetName):
    """Header frame to be implemented"""
    pass

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
        self.master.log_event(f"Button clicked: {action}")
        self.callback(action)

class NetworkInterfaceFrame(customtkinter.CTkFrame):
    """Frame for displaying network interface information"""

    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.network_info = NetworkInfo()
        self.network_interfaces, self.main_interface_info = self.network_info.get_network_interfaces_info()

        self.interface_label = customtkinter.CTkLabel(self, text="Select Network Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        interface_names = self.network_interfaces['Interface'].to_list()
        self.interfaces_var = customtkinter.StringVar(value=self.main_interface_info['Interface'].iloc[0])
        self.interfaces_menu = customtkinter.CTkOptionMenu(self, values=interface_names, command=self.update_ip_address, variable=self.interfaces_var)
        self.interfaces_menu.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.ip_label = customtkinter.CTkLabel(self, text="IP Address:")
        self.ip_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.ip_var = customtkinter.StringVar(value=self.main_interface_info['IP Address'].iloc[0])
        self.ip_address_label = customtkinter.CTkLabel(self, textvariable=self.ip_var)
        self.ip_address_label.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    def update_ip_address(self, *args):
        selected_interface = self.interfaces_var.get()
        if selected_interface:
            ip_address = self.network_info.get_ip_by_interface_name(selected_interface)
            if ip_address:
                self.ip_var.set(ip_address)
                self.master.log_event(f"Interface changed to: {selected_interface} with IP: {ip_address}")
            else:
                self.ip_var.set("")
                self.master.log_event(f"Interface {selected_interface} does not have an associated IP address")
        else:
            self.ip_var.set("")
            self.master.log_event("No network interface selected")

class MainFrame(customtkinter.CTkFrame):
    """Main frame for displaying content"""

    def __init__(self, master):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.label = customtkinter.CTkLabel(self, text="")
        self.label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.table_frame = None

    def show_welcome_message(self):
        if self.table_frame:
            self.table_frame.destroy()
        self.label.configure(text="Welcome to the SDV Project - Pentest Toolbox application!")

    def show_host_discovery(self, df, network_interface_frame):
        if self.table_frame:
            self.table_frame.destroy()

        self.table_frame = customtkinter.CTkFrame(self)
        self.table_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.label.grid_forget()

        pt = Table(self.table_frame, dataframe=df, editable=False)
        pt.show()

        # Add the host_discovery relaunch button
        self.relaunch_button = customtkinter.CTkButton(self.table_frame, text="Refresh", 
                                                       command=lambda: self.relaunch_host_discovery(network_interface_frame))
        self.relaunch_button.grid(row=1, column=0, padx=10, pady=10)

    def relaunch_host_discovery(self, network_interface_frame):
        selected_ip = network_interface_frame.ip_var.get()
        if selected_ip:
            self.label.configure(text=f"Relaunching Host Discovery for IP: {selected_ip}")
            self.master.log_event(f"Relaunching Host Discovery for IP: {selected_ip}")
            df = self.master.network_info.host_discovery(ip_address=selected_ip)
            self.show_host_discovery(df, network_interface_frame)
        else:
            self.label.configure(text="Select a network interface first.")
            self.master.log_event("Attempted to relaunch Host Discovery without selecting a network interface")

class App(customtkinter.CTk):
    """Main class to manage application display"""

    def __init__(self):
        super().__init__()

        self.title("SDV Project - Pentest Toolbox")
        self.geometry("950x650")
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
        self.menu_frame.grid(row=1, padx=0, pady=(0, 0), sticky="nw")

        self.main_frame = MainFrame(self)
        self.main_frame.grid(row=1, column=1, columnspan=2, padx=0, pady=0, sticky="news")

        self.main_frame.show_welcome_message()

        self.network_info = NetworkInfo()

    def log_event(self, message):
        print(message)

    def show_frame(self, frame_name):
        self.log_event(f"Showing frame: {frame_name}")
        if frame_name == "Host Discovery":
            df = self.network_info.get_host_discovery_df()
            self.main_frame.show_host_discovery(df, self.network_interface_frame)
        else:
            self.main_frame.show_welcome_message()

if __name__ == "__main__":
    app = App()
    app.mainloop()
