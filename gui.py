import customtkinter

class WidgetName(customtkinter.CTkFrame):
    """Class qui possède par défaut la taille d'une Frame"""
    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.title = title

class HeaderFrame(WidgetName):
    """"""


class MyCheckboxFrame(customtkinter.CTkFrame):
    """Class qui permet de créer dynamiquement des Frames avec des Checkbox"""

    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.title = title
        self.checkboxes = []

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=6)
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        for i, value in enumerate(self.values):
            checkbox = customtkinter.CTkCheckBox(self, text=value)
            checkbox.grid(row=i+1, column=0, padx=10, pady=(10, 0), sticky="w")
            self.checkboxes.append(checkbox)

    def get(self):
        checked_checkboxes = []
        for checkbox in self.checkboxes:
            if checkbox.get() == 1:
                checked_checkboxes.append(checkbox.cget("text"))
        return checked_checkboxes

class MyRadiobuttonFrame(customtkinter.CTkFrame):
    """Class qui permet de créer dynamiquement des Frames avec des RadioButton"""
    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.title = title
        self.radiobuttons = []
        self.variable = customtkinter.StringVar(value="")

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=6)
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        for i, value in enumerate(self.values):
            radiobutton = customtkinter.CTkRadioButton(self, text=value, value=value, variable=self.variable)
            radiobutton.grid(row=i + 1, column=0, padx=10, pady=(10, 0), sticky="w")
            self.radiobuttons.append(radiobutton)

    def get(self):
        return self.variable.get()

    def set(self, value):
        self.variable.set(value)

class MyScrollableCheckboxFrame(customtkinter.CTkScrollableFrame):
    """Fonction pour créer une Frame avec des Checkbox Scrollable"""
    # More exemple with : https://github.com/TomSchimansky/CustomTkinter/blob/master/examples/scrollable_frame_example.py

    def __init__(self, master, title, values):
        super().__init__(master, label_text=title)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.checkboxes = []

        for i, value in enumerate(self.values):
            checkbox = customtkinter.CTkCheckBox(self, text=value)
            checkbox.grid(row=i, column=0, padx=10, pady=(10, 0), sticky="w")
            self.checkboxes.append(checkbox)

    def get(self):
        checked_checkboxes = []
        for checkbox in self.checkboxes:
            if checkbox.get() == 1:
                checked_checkboxes.append(checkbox.cget("text"))
        return checked_checkboxes

class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("400x300")

        self.label = customtkinter.CTkLabel(self, text="ToplevelWindow")
        self.label.pack(padx=20, pady=20)

class OptionMenuFrame(customtkinter.CTkFrame):
    def __init__(self, master, values, initial_value="option 2"):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)

        self.optionmenu_var = customtkinter.StringVar(value=initial_value)
        self.optionmenu = customtkinter.CTkOptionMenu(self, values=values,
                                                      command=self.optionmenu_callback,
                                                      variable=self.optionmenu_var)
        self.optionmenu.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

    def optionmenu_callback(self, choice):
        print("optionmenu dropdown clicked:", choice)

class App(customtkinter.CTk):
    """Class principale pour gérer l'affichage de l'application"""

    def __init__(self):
        super().__init__()

        self.title("my app")
        self.geometry("950x650")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0, 1, 2, 3, 4), weight=1)

        self.header_frame = customtkinter.CTkFrame(self, fg_color="green")  # Change the background color as needed
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="new")
        self.header_frame.grid_columnconfigure(0, weight=1)
        self.header_label = customtkinter.CTkLabel(self.header_frame, text="Header", corner_radius=6)
        self.header_label.grid(row=0, column=0, padx=10, pady=(20,0), sticky="ew")

        #self.checkbox_frame = MyCheckboxFrame(self, "Values", values=["value 1", "value 2", "value 3"])
        #self.checkbox_frame.grid(row=1, column=0, padx=10, sticky="nsew")
        
        #self.radiobutton_frame = MyRadiobuttonFrame(self, "Options", values=["option 1", "option 2"])
        #self.radiobutton_frame.grid(row=1, column=1, padx=(0, 10), pady=(10, 0), sticky="nsew")
        #self.radiobutton_frame.configure(fg_color="transparent")

        #self.optionmenu_frame = OptionMenuFrame(self, values=["option 1", "option 2"])
        #self.optionmenu_frame.grid(row=2, column=0, padx=10, pady=10, columnspan=2, sticky="ew")

        #self.button = customtkinter.CTkButton(self, text="my button", command=self.button_callback)
        #self.button.grid(row=3, column=0, padx=10, pady=10, sticky="ew", columnspan=2)

        #self.button_1 = customtkinter.CTkButton(self, text="open toplevel", command=self.open_toplevel)
        #self.button_1.grid(row=4, column=0, padx=20, pady=20, sticky="ew", columnspan=2)

        #self.toplevel_window = None

    def open_toplevel(self):
        if self.toplevel_window is None or not self.toplevel_window.winfo_exists():
            self.toplevel_window = ToplevelWindow(self)  # create window if its None or destroyed
        else:
            self.toplevel_window.focus()  # if window exists focus it

    def button_callback(self):
        """Fonction pour log de l'application"""

        print("checkbox_frame:", self.checkbox_frame.get())
        print("radiobutton_frame:", self.radiobutton_frame.get())
        print("optionmenu_frame:", self.optionmenu_frame.optionmenu_var.get())


app = App()
app.mainloop()
