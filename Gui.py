import customtkinter

StartWindow = customtkinter.CTk()
StartWindow.geometry("500x600")
StartWindow.configure(fg_color="#f8f9fa")
StartWindow.title("Supper_Sniffer")
StartWindow.iconbitmap("iconSS.ico")

label = customtkinter.CTkLabel(
    StartWindow,
    text="Supper_Sinffer",
    font=("Nunito", 40, "bold"),
    text_color="black",
    anchor=customtkinter.CENTER
)
label.pack(pady=60)

SettingsWindow = customtkinter.CTk()
SettingsWindow.geometry("600x500")
SettingsWindow.title("SettingsWindow")
SettingsWindow.iconbitmap("iconSS.ico")


StartWindow.mainloop()

