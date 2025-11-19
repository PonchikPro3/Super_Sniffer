import customtkinter as ctk
from tkinter import messagebox

# Настройка внешнего вида
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

class MainApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Super_Sniffer")
        self.app.geometry("500x600")
        self.app.configure(fg_color="#f8f9fa")
        # Установка иконки для главного окна
        self.app.iconbitmap("Super_Sniffer/iconSS.ico")

        self.filters = ""
        self.use_filters = False
        self.invert_filters = False

        # Стек для отслеживания окон
        self.window_stack = []
        self.current_window = "main"

        self.show_main_window()

    def clear_window(self):
        # Очистка окна
        for widget in self.app.winfo_children():
            widget.destroy()

    def push_window(self, window_func):
        # Сохраняем текущее окно в стек перед открытием нового
        self.window_stack.append(self.current_window)
        window_func()

    def pop_window(self):
        # Возвращаемся на предыдущее окно из стека
        if self.window_stack:
            prev_window = self.window_stack.pop()
            if prev_window == "main":
                self.show_main_window()
            elif prev_window == "output":
                # Для возврата в окно вывода нужно знать URL
                self.open_output_window(self.current_url)
        else:
            # Если стек пуст, возвращаемся на главное окно
            self.show_main_window()

    def show_main_window(self):
        self.clear_window()
        self.current_window = "main"

        # Заголовок
        title = ctk.CTkLabel(
            self.app,
            text="Super_Sniffer",
            font=("Helvetica", 32, "bold")
        )
        title.pack(pady=(30, 20))

        # Поле ввода URL
        self.url_entry = ctk.CTkEntry(
            self.app,
            placeholder_text="Url",
            width=300,
            height=40,
            font=("Arial", 14)
        )
        self.url_entry.pack(pady=10)

        # Кнопка "Start"
        start_button = ctk.CTkButton(
            self.app,
            text="Start",
            width=140,
            height=140,
            corner_radius=70,
            fg_color="#6c757d",
            text_color="#f8f9fa",
            font=("Arial", 18, "bold"),
            hover_color="#5a6268",
            command=self.on_start_click
        )
        start_button.pack(pady=50)

        # Кнопка "Установка фильтров"
        filters_button = ctk.CTkButton(
            self.app,
            text="Установка фильтров",
            width=200,
            height=40,
            fg_color="#adb5bd",
            text_color="#f8f9fa",
            hover_color="#9a9fa5",
            command=lambda: self.push_window(self.open_filters_window)
        )
        filters_button.pack(side="bottom", pady=20)

    def on_start_click(self):
        url = self.url_entry.get()
        if not url.strip():
            # Показать окно ошибки
            messagebox.showerror("Ошибка", "Пожалуйста, введите URL")
        else:
            self.current_url = url
            self.push_window(lambda: self.open_output_window(url))

    def open_output_window(self, url):
        self.clear_window()
        self.current_window = "output"

        # Показ URL
        url_label = ctk.CTkLabel(self.app, text=f"URL: {url}", font=("Arial", 14))
        url_label.pack(pady=(20, 10))

        # Поле вывода данных (только для чтения, с цветом фона)
        self.output_textbox = ctk.CTkTextbox(
            self.app,
            width=450,
            height=400,
            fg_color="#e9ecef",
            text_color="black",
            state="disabled"
        )
        self.output_textbox.pack(pady=20)
        self.output_textbox.configure(state="normal")
        self.output_textbox.insert("0.0", "Тестовое сообщение: данные загружаются...")
        self.output_textbox.configure(state="disabled")

        # Кнопки внизу
        button_frame = ctk.CTkFrame(self.app, fg_color="transparent")
        button_frame.pack(side="bottom", pady=20)

        stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            width=120,
            height=40,
            fg_color="#adb5bd",
            text_color="#f8f9fa",
            hover_color="#9a9fa5",
            command=self.show_main_window
        )
        stop_button.pack(side="left", padx=10)

        set_filters_button = ctk.CTkButton(
            button_frame,
            text="Set filters",
            width=120,
            height=40,
            fg_color="#adb5bd",
            text_color="#f8f9fa",
            hover_color="#9a9fa5",
            command=lambda: self.push_window(self.open_filters_window)
        )
        set_filters_button.pack(side="right", padx=10)

    def open_filters_window(self):
        self.clear_window()
        self.current_window = "filters"

        # Текст сверху
        title = ctk.CTkLabel(self.app, text="Добавить фильтры", font=("Arial", 16))
        title.pack(pady=(20, 10))

        # Поле ввода фильтров (5 строк) с цветом фона
        self.filters_entry = ctk.CTkTextbox(
            self.app,
            width=350,
            height=150,
            fg_color="#e9ecef",
            text_color="black"
        )
        self.filters_entry.pack(pady=10)
        self.filters_entry.insert("0.0", self.filters)

        # Переключатели
        self.use_var = ctk.BooleanVar(value=self.use_filters)
        self.invert_var = ctk.BooleanVar(value=self.invert_filters)

        use_filters = ctk.CTkCheckBox(self.app, text="Use filters", variable=self.use_var)
        use_filters.pack(pady=5)

        invert_filters = ctk.CTkCheckBox(self.app, text="Invert filters", variable=self.invert_var)
        invert_filters.pack(pady=5)

        # Кнопка "Continue" — возвращает на предыдущее окно
        continue_button = ctk.CTkButton(
            self.app,
            text="Continue",
            width=120,
            height=40,
            fg_color="#adb5bd",
            text_color="#f8f9fa",
            hover_color="#9a9fa5",
            command=self.save_and_return_to_prev
        )
        continue_button.pack(side="bottom", pady=30)

    def save_and_return_to_prev(self):
        self.filters = self.filters_entry.get("0.0", "end").strip()
        self.use_filters = self.use_var.get()
        self.invert_filters = self.invert_var.get()
        self.pop_window()

    def run(self):
        self.app.mainloop()


if __name__ == "__main__":
    app = MainApp()
    app.run()