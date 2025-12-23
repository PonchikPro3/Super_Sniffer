import customtkinter as ctk
from tkinter import messagebox
import socket
from scapy.all import sniff  # Основной сниффер
from scapy.layers.inet import IP  # Класс IP-пакета
import threading
import requests  # Для автоматического HTTP-запроса
from sniffer_core import validate_url, is_admin, safe_request, check_sniff_permissions

# Настройка внешнего вида
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

def get_ip_from_url(url):

    try:
        # Убираем http/https и слэш в конце, если есть
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        host = url.split("/")[0].split(":")[0]  # Извлекаем хост
        ip = socket.gethostbyname(host)
        return ip
    except Exception as e:
        raise ValueError(f"Не удалось получить IP для URL: {url}. Ошибка: {e}")

def start_sniffing(url, output_callback, stop_event, filters="", use_filters=False, invert_filters=False):
    try:
        # Проверка прав для захвата пакетов
        can_sniff, sniff_error = check_sniff_permissions()
        if not can_sniff:
            output_callback(f"[ERROR] {sniff_error}")
            return
        
        target_ip = get_ip_from_url(url)
        output_callback(f"[INFO] Целевой IP: {target_ip}")
        output_callback(f"[INFO] Фильтр: 'host {target_ip}'")

        # Парсим фильтры: разбиваем по переносам строк и убираем пустые
        filter_keywords = [kw.strip() for kw in filters.split("\n") if kw.strip()]

        def packet_handler(packet):
            if stop_event.is_set():
                return
            # Выводим всё, что пришло
            line = f"[PACKET] {packet.summary()}"
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                payload = bytes(packet[IP].payload)
                line = f"[{ip_src} -> {ip_dst}] Protocol: {protocol} | Payload: {payload[:100]} | {packet.summary()}"

            # Применяем фильтрацию
            if use_filters and filter_keywords:
                # Проверяем, есть ли хотя бы одно ключевое слово в строке
                contains_keyword = any(kw in line for kw in filter_keywords)
                if invert_filters:
                    # Инверсия: выводим, если НЕ содержит
                    if not contains_keyword:
                        output_callback(line)
                else:
                    # Обычный режим: выводим, если содержит
                    if contains_keyword:
                        output_callback(line)
            else:
                # Если фильтры не включены, просто выводим
                output_callback(line)

        # Запускаем сниффинг с обработкой ошибок
        def safe_sniff_wrapper():
            try:
                sniff(filter=f"host {target_ip}", prn=packet_handler, stop_filter=lambda x: stop_event.is_set(), timeout=20)
            except PermissionError as e:
                output_callback(f"[ERROR] Недостаточно прав для захвата пакетов: {e}")
            except OSError as e:
                if "Npcap" in str(e) or "WinPcap" in str(e) or "libpcap" in str(e):
                    output_callback("[ERROR] Npcap/WinPcap/libpcap не установлен или недоступен")
                else:
                    output_callback(f"[ERROR] Ошибка ОС при захвате пакетов: {e}")
            except Exception as e:
                output_callback(f"[ERROR] Ошибка при захвате пакетов: {e}")
        
        sniff_thread = threading.Thread(
            target=safe_sniff_wrapper,
            daemon=True
        )
        sniff_thread.start()

        # Делаем HTTP-запрос с безопасной обработкой
        output_callback("[INFO] Отправляем HTTP-запрос...")
        success, status_code, message = safe_request(url, timeout=5)
        if success:
            output_callback(f"[INFO] HTTP-ответ: {status_code}")
        else:
            output_callback(f"[ERROR] {message}")

        sniff_thread.join()
        output_callback("[INFO] Сниффинг завершён.")
    except ValueError as e:
        output_callback(f"[ERROR] Ошибка URL: {e}")
    except Exception as e:
        output_callback(f"[ERROR] {e}")


class MainApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Super_Sniffer")
        self.app.geometry("500x600")
        self.app.configure(fg_color="#f8f9fa")
        # Установка иконки для главного окна (необязательно)
        try:
            self.app.iconbitmap("Super_Sniffer/iconSS.ico")
        except Exception:
            pass  # Иконка необязательна

        self.filters = ""
        self.use_filters = False
        self.invert_filters = False

        # Стек для отслеживания окон
        self.window_stack = []
        self.current_window = "main"

        # Переменные для сниффинга
        self.sniffer_thread = None
        self.stop_sniffer = threading.Event()

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
            corner_radius=90,
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
            return
        
        # Валидация URL
        is_valid, error_msg = validate_url(url)
        if not is_valid:
            messagebox.showerror("Ошибка URL", error_msg)
            return
        
        # Проверка прав администратора перед началом
        if not is_admin():
            messagebox.showwarning(
                "Требуются права администратора",
                "Для захвата сетевых пакетов требуются права администратора.\n\n"
                "Запустите программу от имени администратора."
            )
            return
        
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

        # Запуск сниффинга в отдельном потоке
        self.stop_sniffer.clear()
        self.sniffer_thread = threading.Thread(
            target=start_sniffing,
            args=(url, self.append_to_output, self.stop_sniffer, self.filters, self.use_filters, self.invert_filters),
            daemon=True
        )
        self.sniffer_thread.start()

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
            command=self.stop_and_return_to_main
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

    def append_to_output(self, text):
        # Потокобезопасный вывод в текстовое поле
        self.app.after(0, lambda: self._update_output(text))

    def _update_output(self, text):
        self.output_textbox.configure(state="normal")
        self.output_textbox.insert("end", text + "\n")
        self.output_textbox.see("end")
        self.output_textbox.configure(state="disabled")

    def stop_and_return_to_main(self):
        self.stop_sniffer.set()
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
        self.show_main_window()

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