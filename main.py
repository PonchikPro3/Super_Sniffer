# main.py

import customtkinter as ctk
from tkinter import messagebox
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import requests
from sniffer_core import get_ip_from_url, parse_filters, should_display_line

# Настройка внешнего вида
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

def start_sniffing(url, output_callback, stop_event, filters="", use_filters=False, invert_filters=False):
    """
    Запускает сниффинг пакетов, исходящих к IP-адресу, полученному из URL.
    С фильтрацией по ключевым словам и инверсией.
    """
    try:
        target_ip = get_ip_from_url(url)
        output_callback(f"[INFO] Целевой IP: {target_ip}")

        filter_keywords = parse_filters(filters)

        def packet_handler(packet):
            if stop_event.is_set():
                return
            line = f"[PACKET] {packet.summary()}"
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                payload = bytes(packet[IP].payload)
                line = f"[{ip_src} -> {ip_dst}] Protocol: {protocol} | Payload: {payload[:100]} | {packet.summary()}"

            # Применяем фильтрацию
            if should_display_line(line, filter_keywords, use_filters, invert_filters):
                output_callback(line)

        # Запускаем сниффинг
        sniff_thread = threading.Thread(
            target=lambda: sniff(filter=f"host {target_ip}", prn=packet_handler, stop_filter=lambda x: stop_event.is_set(), timeout=20),
            daemon=True
        )
        sniff_thread.start()

        # Делаем HTTP-запрос для генерации трафика
        try:
            output_callback("[INFO] Отправляем HTTP-запрос...")
            response = requests.get(url, timeout=5)
            output_callback(f"[INFO] HTTP-ответ: {response.status_code}")
        except Exception as e:
            output_callback(f"[ERROR] Не удалось сделать запрос: {e}")

        sniff_thread.join()
        output_callback("[INFO] Сниффинг завершён.")
    except Exception as e:
        output_callback(f"[ERROR] {e}")


class MainApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Super_Sniffer")
        self.app.geometry("500x600")
        self.app.configure(fg_color="#f8f9fa")
        self.app.iconbitmap("Super_Sniffer/iconSS.ico")

        self.filters = ""
        self.use_filters = False
        self.invert_filters = False
        self.window_stack = []
        self.current_window = "main"
        self.sniffer_thread = None
        self.stop_sniffer = threading.Event()

        self.show_main_window()

    def clear_window(self):
        for widget in self.app.winfo_children():
            widget.destroy()

    def push_window(self, window_func):
        self.window_stack.append(self.current_window)
        window_func()

    def pop_window(self):
        if self.window_stack:
            prev_window = self.window_stack.pop()
            if prev_window == "main":
                self.show_main_window()
            elif prev_window == "output":
                self.open_output_window(self.current_url)
        else:
            self.show_main_window()

    def show_main_window(self):
        self.clear_window()
        self.current_window = "main"

        title = ctk.CTkLabel(self.app, text="Super_Sniffer", font=("Helvetica", 32, "bold"))
        title.pack(pady=(30, 20))

        self.url_entry = ctk.CTkEntry(self.app, placeholder_text="Url", width=300, height=40, font=("Arial", 14))
        self.url_entry.pack(pady=10)

        start_button = ctk.CTkButton(
            self.app, text="Start", width=140, height=140, corner_radius=70,
            fg_color="#6c757d", text_color="#f8f9fa", font=("Arial", 18, "bold"),
            hover_color="#5a6268", command=self.on_start_click
        )
        start_button.pack(pady=50)

        filters_button = ctk.CTkButton(
            self.app, text="Установка фильтров", width=200, height=40,
            fg_color="#adb5bd", text_color="#f8f9fa", hover_color="#9a9fa5",
            command=lambda: self.push_window(self.open_filters_window)
        )
        filters_button.pack(side="bottom", pady=20)

    def on_start_click(self):
        url = self.url_entry.get()
        if not url.strip():
            messagebox.showerror("Ошибка", "Пожалуйста, введите URL")
        else:
            self.current_url = url
            self.push_window(lambda: self.open_output_window(url))

    def open_output_window(self, url):
        self.clear_window()
        self.current_window = "output"

        url_label = ctk.CTkLabel(self.app, text=f"URL: {url}", font=("Arial", 14))
        url_label.pack(pady=(20, 10))

        self.output_textbox = ctk.CTkTextbox(self.app, width=450, height=400, fg_color="#e9ecef", text_color="black", state="disabled")
        self.output_textbox.pack(pady=20)

        self.stop_sniffer.clear()
        self.sniffer_thread = threading.Thread(
            target=start_sniffing,
            args=(url, self.append_to_output, self.stop_sniffer, self.filters, self.use_filters, self.invert_filters),
            daemon=True
        )
        self.sniffer_thread.start()

        button_frame = ctk.CTkFrame(self.app, fg_color="transparent")
        button_frame.pack(side="bottom", pady=20)

        stop_button = ctk.CTkButton(button_frame, text="Stop", width=120, height=40, fg_color="#adb5bd", text_color="#f8f9fa", hover_color="#9a9fa5", command=self.stop_and_return_to_main)
        stop_button.pack(side="left", padx=10)

        set_filters_button = ctk.CTkButton(button_frame, text="Set filters", width=120, height=40, fg_color="#adb5bd", text_color="#f8f9fa", hover_color="#9a9fa5", command=lambda: self.push_window(self.open_filters_window))
        set_filters_button.pack(side="right", padx=10)

    def append_to_output(self, text):
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

        title = ctk.CTkLabel(self.app, text="Добавить фильтры", font=("Arial", 16))
        title.pack(pady=(20, 10))

        self.filters_entry = ctk.CTkTextbox(self.app, width=350, height=150, fg_color="#e9ecef", text_color="black")
        self.filters_entry.pack(pady=10)
        self.filters_entry.insert("0.0", self.filters)

        self.use_var = ctk.BooleanVar(value=self.use_filters)
        self.invert_var = ctk.BooleanVar(value=self.invert_filters)

        ctk.CTkCheckBox(self.app, text="Use filters", variable=self.use_var).pack(pady=5)
        ctk.CTkCheckBox(self.app, text="Invert filters", variable=self.invert_var).pack(pady=5)

        continue_button = ctk.CTkButton(
            self.app, text="Continue", width=120, height=40,
            fg_color="#adb5bd", text_color="#f8f9fa", hover_color="#9a9fa5",
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