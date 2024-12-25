import PacketCapture
import DetectionEngine
import Logger
import Notifier
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("600x500")
        self.root.configure(bg="#d3d3d3")  # Set background color to light gray

        self.status_label = tk.Label(root, text="Status: Stopped", fg="red", bg="#d3d3d3")
        self.status_label.pack(pady=5)

        self.start_button = tk.Button(root, text="Start IDS", command=self.start_ids, bg="#4CAF50", fg="white")
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop IDS", command=self.stop_ids, bg="#f44336", fg="white")
        self.stop_button.pack(pady=5)

        self.report_button = tk.Button(root, text="Generate Report", command=self.generate_report, bg="#2196F3", fg="white")
        self.report_button.pack(pady=5)

        self.log_display = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled', bg="#f0f0f0")
        self.log_display.pack(pady=10)

    def start_ids(self):
        self.capture_thread = threading.Thread(target=PacketCapture.start_packet_capture, args=('Ethernet', self.log_message))
        self.capture_thread.start()
        self.status_label.config(text="Status: Running", fg="green")
        self.log_message("Intrusion Detection System started.")

    def stop_ids(self):
        PacketCapture.stop_packet_capture()
        self.status_label.config(text="Status: Stopped", fg="red")
        self.log_message("Intrusion Detection System stopped.")

    def generate_report(self):
        Logger.analyze_log_file()
        Logger.generate_report()
        Logger.archive_logs()
        self.log_message("Report generated and logs archived.")
        self.log_message("Report saved at: detailed_report.txt")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.config(state='normal')
        self.log_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_display.config(state='disabled')
        self.log_display.yview(tk.END)

def create_ui():
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    create_ui() 