import tkinter as tk
from tkinter import ttk
from threading import Thread
from firewall_dev import *
from datetime import datetime

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Firewall")
        self.root.geometry("1000x500")
        self.root.configure(bg="#1E3A8A")  # Changed background to blue

        # Title Label
        title_label = tk.Label(root, text="Packet Firewall", font=("Arial", 16, "bold"), fg="white", bg="#1E3A8A")
        title_label.pack(pady=10)

        # Frame for Table
        table_frame = tk.Frame(root, bg="#1E3A8A")
        table_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Table for Packet Details
        columns = ("Timestamp", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        self.packet_table.pack(fill=tk.BOTH, expand=True)

        # Set Column Headings
        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=150)

        # Firewall Instance
        self.firewall = Firewall(interface="eth0")
        
        # Control Buttons
        button_frame = tk.Frame(root, bg="#1E3A8A")
        button_frame.pack(pady=10)
        
        self.start_button = tk.Button(button_frame, text="Start Capture", command=self.start_capture, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
        self.start_button.grid(row=0, column=0, padx=10)
        
        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_capture, bg="#F44336", fg="white", font=("Arial", 12, "bold"), state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10)

        # Capture Control Flag
        self.capturing = False

    def start_capture(self):
        """Start packet capture."""
        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_table.delete(*self.packet_table.get_children())

        # Start Sniffing in a Separate Thread
        self.capture_thread = Thread(target=self.firewall.start_capture, daemon=True)
        self.capture_thread.start()
        self.update_display()

    def stop_capture(self):
        """Stop packet capture."""
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_display(self):
        """Update the packet display with captured data."""
        if self.capturing:
            packet_summaries = self.firewall.get_packet_summaries()
            self.packet_table.delete(*self.packet_table.get_children())
            
            for summary in reversed(packet_summaries):  # Show new logs at the top
                parts = summary.split(", ")
                values = [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] + [part.split(": ")[1] for part in parts]  # Add timestamp
                self.packet_table.insert("", 0, values=values)  # Insert at the top

        if self.capturing:
            self.root.after(1000, self.update_display)  # Refresh every second

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()

