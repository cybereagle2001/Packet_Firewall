import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
from firewall_perfect import *
from datetime import datetime
import json
import os

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FortiGate-Style Firewall")
        self.root.geometry("1200x600")
        self.root.configure(bg="#1E3A8A")
        self.ID = self.load_id_counter()

        # Create Main Layout
        self.main_frame = tk.Frame(root, bg="#1E3A8A")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar Menu
        self.sidebar = tk.Frame(self.main_frame, bg="#162A6A", width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        self.menu_buttons = {
            "Packets Dashboard": self.show_packets_dashboard,
            "Policy Creation": self.show_policy_creation,
        }

        for text, command in self.menu_buttons.items():
            btn = tk.Button(self.sidebar, text=text, command=command, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=20)
            btn.pack(pady=10)

        # Main Content Frame
        self.content_frame = tk.Frame(self.main_frame, bg="#1E3A8A")
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.packet_table = None
        self.policy_table = None
        self.capturing = False
        self.firewall = Firewall(interface="eth0", log_file="packet_log.txt")
        self.capture_thread = None
        self.show_packets_dashboard()

    def load_id_counter(self):
        """
        Load the ID counter from a file. If the file doesn't exist, start from 0.
        """
        if os.path.exists("id_counter.json"):
            with open("id_counter.json", "r") as file:
                return json.load(file).get("ID", 0)
        return 0

    def save_id_counter(self):
        """
        Save the ID counter to a file.
        """
        with open("id_counter.json", "w") as file:
            json.dump({"ID": self.ID}, file)

    def show_packets_dashboard(self):
        self.clear_content()

        # Title Label
        title_label = tk.Label(self.content_frame, text="Packets Dashboard", font=("Arial", 16, "bold"), fg="white", bg="#1E3A8A")
        title_label.pack(pady=10)

        # Table for Packet Details
        columns = ("Timestamp", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Action")
        self.packet_table = ttk.Treeview(self.content_frame, columns=columns, show="headings", height=15)
        self.packet_table.pack(fill=tk.BOTH, expand=True)

        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=150)

        # Buttons for Start and Stop Capture
        button_frame = tk.Frame(self.content_frame, bg="#1E3A8A")
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Capture", command=self.start_capture, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_capture, bg="#F44336", fg="white", font=("Arial", 12, "bold"))
        self.stop_button.grid(row=0, column=1, padx=10)

        self.update_display()

    def start_capture(self):
        if not self.capturing:
            self.capturing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.capture_thread = Thread(target=self.firewall.start_capture, daemon=True)
            self.capture_thread.start()
            self.update_display()

    def stop_capture(self):
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def show_policy_creation(self):
        self.clear_content()

        # Title Label
        title_label = tk.Label(self.content_frame, text="Policy Creation", font=("Arial", 16, "bold"), fg="white", bg="#1E3A8A")
        title_label.pack(pady=10)

        # Policy Form
        policy_form = tk.Frame(self.content_frame, bg="#1E3A8A")
        policy_form.pack(pady=10)

        # Protocol Dropdown
        tk.Label(policy_form, text="Protocol:", bg="#1E3A8A", fg="white").grid(row=0, column=0, padx=5, pady=5)
        self.protocol_var = tk.StringVar()
        self.protocol_dropdown = ttk.Combobox(policy_form, textvariable=self.protocol_var, state="readonly", width=10)
        self.protocol_dropdown['values'] = ("TCP", "UDP", "ICMP")
        self.protocol_dropdown.grid(row=0, column=1, padx=5, pady=5)
        self.protocol_dropdown.current(0)  # Set default value

        # Action Dropdown
        tk.Label(policy_form, text="Action:", bg="#1E3A8A", fg="white").grid(row=0, column=2, padx=5, pady=5)
        self.action_var = tk.StringVar()
        self.action_dropdown = ttk.Combobox(policy_form, textvariable=self.action_var, state="readonly", width=10)
        self.action_dropdown['values'] = ("Allow", "Deny")
        self.action_dropdown.grid(row=0, column=3, padx=5, pady=5)
        self.action_dropdown.current(0)  # Set default value

        # Source IP
        tk.Label(policy_form, text="Source IP:", bg="#1E3A8A", fg="white").grid(row=0, column=4, padx=5, pady=5)
        self.source_ip_entry = tk.Entry(policy_form, width=15)
        self.source_ip_entry.grid(row=0, column=5, padx=5, pady=5)

        # Destination IP
        tk.Label(policy_form, text="Dest IP:", bg="#1E3A8A", fg="white").grid(row=0, column=6, padx=5, pady=5)
        self.dest_ip_entry = tk.Entry(policy_form, width=15)
        self.dest_ip_entry.grid(row=0, column=7, padx=5, pady=5)

        # Source Port
        tk.Label(policy_form, text="Source Port:", bg="#1E3A8A", fg="white").grid(row=0, column=8, padx=5, pady=5)
        self.source_port_entry = tk.Entry(policy_form, width=10)
        self.source_port_entry.grid(row=0, column=9, padx=5, pady=5)

        # Destination Port
        tk.Label(policy_form, text="Dest Port:", bg="#1E3A8A", fg="white").grid(row=0, column=10, padx=5, pady=5)
        self.dest_port_entry = tk.Entry(policy_form, width=10)
        self.dest_port_entry.grid(row=0, column=11, padx=5, pady=5)

        # Add Policy Button
        add_policy_button = tk.Button(policy_form, text="Add Policy", command=self.add_policy, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
        add_policy_button.grid(row=0, column=12, padx=10, pady=5)

        # Policy Table
        policy_table_frame = tk.Frame(self.content_frame, bg="#1E3A8A")
        policy_table_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        columns = ("ID", "Protocol", "Action", "Source IP", "Destination IP", "Source Port", "Destination Port")
        self.policy_table = ttk.Treeview(policy_table_frame, columns=columns, show="headings", height=10)
        self.policy_table.pack(fill=tk.BOTH, expand=True)

        for col in columns:
            self.policy_table.heading(col, text=col)
            self.policy_table.column(col, width=150)

        # Load existing policies into the table
        self.update_policy_table()

    def add_policy(self):
        self.ID = self.ID + 1
        ID = self.ID
        self.save_id_counter()
        protocol = self.protocol_var.get()
        action = self.action_var.get()
        source_ip = self.source_ip_entry.get()
        dest_ip = self.dest_ip_entry.get()
        source_port = self.source_port_entry.get()
        dest_port = self.dest_port_entry.get()

        if protocol or source_ip or dest_ip or source_port or dest_port:
            policy = f"{ID},{protocol},{action},{source_ip},{dest_ip},{source_port},{dest_port}"
            self.firewall.add_policy(policy)
            messagebox.showinfo("Success", "Policy added successfully!")
            self.update_policy_table()  # Refresh the policy table
        else:
            messagebox.showwarning("Input Error", "Please fill in at least one field.")

    def update_policy_table(self):
        """Update the policy table with the latest policies in reverse order."""
        if self.policy_table:
            self.policy_table.delete(*self.policy_table.get_children())  # Clear existing rows
            for policy in self.firewall.policies:
                # Split the policy string into its components
                policy_parts = policy.split(",")
                if len(policy_parts) == 7:  # Ensure the policy has exactly 7 parts
                    # Insert the policy at the beginning of the table
                    self.policy_table.insert("", "0", values=policy_parts)  # "0" inserts at the top

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        if hasattr(self, 'packet_table') and self.packet_table:
            self.packet_table = None
        if hasattr(self, 'policy_table') and self.policy_table:
            self.policy_table = None

    def update_display(self):
        if self.capturing and self.packet_table:
            packet_summaries = self.firewall.get_packet_summaries()
            self.packet_table.delete(*self.packet_table.get_children())
            for summary in packet_summaries:
                parts = summary.split(", ")
                values = [part.split(": ")[1] for part in parts]
                self.packet_table.insert("", 0, values=values)
        if self.capturing:
            self.root.after(1000, self.update_display)


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
