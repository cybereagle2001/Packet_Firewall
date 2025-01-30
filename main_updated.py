import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from firewall_dev import *

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Packet Capture")

        # Create a Firewall instance
        self.firewall = Firewall(interface="eth0")

        # Create a text widget to display packet information
        self.packet_display = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled')
        self.packet_display.pack(padx=10, pady=10)

        # Create start and stop buttons
        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Flag to control the capture thread
        self.capturing = False

    def start_capture(self):
        """Start packet capture in a separate thread."""
        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_display.config(state='normal')
        self.packet_display.delete(1.0, tk.END)  # Clear the display
        self.packet_display.config(state='disabled')

        # Start the capture in a separate thread
        self.capture_thread = Thread(target=self.firewall.start_capture)
        self.capture_thread.start()

        # Start updating the display
        self.update_display()

    def stop_capture(self):
        """Stop packet capture."""
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_display(self):
        """Update the packet display with captured packet summaries."""
        if self.capturing:
            # Fetch packet summaries from the Firewall instance
            packet_summaries = self.firewall.get_packet_summaries()

            # Update the display with the packet summaries
            self.packet_display.config(state='normal')
            for summary in packet_summaries:
                self.packet_display.insert(tk.END, summary + "\n")
            self.packet_display.config(state='disabled')
            self.packet_display.see(tk.END)  # Scroll to the bottom

        # Schedule the next update
        if self.capturing:
            self.root.after(1000, self.update_display)  # Update every 1 second

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
