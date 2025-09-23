import argparse
import ipaddress
import subprocess
import os
import requests
import json
import time
import threading
from tkinter import Tk, Label, Button, Entry
from tkinter.ttk import Treeview, Style
import tkinter as tk
from tkinter import font as tkfont
from tkinter import scrolledtext
from tkinter import messagebox

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg="#f4f4f4")
        
        # Configure a custom font
        self.base_font = tkfont.Font(family="Helvetica", size=10)
        self.heading_font = tkfont.Font(family="Helvetica", size=14, weight="bold")
        self.status_font = tkfont.Font(family="Helvetica", size=11, weight="bold")

        self.style = Style()
        self.style.configure("TButton", font=self.base_font, padding=5)
        self.style.configure("TLabel", font=self.base_font, background="#f4f4f4")

        self.is_scanning = False
        self.stop_scan_flag = False
        
        # UI Elements
        self.setup_ui()

    def setup_ui(self):
        # Header and Inputs Frame
        header_frame = tk.Frame(self.root, bg="#dcdcdc", padx=10, pady=10)
        header_frame.pack(pady=10, fill="x")

        # Title Label
        title_label = Label(header_frame, text="Network Scanner Tool", font=self.heading_font, bg="#dcdcdc", fg="#333")
        title_label.pack(pady=(0, 10))

        # Input Frame
        input_frame = tk.Frame(header_frame, bg="#dcdcdc")
        input_frame.pack()

        Label(input_frame, text="Network IP:", bg="#dcdcdc").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = Entry(input_frame, width=20, font=self.base_font)
        self.ip_entry.insert(0, "192.168.1.0")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        Label(input_frame, text="Subnet Mask:", bg="#dcdcdc").grid(row=0, column=2, padx=5, pady=5)
        self.subnet_entry = Entry(input_frame, width=20, font=self.base_font)
        self.subnet_entry.insert(0, "255.255.255.0")
        self.subnet_entry.grid(row=0, column=3, padx=5, pady=5)

        # Buttons Frame
        button_frame = tk.Frame(header_frame, bg="#dcdcdc")
        button_frame.pack(pady=10)
        self.scan_button = Button(button_frame, text="Start Scan", command=self.start_scan, bg="#4CAF50", fg="white", relief="raised", padx=10)
        self.scan_button.grid(row=0, column=0, padx=5)

        self.stop_button = Button(button_frame, text="Stop Scan", command=self.stop_scan, bg="#F44336", fg="white", relief="raised", padx=10, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        # Status Message
        self.status_label = Label(self.root, text="Ready to scan.", font=self.status_font, bg="#f4f4f4")
        self.status_label.pack(pady=5)
        
        # Results Table (Treeview)
        columns = ("ip", "status", "location")
        self.results_tree = Treeview(self.root, columns=columns, show="headings")
        self.results_tree.heading("ip", text="IP Address")
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("location", text="Location")

        self.results_tree.column("ip", width=150, anchor="w")
        self.results_tree.column("status", width=100, anchor="center")
        self.results_tree.column("location", width=250, anchor="w")
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.results_tree.pack(expand=True, fill="both", padx=10)

        # Active IPs Block
        active_frame = tk.Frame(self.root, bg="#f4f4f4")
        active_frame.pack(pady=10, fill="x")
        Label(active_frame, text="Active Devices Found:", font=self.heading_font, bg="#f4f4f4").pack()
        self.active_text = scrolledtext.ScrolledText(active_frame, height=5, font=self.base_font)
        self.active_text.pack(fill="x", padx=10)

    def run_scan(self):
        """Performs the network scan in a separate thread."""
        ip_address = self.ip_entry.get()
        subnet_mask = self.subnet_entry.get()

        if not ip_address or not subnet_mask:
            self.update_status("Error: Missing IP or subnet.", "red")
            self.reset_ui()
            return

        self.update_status("Scanning in progress...", "orange")
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_tree.delete(*self.results_tree.get_children())
        self.active_text.delete('1.0', tk.END)
        self.stop_scan_flag = False
        active_ips = []

        try:
            network = ipaddress.ip_network(f'{ip_address}/{subnet_mask}', strict=False)
            
            for host in network.hosts():
                if self.stop_scan_flag:
                    break
                
                ip = str(host)
                status = 'Inactive'
                location = 'Unknown'

                # Ping command is OS-dependent
                if os.name == 'nt':  # Windows
                    command = ['ping', '-n', '1', '-w', '500', ip]
                else:  # Linux/macOS
                    command = ['ping', '-c', '1', '-W', '1', ip]

                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=1)
                    if result.returncode == 0:
                        status = 'Active'

                        try:
                            geo = requests.get(f'http://ip-api.com/json/{ip}').json()
                            location = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(', ')
                            if not location or location == ",":
                                location = "Unknown"
                        except:
                            location = "Unknown"
                        
                        active_ips.append(ip)

                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass # Continue to the next host if an error occurs

                # Update the GUI from the main thread
                self.root.after(0, self.add_to_table, ip, status, location)
                time.sleep(0.05)
            
            if not self.stop_scan_flag:
                self.update_status("Scan complete.", "green")
                self.root.after(0, self.update_active_ips, active_ips)
            else:
                self.update_status("Scan stopped by user.", "red")

        except ValueError:
            self.update_status("Error: Invalid IP or subnet mask.", "red")
        except Exception as e:
            self.update_status(f"An unexpected error occurred: {e}", "red")

        self.reset_ui()

    def add_to_table(self, ip, status, location):
        """Adds a new row to the Treeview table."""
        self.results_tree.insert('', 'end', values=(ip, status, location))

    def update_active_ips(self, active_ips):
        """Updates the active IPs scrolled text box."""
        self.active_text.delete('1.0', tk.END)
        if active_ips:
            for ip in active_ips:
                self.active_text.insert(tk.END, f"{ip}\n")
        else:
            self.active_text.insert(tk.END, "No active devices found.")

    def update_status(self, message, color):
        """Updates the status label."""
        self.status_label.config(text=message, fg=color)

    def reset_ui(self):
        """Resets the UI elements to their initial state."""
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_scan(self):
        """Starts the scanning process in a separate thread."""
        if not self.is_scanning:
            self.is_scanning = True
            scan_thread = threading.Thread(target=self.run_scan, daemon=True)
            scan_thread.start()

    def stop_scan(self):
        """Sets the flag to stop the scanning process."""
        if self.is_scanning:
            self.stop_scan_flag = True

if __name__ == '__main__':
    root = Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
