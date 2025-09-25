import argparse
import ipaddress
import subprocess
import os
import requests
import json
import time

def detect_os(ip):
    """
    Attempts to detect the operating system of an active host using nmap.
    Note: nmap must be installed on your system for this to work.
    """
    try:
        # Use a timeout of 10 seconds to avoid long waits for non-responsive hosts.
        result = subprocess.run(['nmap', '-O', ip], capture_output=True, text=True, timeout=10)
        output = result.stdout
        for line in output.splitlines():
            if "OS details" in line:
                return line.split("OS details:")[1].strip()
            elif "Running:" in line:
                return line.split("Running:")[1].strip()
        return "Unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return "Unknown"

def main():
    """
    The main function to parse command-line arguments and run the network scan.
    """
    parser = argparse.ArgumentParser(description="A simple command-line network scanner.")
    parser.add_argument("ip_address", help="The network IP address to scan (e.g., 192.168.1.0)")
    parser.add_argument("subnet_mask", help="The subnet mask (e.g., 255.255.255.0)")

    args = parser.parse_args()
    ip_address = args.ip_address
    subnet_mask = args.subnet_mask

    print(f"Starting scan for network: {ip_address} with subnet mask: {subnet_mask}\n")
    print("-" * 70)
    print(f"{'IP Address':<20}{'Status':<15}{'Location':<25}{'Operating System'}")
    print("-" * 70)

    try:
        network = ipaddress.ip_network(f'{ip_address}/{subnet_mask}', strict=False)
        active_devices = []

        for host in network.hosts():
            ip = str(host)

            # Ping command is OS-dependent
            if os.name == 'nt':  # Windows
                command = ['ping', '-n', '1', '-w', '500', ip]
            else:  # Linux/macOS
                command = ['ping', '-c', '1', '-W', '1', ip]

            status = 'Inactive'
            location = 'Unknown'
            os_info = 'Unknown'

            try:
                # Ping the host with a 1-second timeout
                result = subprocess.run(command, capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    status = 'Active'
                    active_devices.append(ip)

                    # Get location data for active hosts
                    try:
                        geo = requests.get(f'http://ip-api.com/json/{ip}').json()
                        location = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(', ')
                        if not location or location == ",":
                            location = "Unknown"
                    except:
                        location = "Unknown"

                    # Get OS information for active hosts
                    os_info = detect_os(ip)

            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                pass # Continue to the next host if an error occurs

            print(f"{ip:<20}{status:<15}{location:<25}{os_info}")
            time.sleep(0.1) # Add a small delay to prevent resource overload

        print("\n" + "-" * 70)
        print(f"Scan complete. Found {len(active_devices)} active devices.")
        if active_devices:
            print("Active devices:")
            for device in active_devices:
                print(f" - {device}")

    except ValueError:
        print("Error: Invalid IP or subnet mask. Please try again.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()

