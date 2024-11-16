import socket
from concurrent.futures import ThreadPoolExecutor
import sys
import argparse
import threading

# Common ports with associated service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    636: "LDAPS",
    3306: "MySQL",
    3389: "RDP",
}

# Extended range of less-common but relevant ports
EXTENDED_MINOR_PORTS = {
    161: "SNMP",
    162: "SNMP Trap",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    1812: "RADIUS",
    2049: "NFS",
    5353: "mDNS",
    8080: "HTTP Proxy",
    8443: "HTTPS Proxy",
    8888: "Web Service",
    25565: "Minecraft Server",
    27015: "Steam Game Server",
    5432: "PostgreSQL",
    1521: "Oracle DB",
    5900: "VNC",
    6667: "IRC",
    8000: "Development Server",
    8001: "Alternate Development Server",
    4000: "Custom Application",
    5555: "ADB (Android Debug Bridge)",
    5556: "Alternate ADB",
}

def scan_port(ip, port):
    """Check if a port is open and return its status."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, EXTENDED_MINOR_PORTS.get(port, "Unknown Service"))
                return port, service
    except:
        pass
    return None

def scan_ports(ip, ports):
    """Scan multiple ports and return the results."""
    open_ports = []
    total_ports = len(ports)

    print(f"\n[+] Scanning {total_ports} ports on {ip}...\n")
    max_length = 0  # Track the maximum length of printed lines for clearing

    for idx, port in enumerate(ports):
        result = scan_port(ip, port)
        if result:
            open_ports.append(result)

        # Update progress with current port
        service = COMMON_PORTS.get(port, EXTENDED_MINOR_PORTS.get(port, "Unknown Service"))
        progress = f"  -> Progress: {idx + 1}/{total_ports} ports scanned (Current: {port}: {service})"
        max_length = max(max_length, len(progress))

        # Clear the line before printing the updated progress
        sys.stdout.write("\r" + " " * max_length)
        sys.stdout.write("\r" + progress)
        sys.stdout.flush()

    # Final newline after progress is complete
    print()
    return open_ports

def display_results(results):
    """Display scan results in a user-friendly way."""
    print("\n[+] Scan Results:")
    if results:
        print("\n  Open Ports:")
        for port, service in sorted(results):
            print(f"   - Port {port}: {service}")
    else:
        print("  No open ports found.")
    print("\n[✔] Scan completed.")

def cool_exit_prompt():
    """Prompt for another scan with a 5-second timeout."""
    print("\n[?] Excelsior? (y/n): ", end="", flush=True)
    choice = []
    timer = threading.Event()

    def get_input():
        try:
            choice.append(input().strip().lower())
        except EOFError:
            pass
        finally:
            timer.set()

    thread = threading.Thread(target=get_input, daemon=True)
    thread.start()
    timer.wait(timeout=5)

    if not choice:
        sys.exit(0)  # Quiet exit without any additional output

    return choice[0]

def interactive_menu(ip):
    """Interactive menu for selecting scan options."""
    while True:
        print("\n[+] Select Scan Mode:")
        print("  1. Common Ports (Well-Known Services)")
        print("  2. Minor Extended Ports (Includes Common Ports)")
        print("  3. Full Range (1-65535)")
        print("  4. Custom Port Range")
        print("  5. Exit\n")

        choice = input("Enter your choice (1-5): ").strip()

        if choice == "1":
            # Common ports scan
            ports = list(COMMON_PORTS.keys())
            print("\n[+] Scanning common ports...")
            results = scan_ports(ip, ports)
            display_results(results)

        elif choice == "2":
            # Minor extended range ports scan (includes common ports)
            ports = list(COMMON_PORTS.keys()) + list(EXTENDED_MINOR_PORTS.keys())
            print("\n[+] Scanning minor extended ports (includes common ports)...")
            results = scan_ports(ip, ports)
            display_results(results)

        elif choice == "3":
            # Full range scan
            print("\n[!] Full range scan may take a long time.")
            confirm = input("Do you want to proceed? (y/n): ").strip().lower()
            if confirm == "y":
                ports = range(1, 65536)
                print("\n[+] Scanning all ports...")
                results = scan_ports(ip, ports)
                display_results(results)
            else:
                print("[!] Full range scan canceled.")

        elif choice == "4":
            # Custom port range scan
            port_range = input("Enter port range (e.g., 20-100): ").strip()
            try:
                start, end = map(int, port_range.split("-"))
                ports = range(start, end + 1)
                print(f"\n[+] Scanning ports {start}-{end}...")
                results = scan_ports(ip, ports)
                display_results(results)
            except ValueError:
                print("[!] Invalid range. Please enter in the format 'start-end'.")

        elif choice == "5":
            break

        else:
            print("[!] Invalid choice. Please try again.")

        # Prompt for another scan
        retry = cool_exit_prompt()
        if retry != "y":
            break

def main():
    parser = argparse.ArgumentParser(description="Interactive Port Scanner")
    parser.add_argument("ip", help="Target IP address to scan")
    args = parser.parse_args()

    interactive_menu(args.ip)

if __name__ == "__main__":
    main()