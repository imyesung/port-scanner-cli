# Port Scanner CLI
---

A simple, interactive command-line tool for scanning ports on a target IP address.
This tool supports multiple scan modes for various use cases and provides clear, actionable results.

---
Features

- Multiple Scan Modes:
  - Common Ports (e.g., HTTP, HTTPS, FTP, SSH)
  - Extended Ports (less-common but relevant services)
  - Full-Range Scanning (ports 1–65535)
  - Custom Port Ranges

- Interactive and Intuitive:
  - User-friendly menu-based interaction for selecting scan modes.
- Real-Time Progress Updates:
  - Displays scanning progress dynamically for transparency.
- Efficient Scanning:
  - Multithreaded for faster execution.
- Service Detection:
  - Identifies the common services associated with open ports.
  

```
[+] Scanning 12 ports on 192.168.1.1...
  -> Progress: 12/12 ports scanned (Current: 443: HTTPS)

[+] Scan Results:

  Open Ports:
   - Port 80: HTTP
   - Port 443: HTTPS

[✔] Scan completed.
```
