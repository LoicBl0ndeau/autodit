# Autodit

**Autodit** (Automated Audit) is a lightweight Python3 auditing tool developed by **Loïc Blondeau**. It analyzes Nmap XML scan results, identify exposed services (FTP, HTTP, HTTPS, SMB and alternative ports), check for anonymous FTP login, and optionally brute-force web login forms using Selenium and a custom wordlist.

---

## 🚀 Key Features

- 🔎 **Nmap XML Parser** – Parses Nmap scans and extracts open ports per host.
- 🧬 **FTP Access Checker** – Detects anonymous FTP login with read/write access.
- 🌐 **Web App Form Scanner** – Analyzes login forms using Selenium.
- 🧪 **Credential Brute-Forcing** – Uses a custom wordlist to test credentials.
- 📋 **Smart Reporting** – Summarizes findings and highlights priority targets.
- 🧠 **Protocol Awareness** – Identifies HTTP/HTTPS services and other common web ports.
- 🔐 **SMB Flagging** – Marks hosts with open SMB ports for deeper analysis.

---

## 🛠️ Requirements

* Python 3+
* Google Chrome installed (for Selenium)
* Required Python packages:
```bash
pip install -r requirements.txt
```

---

## 🧪 Example Usage

```bash
python3 autodit.py --xml nmap_output.xml [--wordlist wordlist.txt] [--agent "CustomUserAgent/1.0"]
```

### Required:

* `--xml`: Path to your Nmap XML output.

### Optional:

* `--wordlist`: Path to a custom wordlist for brute-force testing.
* `--agent`: User-Agent string to be used in HTTP requests (default: `Mozilla/5.0`).

---

## 📦 Wordlist Format

The `wordlist.txt` should follow this structure:

```
Username1
Password1

Username2
Password2

Username3
Password3
```

Each login-password pair must be separated by two newlines.

---

## 🔒 Ethical Use

This tool is intended **strictly for authorized auditing and penetration testing** in **controlled environments** such as:

* Internal corporate networks
* Capture The Flag (CTF) challenges
* Security research labs

**Do not** use this tool on unauthorized networks or systems. Always ensure you have permission.

---

## 📌 Notes

* ℹ️ The script uses --headless mode by default for browser automation — disable it if you want to watch browser actions.

---

## 🧾 Output Example

```
[*] Nmap XML well parsed
[*] User-Agent: Mozilla/5.0
[*] Wordlist: creds.txt

[+] Anonymous READ/WRITE on 10.10.10.5 - Welcome to FTP Server
[+] Login found on http://10.10.10.5 : admin / admin123

[*] Interesting alternative opened ports (try https if no results):
10.10.10.5:8080

[*] IP addresses with port 445 opened:
10.10.10.7 10.10.10.9
```