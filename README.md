# CTF Toolkit Installer

A simple, interactive shell script for installing a comprehensive set of tools used in Capture The Flag (CTF), ethical hacking, and penetration testing. The script auto-detects the user's Linux package manager and provides a menu-driven interface for individual or bulk installation of 50 essential security tools.

---

## ✨ Features

- 🔍 Auto-detects supported package managers: `apt`, `pacman`, `yay`, `dnf`, and `zypper`
- 📦 Installs 50 widely-used CTF and pentesting tools
- 📜 Displays tools in a clean two-column interface with descriptions
- 🎯 Menu-driven selection: install one, all, or exit
- 🎨 Color-coded output for clear status indication (success/failure)
- ⚡ Lightweight and fast CLI experience

---

## 🛠️ Tools Included

Includes but not limited to:
- **Recon**: `nmap`, `theHarvester`, `amass`, `dnsenum`, `sublist3r`
- **Web**: `wfuzz`, `gobuster`, `nikto`, `burpsuite`, `zap`
- **Crypto & Exploits**: `sqlmap`, `hydra`, `john`, `hashcat`, `metasploit`
- **Steganography**: `stegsolve`, `steghide`, `zsteg`, `exiftool`
- **Reverse Engineering**: `gdb`, `radare2`, `ghidra`, `binwalk`
- **Networking**: `netcat`, `wireshark`, `tshark`, `tcpdump`, `socat`

Full list available in the script menu.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/bishalpoudel-1/ctftoolkit.git
cd ctftoolkit
chmod +x ctftoolkit.sh
./ctftoolkit.sh
```
## Script run image
![image](https://github.com/user-attachments/assets/bbea9bc2-8a30-4c2b-b34c-28cdb101f75d)
