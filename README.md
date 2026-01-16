# 🧰 CTF Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

**CTF Toolkit** is a comprehensive, automated installer and organizer for Capture The Flag (CTF) and penetration testing tools. Designed to save time and effort, it automatically detects your Linux distribution and package manager to install over 100 essential tools across multiple categories.

Whether you are a beginner setting up your first CTF lab or a pro needing a quick environment rebuild, CTF Toolkit has you covered.

## ✨ Features

-   **🐧 Multi-Distro Support**: Automatically detects and adapts to:
    -   Debian / Ubuntu / Kali / Parrot (`apt`)
    -   Arch Linux / Manjaro / BlackArch (`pacman`, `yay`)
    -   Fedora (`dnf`)
-   **📦 Smart Installation**: Attempts to install via the native package manager first. If unavailable, it falls back to manual installation scripts (pip, go, git clone, wget, etc.).
-   **📂 Organized Categories**: Tools are grouped into 7 logical categories for easy navigation.
-   **🚀 Extensive Tool Collection**: Includes pre-configured installers for over 100 popular tools.

## 🛠️ Tool Categories

The toolkit organizes tools into the following categories:

1.  **Connectivity & Network**: `nmap`, `wireshark`, `tcpdump`, `masscan`, `socat`, etc.
2.  **Web Exploitation**: `burpsuite`, `sqlmap`, `gobuster`, `ffuf`, `nikto`, `wpscan`, etc.
3.  **Mobile Assessment**: `adb`, `scrcpy`, `apktool`, `frida-tools`, `jadx`, `objection`, etc.
4.  **Forensics**: `volatility`, `binwalk`, `exiftool`, `steghide`, `sleuthkit`, etc.
5.  **Reverse Engineering**: `ghidra`, `radare2`, `gdb`, `ltrace`, `strace`, etc.
6.  **Privilege Escalation**: `linpeas`, `winpeas`, `metasploit`, `mimikatz`, `searchsploit`, etc.
7.  **OSINT & Misc**: `sherlock`, `theHarvester`, `shodan`, `cyberchef`, `gitleaks`, etc.

## 🚀 Installation & Usage

### Prerequisites
- A Linux-based operating system.
- `git` installed (usually present, or install via `sudo apt install git` / `sudo pacman -S git`).
- Root/Sudo privileges are required for installing packages.

### Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/ctftoolkit.git
    cd ctftoolkit
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x ctftoolkit.sh
    ```

3.  **Run the toolkit:**
    ```bash
    ./ctftoolkit.sh
    ```

### Interactive Menu
Once launched, you will see a menu listing the tool categories.
-   Select a number **(1-7)** to view tools in that category.
-   Inside a category, select a specific tool to install, or choose **0** to install **ALL** tools in that category.
-   From the main menu, choose **0** to install **EVERYTHING** (grab a coffee ☕, this takes a while!).

## 🤝 Contributing

Contributions are welcome! If you find a bug, a missing tool, or have a better installation method for a specific distro:
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/amazing-tool`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## ⚠️ Disclaimer

This script is for **educational purposes and legal security assessments only**. The author is not responsible for any misuse of the tools installed by this script. Always ensure you have permission to test the networks and systems you target.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Developed by Bishal Poudel*
