#!/bin/sh

# Colors
yellow='\033[1;33m'
green='\033[0;32m'
red='\033[0;31m'
nocolor='\033[0m'
bold='\033[1m'

clear

# Detect package manager
if command -v apt >/dev/null 2>&1; then
    INSTALLER="sudo apt install -y"
elif command -v pacman >/dev/null 2>&1; then
    INSTALLER="sudo pacman -S --noconfirm"
elif command -v yay >/dev/null 2>&1; then
    INSTALLER="yay -S --noconfirm"
elif command -v dnf >/dev/null 2>&1; then
    INSTALLER="sudo dnf install -y"
elif command -v zypper >/dev/null 2>&1; then
    INSTALLER="sudo zypper install -y"
else
    echo "${red}Unsupported distro or package manager not found.${nocolor}"
    exit 1
fi

# Ensure figlet is installed
if ! command -v figlet >/dev/null 2>&1; then
    printf "${green}Installing figlet...\n"
    $INSTALLER figlet >/dev/null 2>&1
    clear
fi

# Title
printf "${yellow}*******************************************************\n"
figlet "CTF Toolskit"
printf "${yellow}*******************************************************\n${nocolor}"
printf "${red}Developed by Bishal Poudel\n\n${nocolor}"

# Header
printf "${yellow}------------------------------------------------------------\n"
printf "${bold}${green}Available Tools in CTF Toolskit:${nocolor}\n"
printf "${yellow}------------------------------------------------------------\n${nocolor}"

# Tool names for installation
TOOL_NAMES=(
"nmap" "netcat" "sqlmap" "hydra" "john" "hashcat" "gobuster" "dirb" "wfuzz" "nikto"
"burpsuite" "zap" "wireshark" "tshark" "tcpdump" "enum4linux" "smbclient" "rpcclient" "nbtscan" "theHarvester"
"amass" "dnsenum" "dnsrecon" "sublist3r" "fierce" "sslscan" "openssl" "metasploit" "searchsploit" "exploitdb"
"linpeas" "winpeas" "ltrace" "strace" "gdb" "radare2" "ghidra" "binwalk" "strings" "objdump"
"xxd" "stegsolve" "steghide" "exiftool" "zsteg" "pngcheck" "pdf-parser" "base64" "cyberchef" "socat"
)

# Display names in columns
left_column=(
"1.  nmap         - Port scanning"
"2.  netcat       - Network utility"
"3.  sqlmap       - SQLi automation"
"4.  hydra        - Brute-forcer"
"5.  john         - Hash cracker"
"6.  hashcat      - GPU cracker"
"7.  gobuster     - Dir bruteforce"
"8.  dirb         - Web scanner"
"9.  wfuzz        - Web bruteforce"
"10. nikto        - Web vuln scan"
"11. burpsuite    - Web testing"
"12. zap          - ZAP scanner"
"13. wireshark    - Traffic GUI"
"14. tshark       - CLI traffic"
"15. tcpdump      - Packet sniff"
"16. enum4linux   - SMB enum"
"17. smbclient    - SMB connect"
"18. rpcclient    - Win info"
"19. nbtscan      - NetBIOS scan"
"20. theHarvester - Info gather"
"21. amass        - Subdomains"
"22. dnsenum      - DNS enum"
"23. dnsrecon     - DNS scanner"
"24. sublist3r    - Subdomain enum"
"25. fierce       - DNS recon"
)

right_column=(
"26. sslscan      - SSL scanner"
"27. openssl      - Crypto utils"
"28. metasploit   - Exploits"
"29. searchsploit - ExploitDB CLI"
"30. exploitdb    - Public exploits"
"31. linpeas      - Linux priv esc"
"32. winpeas      - Windows priv esc"
"33. ltrace       - Library trace"
"34. strace       - Syscall trace"
"35. gdb          - Debugger"
"36. radare2      - RE toolkit"
"37. ghidra       - NSA RE GUI"
"38. binwalk      - Firmware RE"
"39. strings      - Extract text"
"40. objdump      - Binary inspect"
"41. xxd          - Hex dump"
"42. stegsolve    - Stego GUI"
"43. steghide     - Stego tool"
"44. exiftool     - Metadata read"
"45. zsteg        - PNG stego detect"
"46. pngcheck     - PNG analysis"
"47. pdf-parser   - PDF analyzer"
"48. base64       - Encoding tool"
"49. cyberchef    - Data analyzer"
"50. socat        - Net tool"
)

# Print tools in two columns
for i in $(seq 0 24); do
    printf "%-40s  %s\n" "${left_column[$i]}" "${right_column[$i]}"
done

printf "\n${yellow}0 For All Tools \t 100 to Exit${nocolor}\n"

# Menu loop
while true; do
    printf "${green}Enter a number to install the tool: ${nocolor}"
    read -r choice

    if [ "$choice" = "100" ]; then
        printf "${yellow}Exiting...${nocolor}\n"
        exit 0
    elif [ "$choice" = "0" ]; then
        for tool in "${TOOL_NAMES[@]}"; do
            echo "Installing $tool..."
            $INSTALLER "$tool" >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "${green}$tool installed successfully.${nocolor}"
            else
                echo -e "${red}Failed to install $tool.${nocolor}"
            fi
        done
        echo "All tools attempted to install."
        exit 0
    elif [ "$choice" -ge 1 ] && [ "$choice" -le 50 ]; then
        tool_name="${TOOL_NAMES[$((choice - 1))]}"
        echo "Installing $tool_name..."
        $INSTALLER "$tool_name" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${green}$tool_name installed successfully.${nocolor}"
        else
            echo -e "${red}Failed to install $tool_name.${nocolor}"
        fi
    else
        printf "${red}Invalid input. Choose between 1-50, 0 for all, or 100 to exit.${nocolor}\n"
    fi
done
