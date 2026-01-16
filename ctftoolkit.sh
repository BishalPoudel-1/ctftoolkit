#!/bin/bash

# Colors
yellow='\033[1;33m'
green='\033[0;32m'
red='\033[0;31m'
blue='\033[1;34m'
nocolor='\033[0m'
bold='\033[1m'

clear

# --- 1. Distro Detection & PackageManager Configuration ---
PKG_MANAGER=""
INSTALLER=""
DISTRO_ID=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID=$ID
fi

if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    INSTALLER="sudo apt install -y"
elif command -v yay >/dev/null 2>&1; then
    PKG_MANAGER="yay"
    INSTALLER="yay -S --noconfirm"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    INSTALLER="sudo pacman -S --noconfirm"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    INSTALLER="sudo dnf install -y"
else
    echo "${red}Unsupported distribution or package manager not found.${nocolor}"
    exit 1
fi

echo -e "${blue}Detected Distro: $DISTRO_ID using $PKG_MANAGER${nocolor}"

# --- 2. Package Mapping Function ---
function get_pkg_name() {
    local tool=$1
    local pkg_name=$tool

    # Mappings for common mismatches
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        case "$tool" in
            "netcat") pkg_name="netcat-openbsd" ;;
            "metasploit") pkg_name="metasploit-framework" ;;
            "burpsuite") pkg_name="burpsuite" ;;
            "apktool") pkg_name="apktool" ;;
            "adb") pkg_name="adb" ;;
            "scrcpy") pkg_name="scrcpy" ;;
            "jadx") pkg_name="jadx" ;;
            "hashcat") pkg_name="hashcat" ;;
            "john") pkg_name="john" ;;
            "nmap") pkg_name="nmap" ;;
            "wireshark") pkg_name="wireshark" ;;
            "sqlmap") pkg_name="sqlmap" ;;
            "hydra") pkg_name="hydra" ;;
            "gobuster") pkg_name="gobuster" ;;
            "wfuzz") pkg_name="wfuzz" ;;
            "nikto") pkg_name="nikto" ;;
            "seclists") pkg_name="seclists" ;;
            "feroxbuster") pkg_name="feroxbuster" ;; # May need manual on older debs
            "ffuf") pkg_name="ffuf" ;;
            "traceroute") pkg_name="traceroute" ;;
            "whois") pkg_name="whois" ;;
            "bind-utils") pkg_name="dnsutils" ;; # dig/nslookup
             # Many others are standard or manual
        esac
    elif [[ "$PKG_MANAGER" == "pacman" || "$PKG_MANAGER" == "yay" ]]; then
        case "$tool" in
            "netcat") pkg_name="gnu-netcat" ;;
            "metasploit") pkg_name="metasploit" ;;
            "burpsuite") pkg_name="burpsuite" ;;
            "zap") pkg_name="zaproxy" ;;
            "apktool") pkg_name="android-apktool" ;;
            "adb") pkg_name="android-tools" ;;
            "scrcpy") pkg_name="scrcpy" ;;
            "bind-utils") pkg_name="bind" ;;
        esac
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        case "$tool" in
            "netcat") pkg_name="nmap-ncat" ;;
            "metasploit") pkg_name="metasploit-framework" ;;
            "apktool") pkg_name="apktool" ;;
            "adb") pkg_name="android-tools" ;;
            "bind-utils") pkg_name="bind-utils" ;;
        esac
    fi
    echo "$pkg_name"
}

# --- 3. Helper Functions ---
function check_pip() {
    if ! command -v pip3 >/dev/null 2>&1; then
        echo -e "${yellow}pip3 NOT found. Attempting to install...${nocolor}"
        $INSTALLER python3-pip >/dev/null 2>&1
    fi
}

function check_go() {
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${yellow}Go NOT found. Attempting to install...${nocolor}"
        $INSTALLER golang >/dev/null 2>&1
    fi
}

# --- 4. Manual Installation Function ---
function install_manual() {
    local tool=$1
    echo -e "${yellow}Attempting manual install or download for $tool...${nocolor}"
    
    mkdir -p ~/ctf-tools
    cd ~/ctf-tools || return

    case "$tool" in
        "linpeas")
            wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
            chmod +x linpeas.sh
            echo -e "${green}LinPEAS downloaded to ~/ctf-tools/linpeas.sh${nocolor}"
            ;;
        "winpeas")
             wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -O winPEASx64.exe
             echo -e "${green}WinPEAS downloaded to ~/ctf-tools/winPEASx64.exe${nocolor}"
             ;;
        "sublist3r")
            if [ -d "Sublist3r" ]; then echo "Sublist3r already present."; else
                git clone https://github.com/aboul3la/Sublist3r.git
                check_pip
                pip3 install -r Sublist3r/requirements.txt
                echo -e "${green}Sublist3r cloned to ~/ctf-tools/Sublist3r${nocolor}"
            fi
            ;;
        "stegsolve")
             wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
             chmod +x stegsolve.jar
             echo -e "${green}Stegsolve downloaded to ~/ctf-tools/stegsolve.jar${nocolor}"
             ;;
        "impacket-scripts")
             check_pip
             pip3 install --user impacket
             echo -e "${green}Impacket installed via pip.${nocolor}"
             ;;
        "frida-tools"|"objection"|"drozer"|"androguard"|"apkleaks"|"pwncat"|"becreepy"|"uncompyle6"|"decompyle3"|"ropper"|"arjun"|"commix")
             check_pip
             echo "Installing $tool via pip..."
             pip3 install --user "$tool"
             ;;
        "httprobe"|"subfinder"|"feroxbuster"|"amass"|"assetfinder")
            # Try apt/repo first, if not try go
             check_go
             echo "Installing $tool via Go..."
             # Go install paths vary by version, simplistic approach:
             if [[ "$tool" == "httprobe" ]]; then go install github.com/tomnomnom/httprobe@latest; fi
             if [[ "$tool" == "subfinder" ]]; then go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; fi
             if [[ "$tool" == "assetfinder" ]]; then go install github.com/tomnomnom/assetfinder@latest; fi
             if [[ "$tool" == "feroxbuster" ]]; then 
                 # Often cargo, but let's try just downloading binary for speed/reliability if go fails or isn't target
                 curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
             fi
             ;;
        "volatility")
            # Volatility 3
            if [ -d "volatility3" ]; then echo "Volatility3 already present."; else
                git clone https://github.com/volatilityfoundation/volatility3.git
                check_pip
                pip3 install -r volatility3/requirements.txt
                echo -e "${green}Volatility3 cloned.${nocolor}"
            fi
            ;;
        "sherlock")
             if [ -d "sherlock" ]; then echo "Sherlock already present."; else
                 git clone https://github.com/sherlock-project/sherlock.git
                 check_pip
                 pip3 install -r sherlock/requirements.txt
                 echo -e "${green}Sherlock cloned.${nocolor}"
             fi
             ;;
        "photon")
             if [ -d "Photon" ]; then echo "Photon already present."; else
                 git clone https://github.com/s0md3v/Photon.git
                 check_pip
                 pip3 install -r Photon/requirements.txt
                 echo -e "${green}Photon cloned.${nocolor}"
             fi
             ;;
        "gitleaks")
             # Binary download is safest
             echo "Downloading gitleaks binary..."
             wget https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
             tar -xzf gitleaks_linux_x64.tar.gz
             sudo mv gitleaks /usr/local/bin/
             rm gitleaks_linux_x64.tar.gz
             ;;
         *)
            echo -e "${red}No manual installation method defined for $tool.${nocolor}"
            return 1
            ;;
    esac
}

# --- 5. Main Installation Function ---
function install_tool() {
    local tool_generic=$1
    local pkg_name=$(get_pkg_name "$tool_generic")
    
    echo -e "Installing ${bold}$tool_generic${nocolor}..."

    # List of tools that are ALWAYS manual/pip/go or likely not in repo
    local manual_only=0
    case "$tool_generic" in
        "linpeas"|"winpeas"|"sublist3r"|"stegsolve"|"frida-tools"|"objection"|"drozer"|"androguard"|"apkleaks"|"pwncat"|"becreepy"|"uncompyle6"|"decompyle3"|"ropper"|"arjun"|"commix"|"impacket-scripts"|"volatility"|"sherlock"|"photon"|"gitleaks"|"httprobe"|"subfinder"|"feroxbuster"|"assetfinder") manual_only=1 ;;
    esac

    if [ $manual_only -eq 0 ]; then
        $INSTALLER "$pkg_name" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${green}$tool_generic installed successfully (via package manager).${nocolor}"
            return 0
        else
            echo -e "${yellow}Package '$pkg_name' not found in repo. Trying manual...${nocolor}"
        fi
    fi

    # Fallback/Primary manual install
    install_manual "$tool_generic"
}

# --- 6. Tool Categories ---
CATS=("1. Basic / Net" "2. Web Exploit" "3. Mobile" "4. Forensics" "5. Reverse Eng" "6. PrivEsc / Exp" "7. OSINT / Misc")

# Expanded Arrays (20+ tools each)

TOOL_CAT_1=(
"nmap" "netcat" "tcpdump" "wireshark" "tshark" "socat" "masscan" "curl" "wget" "hping3" 
"traceroute" "whois" "bind-utils" "netdiscover" "arp-scan" "iftop" "nload" "ethtool" "ssh" "telnet" "ftp"
)

TOOL_CAT_2=(
"burpsuite" "zap" "sqlmap" "gobuster" "dirb" "wfuzz" "nikto" "whatweb" "wpscan" "commix" 
"arjun" "skipfish" "feroxbuster" "ffuf" "davtest" "uniscan" "xsser" "httprobe" "subfinder" 
"scoutsuite" "nikto"
)

TOOL_CAT_3=(
"apktool" "jadx" "frida-tools" "objection" "scrcpy" "adb" "drozer" "androguard" "apkleaks" "qark" 
"dex2jar" "enjarify" "classyshark" "r2frida" "keytool" "jarsigner" "zipalign" "pidcat"
)

TOOL_CAT_4=(
"binwalk" "stegsolve" "steghide" "exiftool" "zsteg" "pngcheck" "pdf-parser" "strings" "volatility" 
"foremost" "scalpel" "bulk_extractor" "magicrescue" "recoverjpeg" "tcpflow" "pcapfix" "chkrootkit" 
"rkhunter" "clamav" "galleta" "btscanner"
)

TOOL_CAT_5=(
"gdb" "radare2" "ghidra" "ltrace" "strace" "objdump" "xxd" "edb-debugger" "ropper" "uncompyle6" 
"decompyle3" "nasm" "rappel" "checksec" "lief" "cutter"
)

TOOL_CAT_6=(
"linpeas" "winpeas" "metasploit" "searchsploit" "exploitdb" "hydra" "john" "hashcat" "impacket-scripts" 
"crackmapexec" "responder" "evil-winrm" "pwncat" "powersploit" "mimikatz" "pspy" "gtfobins" 
"becreepy" "unix-privesc-check" "shellter"
)

TOOL_CAT_7=(
"theHarvester" "amass" "sublist3r" "cyberchef" "base64" "maltego" "recon-ng" "spiderfoot" "sherlock" 
"photon" "sn1per" "metagoofil" "dnsdumpster" "gitrob" "gitleaks" "shodan" "assetfinder" "censys" 
"exifprobe" "creepy"
)

function show_banner() {
    clear
    printf "${yellow}*******************************************************\n"
    if command -v figlet >/dev/null 2>&1; then
        figlet "CTF Toolskit"
    else
        echo "CTF Toolskit"
    fi
    printf "${yellow}*******************************************************\n${nocolor}"
    printf "${red}Developed by Bishal Poudel\n\n${nocolor}"
}

function show_category_menu() {
    show_banner
    printf "${yellow}------------------------------------------------------------\n"
    printf "${bold}${green}Select a Category:${nocolor}\n"
    printf "${yellow}------------------------------------------------------------\n${nocolor}"
    for cat in "${CATS[@]}"; do
        echo "$cat"
    done
    printf "\n${yellow}0. Install ALL Tools \t 100. Exit${nocolor}\n"
}

function handle_category() {
    local cat_idx=$1
    local array_name="TOOL_CAT_$cat_idx[@]"
    local tools=("${!array_name}")
    
    if [ ${#tools[@]} -eq 0 ]; then
        echo "${red}Invalid category.${nocolor}"
        return
    fi
    
    # Show tools in category
    show_banner
    printf "${yellow}Category: ${CATS[$((cat_idx-1))]}${nocolor}\n"
    
    local i=1
    local half=$(( (${#tools[@]} + 1) / 2 ))
    
    # Simple columnar display logic for more tools
    for (( j=0; j<half; j++ )); do
        local tool1="${tools[$j]}"
        local idx2=$((j + half))
        local tool2="${tools[$idx2]}"
        
        if [ ! -z "$tool2" ]; then
             printf "%-2d. %-30s | %-2d. %s\n" $((j+1)) "$tool1" $((idx2+1)) "$tool2"
        else
             printf "%-2d. %s\n" $((j+1)) "$tool1"
        fi
    done
    
    printf "\n${yellow}0. Install ALL in this category \t 99. Back${nocolor}\n"
    
    while true; do
        printf "${green}Select tool to install: ${nocolor}"
        read -r t_choice
        
        if [ "$t_choice" = "99" ]; then
            return
        elif [ "$t_choice" = "0" ]; then
            for tool in "${tools[@]}"; do
                install_tool "$tool"
            done
            read -p "Press Enter to continue..."
            return
        elif [[ "$t_choice" =~ ^[0-9]+$ ]] && [ "$t_choice" -ge 1 ] && [ "$t_choice" -le ${#tools[@]} ]; then
             local selected_tool="${tools[$((t_choice-1))]}"
             install_tool "$selected_tool"
             read -p "Press Enter to continue..."
        else
             echo "${red}Invalid selection.${nocolor}"
        fi
    done
}

# Ensure figlet
if ! command -v figlet >/dev/null 2>&1; then
    install_tool "figlet" >/dev/null 2>&1
fi

# Main Loop
while true; do
    show_category_menu
    printf "${green}Enter your choice: ${nocolor}"
    read -r choice
    
    if [ "$choice" = "100" ]; then
        echo "Exiting..."
        exit 0
    elif [ "$choice" = "0" ]; then
        # Install ALL
        for i in {1..7}; do
             local array_name="TOOL_CAT_$i[@]"
             local tools=("${!array_name}")
             for tool in "${tools[@]}"; do
                 install_tool "$tool"
             done
        done
        echo "All tools installed."
        exit 0
    elif [[ "$choice" =~ ^[1-7]$ ]]; then
        handle_category "$choice"
    else
        echo "${red}Invalid choice.${nocolor}"
        sleep 1
    fi
done
