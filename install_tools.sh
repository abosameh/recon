#!/bin/bash

# Colors
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NORMAL="\e[0m"
BLUE="\033[0;34m"

# Get the actual user who ran sudo
REAL_USER=$(logname || who am i | awk '{print $1}')
REAL_HOME=$(eval echo ~${REAL_USER})

# Function to run command as real user
run_as_user() {
    sudo -u ${REAL_USER} "$@"
}

# Function to check if a command exists
check_command() {
    local cmd=$1
    local name=${2:-$1}
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}[✓] $name is installed${NORMAL}"
        return 0
    else
        echo -e "${RED}[✗] $name is not installed${NORMAL}"
        echo -e "${BLUE}[*] Installing $name...${NORMAL}"
        return 1
    fi
}

# Function to check if a Python package is installed
check_python_package() {
    local package=$1
    # Ensure virtual environment exists
    setup_venv
    if $REAL_HOME/tools/venv/bin/pip3 list | grep -q "^$package "; then
        echo -e "${GREEN}[✓] Python package $package is installed${NORMAL}"
        return 0
    else
        echo -e "${RED}[✗] Python package $package is not installed${NORMAL}"
        echo -e "${BLUE}[*] Installing Python package $package...${NORMAL}"
        $REAL_HOME/tools/venv/bin/pip3 install $package
        return 1
    fi
}

# Function to check if a directory exists
check_directory() {
    local dir=$1
    local name=${2:-$1}
    if [ -d "$dir" ]; then
        echo -e "${GREEN}[✓] Directory $name exists${NORMAL}"
        return 0
    else
        echo -e "${RED}[✗] Directory $name does not exist${NORMAL}"
        echo -e "${BLUE}[*] Creating directory $name...${NORMAL}"
        mkdir -p "$dir"
        return 1
    fi
}

# Function to ensure virtual environment is active and use its pip
use_venv() {
    # Ensure correct permissions before using venv
    chown -R ${REAL_USER}:${REAL_USER} "$REAL_HOME/tools/venv"
    source $REAL_HOME/tools/venv/bin/activate
    $REAL_HOME/tools/venv/bin/pip3 "$@"
}

# Create and setup virtual environment if it doesn't exist
setup_venv() {
    if [ ! -d "$REAL_HOME/tools/venv" ]; then
        echo -e "${YELLOW}Setting up Python virtual environment...${NORMAL}"
        apt-get install -y python3-venv python3-pip
        # Create venv directory with correct permissions
        mkdir -p "$REAL_HOME/tools/venv"
        chown -R ${REAL_USER}:${REAL_USER} "$REAL_HOME/tools/venv"
        # Create venv as the real user
        run_as_user python3 -m venv "$REAL_HOME/tools/venv"
        # Ensure all venv files have correct ownership
        chown -R ${REAL_USER}:${REAL_USER} "$REAL_HOME/tools/venv"
        source $REAL_HOME/tools/venv/bin/activate
        $REAL_HOME/tools/venv/bin/pip3 install --upgrade pip
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NORMAL}"
    exit
fi

echo -e "${GREEN}Starting tools installation...${NORMAL}"

# Check and create tools directory
check_directory $REAL_HOME/tools "Tools directory"
cd $REAL_HOME/tools

# Setup virtual environment
setup_venv

# Check and install basic requirements
echo -e "\n${YELLOW}Checking and installing basic requirements...${NORMAL}"
if ! check_command git || ! check_command python3 || ! check_command pip3 || ! check_command go || ! check_command wget || ! check_command curl || ! check_command ruby || ! check_command gem || ! check_command nmap || ! check_command whois || ! check_command jq; then
    echo -e "${BLUE}Installing basic requirements...${NORMAL}"
    apt-get update
    apt-get install -y git python3 python3-pip golang wget curl ruby rubygems nmap whois dnsutils jq lolcat 

    # Ensure virtual environment is setup
    setup_venv
fi

# Check and install Python packages
echo -e "\n${YELLOW}Checking and installing Python packages...${NORMAL}"
python_packages=(
    "tldextract"
    "bs4"
    "requests"
    "dnspython"
    "argparse"
    "termcolor"
    "colorama"
    "tqdm"
    "porch-pirate"
    "dnsgen"
    "urllib3"
)

for package in "${python_packages[@]}"; do
    echo -e "${BLUE}Installing $package...${NORMAL}"
    use_venv install $package
done

# Install Go tools
echo -e "\n${YELLOW}Checking and installing Go tools...${NORMAL}"
go_tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/KathanP19/Gxss@latest"
    "github.com/deletescape/goop@latest"
    "github.com/dubs3c/urldedupe@latest"
    "github.com/ferreiraklet/airixss@latest"
    "github.com/takshal/freq@latest"
    "github.com/rix4uni/emailfinder@latest"
    "github.com/Hackmanit/TInjA@latest"
    "github.com/edoardottt/pphack/cmd/pphack@latest"
)

for tool in "${go_tools[@]}"; do
    name=$(basename $(echo $tool | cut -d@ -f1))
    if ! check_command $name; then
        go install -v $tool
    fi
done

# Move Go tools to /usr/local/bin
echo -e "${BLUE}Moving Go tools to /usr/local/bin...${NORMAL}"
cp ~/go/bin/* /usr/local/bin/ 2>/dev/null

# Check and install Findomain
echo -e "\n${YELLOW}Checking and installing Findomain...${NORMAL}"
if ! check_command findomain; then
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
    chmod +x findomain-linux
    mv findomain-linux /usr/local/bin/findomain
fi

# Check and install Amass
echo -e "\n${YELLOW}Checking and installing Amass...${NORMAL}"
if ! check_command amass; then
    snap install amass
fi

# Check and install other tools
echo -e "\n${YELLOW}Checking and installing other tools...${NORMAL}"
if ! check_directory $REAL_HOME/tools/Sublist3r "Sublist3r"; then
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r
    use_venv install -r requirements.txt
    cd ..
fi

if ! check_directory $REAL_HOME/tools/SecretFinder "SecretFinder"; then
    git clone https://github.com/m4ll0k/SecretFinder.git
    cd SecretFinder
    use_venv install -r requirements.txt
    cd ..
fi

if ! check_directory $REAL_HOME/tools/sqlmap "SQLMap"; then
    git clone https://github.com/sqlmapproject/sqlmap.git
fi

if ! check_directory $REAL_HOME/tools/commix "Commix"; then
    git clone https://github.com/commixproject/commix.git
fi

# Install SQLiDetector
echo -e "\n${YELLOW}Checking and installing SQLiDetector...${NORMAL}"
if ! check_directory $REAL_HOME/tools/SQLiDetector "SQLiDetector"; then
    cd $REAL_HOME/tools
    git clone https://github.com/abosameh/SQLiDetector.git
    cd SQLiDetector
    use_venv install -r requirements.txt
    chmod +x sqlidetector.py
    ln -sf $(pwd)/sqlidetector.py /usr/local/bin/sqlidetector
    cd ..
fi

# Install SwaggerSpy
echo -e "\n${YELLOW}Checking and installing SwaggerSpy...${NORMAL}"
if ! check_directory $REAL_HOME/tools/SwaggerSpy "SwaggerSpy"; then
    cd $REAL_HOME/tools
    git clone https://github.com/UndeadSec/swaggerspy.git SwaggerSpy
    cd SwaggerSpy
    # Install urllib3 first to avoid dependency issues
    use_venv install urllib3
    use_venv install -r requirements.txt
    chmod +x swaggerspy.py
    ln -sf $(pwd)/swaggerspy.py /usr/local/bin/swaggerspy
    cd ..
fi

# Check and install WPScan
echo -e "\n${YELLOW}Checking and installing WPScan...${NORMAL}"
if ! check_command wpscan; then
    gem install wpscan
fi

# Check and setup GF patterns
echo -e "\n${YELLOW}Checking and setting up GF patterns...${NORMAL}"
if ! check_directory ~/.gf "GF patterns directory"; then
    git clone https://github.com/1ndianl33t/Gf-Patterns
    mv Gf-Patterns/*.json ~/.gf/
fi

# Check and create necessary directories
echo -e "\n${YELLOW}Checking and creating necessary directories...${NORMAL}"
check_directory $REAL_HOME/Desktop/work "Work directory"
check_directory $REAL_HOME/tools/sec/Fuzzing/XSS "XSS directory"
check_directory $REAL_HOME/tools/sec/Discovery/Web-Content "Web-Content directory"

# Check and download wordlists
echo -e "\n${YELLOW}Checking and downloading wordlists...${NORMAL}"
check_directory $REAL_HOME/tools/wordlists "Wordlists directory"
cd $REAL_HOME/tools/wordlists

if [ ! -f dns_wordlist.txt ]; then
    echo -e "${BLUE}Downloading DNS wordlist...${NORMAL}"
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt -O dns_wordlist.txt
fi

if [ ! -f common.txt ]; then
    echo -e "${BLUE}Downloading common wordlist...${NORMAL}"
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
fi

echo -e "\n${GREEN}Installation and checks completed!${NORMAL}"
echo -e "${YELLOW}Please make sure to configure API keys for tools that require them.${NORMAL}"
echo -e "${YELLOW}Some tools might need manual configuration or additional setup.${NORMAL}"

# Final verification
echo -e "\n${YELLOW}Running final verification...${NORMAL}"
# Assuming check_tools.sh is in the same directory as install_tools.sh
"$(dirname "$0")/check_tools.sh"

echo -e "\n${YELLOW}Creating activation script...${NORMAL}"
cat > $REAL_HOME/tools/activate_venv.sh << EOF
#!/bin/bash
source $REAL_HOME/tools/venv/bin/activate
EOF
chmod +x $REAL_HOME/tools/activate_venv.sh
chown ${REAL_USER}:${REAL_USER} $REAL_HOME/tools/activate_venv.sh

echo -e "\n${GREEN}Setup complete! Please review any errors above if present.${NORMAL}"

# Add this after the basic requirements installation
echo -e "\n${YELLOW}Installing httpx-toolkit...${NORMAL}"
if ! check_command httpx-toolkit; then
    apt-get install -y httpx-toolkit
fi

# Install OpenRedireX
echo -e "\n${YELLOW}Checking and installing OpenRedireX...${NORMAL}"
if ! check_directory $REAL_HOME/tools/openredirex "OpenRedireX"; then
    cd $REAL_HOME/tools
    git clone https://github.com/devanshbatham/openredirex
    cd openredirex
    chmod +x setup.sh
    ./setup.sh
    cd ..
fi

echo -e "\n${YELLOW}Fixing permissions...${NORMAL}"
chown -R ${REAL_USER}:${REAL_USER} $REAL_HOME/tools 

# Check and install dalfox
echo -e "\n${YELLOW}Checking and installing dalfox...${NORMAL}"
if ! check_command dalfox; then
    snap install dalfox
fi 
