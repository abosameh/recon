#!/bin/bash

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NORMAL="\e[0m"

# Get the actual user who ran sudo
REAL_USER=$(logname || who am i | awk '{print $1}')
REAL_HOME=$(eval echo ~${REAL_USER})

# Function to check if a command exists
check_command() {
    local cmd=$1
    local name=${2:-$1}
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}[✓] $name is installed${NORMAL}"
        return 0
    else
        echo -e "${RED}[✗] $name is not installed${NORMAL}"
        return 1
    fi
}

# Function to check if a Python package is installed
check_python_package() {
    local package=$1
    if pip3 list | grep -q "^$package "; then
        echo -e "${GREEN}[✓] Python package $package is installed${NORMAL}"
        return 0
    else
        echo -e "${RED}[✗] Python package $package is not installed${NORMAL}"
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
        return 1
    fi
}

echo -e "${YELLOW}Checking installed tools...${NORMAL}\n"

# Check basic requirements
echo -e "${YELLOW}Basic Requirements:${NORMAL}"
check_command git
check_command python3
check_command pip3
check_command go
check_command wget
check_command curl
check_command ruby
check_command gem
check_command nmap
check_command whois
check_command dig "dnsutils"
check_command jq

# Check Go tools
echo -e "\n${YELLOW}Go Tools:${NORMAL}"
check_command subfinder
check_command assetfinder
check_command anew
check_command waybackurls
check_command gf
check_command httpx
check_command httpx-toolkit
check_command nuclei
check_command naabu
check_command dnsx
check_command gau
check_command ffuf
check_command crlfuzz
check_command dalfox
check_command gospider
check_command hakrawler
check_command gxss
check_command goop
check_command urldedupe
check_command airixss
check_command freq
check_command emailfinder
check_command TInjA
check_command pphack

# Check Python tools and packages
echo -e "\n${YELLOW}Python Tools and Packages:${NORMAL}"
check_python_package bs4
check_python_package requests
check_python_package dnspython
check_python_package argparse
check_python_package termcolor
check_python_package colorama
check_python_package tqdm
check_python_package "porch-pirate"
check_python_package tinja
check_python_package dnsgen

# Check other tools
echo -e "\n${YELLOW}Other Tools:${NORMAL}"
check_command findomain
check_command amass
check_command wpscan

# Check important directories
echo -e "\n${YELLOW}Important Directories:${NORMAL}"
check_directory $REAL_HOME/tools "Tools directory"
check_directory $REAL_HOME/tools/Sublist3r "Sublist3r"
check_directory $REAL_HOME/tools/SecretFinder "SecretFinder"
check_directory $REAL_HOME/tools/sqlmap "SQLMap"
check_directory $REAL_HOME/tools/commix "Commix"
check_directory $REAL_HOME/tools/SQLiDetector "SQLiDetector"
check_directory $REAL_HOME/tools/SwaggerSpy "SwaggerSpy"
check_directory $REAL_HOME/.gf "GF patterns directory"
check_directory /root/Desktop/work "Work directory"
check_directory /root/tools/sec/Fuzzing/XSS "XSS directory"
check_directory /root/tools/sec/Discovery/Web-Content "Web-Content directory"

# Check wordlists
echo -e "\n${YELLOW}Wordlists:${NORMAL}"
check_directory $REAL_HOME/tools/wordlists "Wordlists directory"
if [ -f $REAL_HOME/tools/wordlists/dns_wordlist.txt ]; then
    echo -e "${GREEN}[✓] DNS wordlist exists${NORMAL}"
else
    echo -e "${RED}[✗] DNS wordlist is missing${NORMAL}"
fi
if [ -f $REAL_HOME/tools/wordlists/common.txt ]; then
    echo -e "${GREEN}[✓] Common wordlist exists${NORMAL}"
else
    echo -e "${RED}[✗] Common wordlist is missing${NORMAL}"
fi

# Check OpenRedireX installation
if [ -f $REAL_HOME/tools/openredirex/openredirex.py ]; then
    echo -e "${GREEN}[✓] OpenRedireX is installed${NORMAL}"
else
    echo -e "${RED}[✗] OpenRedireX is not installed${NORMAL}"
fi

# Check SwaggerSpy installation
if [ -f /usr/local/bin/swaggerspy ]; then
    echo -e "${GREEN}[✓] SwaggerSpy is installed${NORMAL}"
else
    echo -e "${RED}[✗] SwaggerSpy is not installed${NORMAL}"
fi

# Check SQLiDetector installation
if [ -f /usr/local/bin/sqlidetector ]; then
    echo -e "${GREEN}[✓] SQLiDetector is installed${NORMAL}"
else
    echo -e "${RED}[✗] SQLiDetector is not installed${NORMAL}"
fi

echo -e "\n${YELLOW}Note: Some tools might be installed but not in PATH or might need configuration.${NORMAL}"
echo -e "${YELLOW}Please check the tool-specific documentation if you see any missing tools.${NORMAL}" 