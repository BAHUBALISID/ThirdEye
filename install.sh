#!/bin/bash
# install.sh - Installation script for ThirdEye

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               ThirdEye Installation Script                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 is not installed!"
    echo "[+] Installing Python3..."
    # Detect OS and install Python3
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update
        sudo apt-get install python3 python3-pip -y
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install python3
    else
        echo "[-] Please install Python3 manually from python.org"
        exit 1
    fi
fi

echo "[+] Python3 version: $(python3 --version)"

# Upgrade pip
echo "[+] Upgrading pip..."
python3 -m pip install --upgrade pip

# Install requirements
echo "[+] Installing requirements..."
python3 -m pip install -r requirements.txt

# Make the script executable
if [ -f "thirdeye.py" ]; then
    chmod +x thirdeye.py
    echo "[+] Made thirdeye.py executable"
fi

# Create symbolic link in /usr/local/bin (optional)
read -p "[?] Create symlink in /usr/local/bin for global access? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "thirdeye.py" ]; then
        sudo ln -sf "$PWD/thirdeye.py" /usr/local/bin/thirdeye
        echo "[+] Created symlink: /usr/local/bin/thirdeye"
        echo "[+] You can now run 'thirdeye' from anywhere!"
    fi
fi

# Check for missing tools
echo "[+] Checking for required tools..."
if ! command -v xnldorker &> /dev/null; then
    echo "[!] xnldorker is not installed. Attempting to install..."
    python3 -m pip install xnldorker
fi

# Verify installation
echo "[+] Verifying installation..."
python3 -c "import tldextract, argparse, requests, colorama; print('[✓] All core dependencies installed')" 2>/dev/null || echo "[-] Some dependencies missing"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Installation Complete!                     ║"
echo "║                                                              ║"
echo "║  Usage: ./thirdeye.py -d example.com                         ║"
echo "║  Or:     thirdeye -d example.com (if symlink created)       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
