#!/bin/bash
# Installation script for Phase 1 security tools (WhatWeb and Nikto)

set -e

echo "========================================="
echo "Phase 1 Security Tools Installation"
echo "Installing WhatWeb and Nikto"
echo "========================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS ($DISTRO)"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies based on OS
install_dependencies() {
    echo "Installing dependencies..."
    
    if [ "$OS" = "linux" ]; then
        if [ "$DISTRO" = "debian" ]; then
            sudo apt-get update
            sudo apt-get install -y git ruby ruby-dev libcurl4-openssl-dev make build-essential perl
        elif [ "$DISTRO" = "redhat" ]; then
            sudo yum install -y git ruby ruby-devel openssl-devel make gcc perl
        fi
    elif [ "$OS" = "macos" ]; then
        # Check if Homebrew is installed
        if ! command_exists brew; then
            echo "Homebrew not found. Please install it first:"
            echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            exit 1
        fi
        brew install git ruby perl
    fi
}

# Install WhatWeb
install_whatweb() {
    echo ""
    echo "Installing WhatWeb..."
    
    if command_exists whatweb; then
        echo "WhatWeb is already installed"
        whatweb --version
    else
        # Clone WhatWeb repository
        if [ ! -d "/opt/whatweb" ]; then
            sudo git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb
        fi
        
        # Make it executable
        sudo chmod +x /opt/whatweb/whatweb
        
        # Create symlink
        sudo ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb
        
        # Install Ruby dependencies
        cd /opt/whatweb
        sudo bundle install || echo "Bundle install failed - WhatWeb may still work"
        
        echo "WhatWeb installed successfully"
        whatweb --version
    fi
}

# Install Nikto
install_nikto() {
    echo ""
    echo "Installing Nikto..."
    
    if command_exists nikto; then
        echo "Nikto is already installed"
        nikto -Version
    else
        if [ "$OS" = "linux" ] && [ "$DISTRO" = "debian" ]; then
            # Try apt first
            sudo apt-get install -y nikto || {
                echo "apt install failed, installing from source..."
                install_nikto_from_source
            }
        else
            install_nikto_from_source
        fi
    fi
}

# Install Nikto from source
install_nikto_from_source() {
    # Clone Nikto repository
    if [ ! -d "/opt/nikto" ]; then
        sudo git clone https://github.com/sullo/nikto.git /opt/nikto
    fi
    
    # Create symlink
    sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
    sudo chmod +x /opt/nikto/program/nikto.pl
    
    # Update Nikto database
    cd /opt/nikto/program
    sudo ./nikto.pl -update || echo "Nikto update failed - continuing anyway"
    
    echo "Nikto installed successfully"
}

# Verify installations
verify_installations() {
    echo ""
    echo "Verifying installations..."
    echo "=========================="
    
    if command_exists whatweb; then
        echo "✓ WhatWeb: $(whatweb --version | head -1)"
    else
        echo "✗ WhatWeb: Not found"
    fi
    
    if command_exists nikto; then
        echo "✓ Nikto: $(nikto -Version | grep 'Nikto' | head -1)"
    else
        echo "✗ Nikto: Not found"
    fi
}

# Main installation flow
main() {
    echo "Starting installation..."
    
    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then 
        echo "Warning: Running as root. It's recommended to run as a regular user with sudo access."
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Install dependencies
    install_dependencies
    
    # Install tools
    install_whatweb
    install_nikto
    
    # Verify
    verify_installations
    
    echo ""
    echo "========================================="
    echo "Installation complete!"
    echo ""
    echo "You can now use the technology-aware scanner with:"
    echo "  python3 test_phase1_scanner.py"
    echo "========================================="
}

# Run main function
main