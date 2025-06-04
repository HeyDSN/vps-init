#!/bin/bash

# VPS Auto Setup Script for Debian
# This script automates the initial setup of a new Debian VPS server
# Usage: ./setup.sh

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SWAP_SIZE="1G"
SETUP_MARKER="/root/.vps-setup-complete"

# Public keys
# EXAMPLE
# PUBLIC_KEYS=(
#     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfXq4iZMx... user1@laptop"
#     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFj3F9cSd... user2@desktop"
#     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlPxEfGk9... backup@tablet"
# )
# Comment for machine name can be omitted
PUBLIC_KEYS=(
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDTDZXGYCm5gmLpwWYYe/nYtwQPmfLPFlqtUZ+g7jwI8WdJDT3hz28nNAWdWA72BEiHJ1zLwW9pbauc9Settpmqm1FKAMjpMtYVp3HKLmAbuZwCeEF+OHdem4Ye0Bm1U85QXt+uV0nxkvive2rN3M6YDDTz9H5rCsnTtURQtZXt5/EWgwP894I4xQCFyDc+HIieMqaW25k+WVV2A43Ly+7vNkQERRjslzC3aHtBM5YstRVmhEusPvjRBuwXWwdr7jTd8E/w4Qf7FIKWWuBuX325fPFgrNTxx5eR5V0B7EKKw0BQ47VphLBAqbEr8EVZwzijn7nlu5gyUHkdeU1VRXGJxpXcmtC+W3XHzqwzOSaDONVus+2yvonP/QoaHaXggLLHSht6a0YGr6XM9B+dQ1CTWUsMfAztImfXJ0a4oLSA5zy87qEIceBaNk9N5/UTUYCEPfuijeBwXd/5lTX6Ka8f9h9d7QR3Q8tQO0WqR5gAK20b6+09ors/9TFu5CxNzdVoWuluBo1abntUfDb24vD/2KgrtVwA58ZXknmusYEfOuY2/bK5Tt3cBCFwN9h0F9xpsZLsJtS6Bn69F9iwxDh4CfO8LHJNLBUIuBwjVASrh6ughBJe6aQo5PquvJHEni4S27nB1gLgwxVWVff8Puz/freJYScK9beJhWmxPZhobQ=="
)

# Function to check if script has been run before
check_setup_status() {
    if [[ -f "$SETUP_MARKER" ]]; then
        print_warning "This server has already been set up!"
        echo "Setup marker found at: $SETUP_MARKER"
        echo "Setup date: $(cat $SETUP_MARKER)"
        echo
        exit 1
    fi
}

# Function to create setup marker
create_setup_marker() {
    echo "VPS setup completed on $(date)" > $SETUP_MARKER
    print_success "Setup marker created at $SETUP_MARKER"
}

# Function to get hostname from user
get_hostname() {
    echo
    print_status "Current hostname: $(hostname)"
    read -p "Enter new hostname (or press Enter to keep current): " NEW_HOSTNAME
    
    if [[ -z "$NEW_HOSTNAME" ]]; then
        NEW_HOSTNAME=$(hostname)
        print_status "Keeping current hostname: $NEW_HOSTNAME"
    else
        print_status "New hostname will be: $NEW_HOSTNAME"
    fi
}

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running on Debian
check_debian() {
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This script is designed for Debian systems only"
        print_error "Current system is not Debian"
        exit 1
    fi
    
    local debian_version=$(cat /etc/debian_version)
    print_status "Detected Debian version: $debian_version"
}

# Function to check required dependencies
check_dependencies() {
    print_status "Checking required dependencies..."
    
    local missing_deps=()
    
    # Check for required commands
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if ! command -v systemctl >/dev/null 2>&1; then
        missing_deps+=("systemd")
    fi
    
    # fallocate is optional, we have dd fallback
    if ! command -v fallocate >/dev/null 2>&1; then
        print_warning "fallocate not available, will use dd for swap creation (slower)"
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_status "Installing missing dependencies..."
        apt-get update
        for dep in "${missing_deps[@]}"; do
            case $dep in
                "curl")
                    apt-get install -y curl
                    ;;
                "systemd")
                    print_error "systemd is required but not available"
                    exit 1
                    ;;
            esac
        done
        print_success "Dependencies installed"
    else
        print_success "All required dependencies are available"
    fi
}

# Function to require running as actual root user (not via sudo)
check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        print_error "This script must be run as the actual root user (not using sudo)"
        print_error "Please log in as root user instead"
        exit 1
    fi
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    apt-get update && apt-get upgrade -y
    print_success "System updated successfully"
}

# Function to change hostname
change_hostname() {
    if [[ "$NEW_HOSTNAME" != "$(hostname)" ]]; then
        print_status "Changing hostname to: $NEW_HOSTNAME"
        
        # Update /etc/hostname
        echo "$NEW_HOSTNAME" > /etc/hostname
        
        print_success "Hostname changed to $NEW_HOSTNAME"
        print_warning "Hostname change will take effect after reboot"
    else
        print_status "Hostname unchanged: $NEW_HOSTNAME"
    fi
}

# Function to setup SSH security
setup_ssh() {
    print_status "Setting up SSH security..."
    
    # Create .ssh directory for root if it doesn't exist
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # Create or reset authorized_keys file
    > /root/.ssh/authorized_keys
    
    # Add all public keys
    if [[ ${#PUBLIC_KEYS[@]} -eq 0 ]]; then
        print_error "No SSH public keys configured!"
        print_error "Setup cannot continue without SSH keys"
        exit 1
    fi
    
    print_status "Adding ${#PUBLIC_KEYS[@]} SSH public keys:"
    for key in "${PUBLIC_KEYS[@]}"; do
        echo "$key" >> /root/.ssh/authorized_keys
        print_status "  - Added key: ${key:0:20}..."
    done
    
    chmod 600 /root/.ssh/authorized_keys
    
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Configure SSH settings
    sed -i 's/#PermitRootLogin.*/PermitRootLogin without-password/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Ensure the settings are properly set
    if ! grep -q "^PermitRootLogin without-password" /etc/ssh/sshd_config; then
        echo "PermitRootLogin without-password" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
        echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service
    systemctl restart sshd
    
    print_success "SSH security configured"
    print_warning "Make sure you can login with your SSH keys before closing this session!"
}

# Function to setup swap (Debian compatible)
setup_swap() {
    print_status "Setting up ${SWAP_SIZE} swap file..."
    
    # Check if swap already exists
    if swapon --show | grep -q "/swapfile"; then
        print_warning "Swap file already exists, skipping..."
        return
    fi
    
    # Create swap file (Debian compatible method)
    if ! fallocate -l $SWAP_SIZE /swapfile 2>/dev/null; then
        print_warning "fallocate not available, using dd method (slower)..."
        # Calculate size in megabytes
        local swap_size_mb=$((${SWAP_SIZE//[!0-9]/} * 1024))
        dd if=/dev/zero of=/swapfile bs=1M count=$swap_size_mb
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Add to fstab for persistence
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi
    
    print_success "Swap file created and added to fstab"
}

# Function to install Docker on Debian
install_docker() {
    print_status "Installing Docker..."
    
    # Remove old Docker installations
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Install prerequisites
    apt-get install -y ca-certificates curl gnupg
    
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    
    # Add the repository to Apt sources
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index
    apt-get update
    
    # Install Docker
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    print_success "Docker installed successfully"
}

# Function to install and setup Oh My Zsh
install_oh_my_zsh() {
    print_status "Installing Oh My Zsh..."
    
    # Install zsh if not already installed
    if ! command -v zsh >/dev/null 2>&1; then
        print_status "Installing zsh..."
        apt-get install -y zsh
    fi
    
    # Check if Oh My Zsh is already installed
    if [[ -d "/root/.oh-my-zsh" ]]; then
        print_warning "Oh My Zsh already installed, skipping..."
        return
    fi
    
    # Install Oh My Zsh (unattended installation)
    print_status "Downloading and installing Oh My Zsh..."
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    
    # Change default shell to zsh for root
    print_status "Changing default shell to zsh for root user..."
    chsh -s $(which zsh) root
    
    # Create a basic .zshrc configuration
    print_status "Configuring Oh My Zsh..."
    cat > /root/.zshrc << 'EOF'
# Path to your oh-my-zsh installation.
export ZSH="$HOME/.oh-my-zsh"

# Set name of the theme to load
ZSH_THEME="robbyrussell"

# Which plugins would you like to load?
plugins=(git docker docker-compose)

source $ZSH/oh-my-zsh.sh

# User configuration
export PATH=$PATH:/usr/local/bin

# Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'

# Docker aliases
alias dps='docker ps'
alias dpa='docker ps -a'
alias di='docker images'
alias dc='docker compose'
alias dcu='docker compose up -d'
alias dcd='docker compose down'
alias dcl='docker compose logs -f'
EOF
    
    print_success "Oh My Zsh installed and configured"
    print_warning "Zsh will be the default shell for new sessions after reboot"
}

# Function to setup Dozzle using Docker Compose
setup_dozzle() {
    print_status "Setting up Dozzle using Docker Compose..."
    
    # Create Dozzle directory in root's home
    DOZZLE_DIR="/root/dozzle"
    mkdir -p "$DOZZLE_DIR"
    print_success "Created Dozzle directory: $DOZZLE_DIR"
    
    # Check for docker-compose.yml in current directory
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    COMPOSE_SOURCE="$SCRIPT_DIR/docker-compose.yml"
    
    if [[ ! -f "$COMPOSE_SOURCE" ]]; then
        print_error "docker-compose.yml not found in $SCRIPT_DIR!"
        print_error "Please ensure it exists in the same directory as this script"
        return 1
    fi
    
    # Copy docker-compose.yml to Dozzle directory
    cp "$COMPOSE_SOURCE" "$DOZZLE_DIR/docker-compose.yml"
    print_success "Copied docker-compose.yml to $DOZZLE_DIR"
    
    # Create .env file with hostname for docker-compose
    echo "HOSTNAME=$NEW_HOSTNAME" > "$DOZZLE_DIR/.env"
    print_success "Created .env file with hostname: $NEW_HOSTNAME"
    
    # Launch Dozzle
    print_status "Starting Dozzle container..."
    cd "$DOZZLE_DIR" && docker compose up -d
    
    # Verify it's running
    if docker ps | grep -q dozzle; then
        print_success "Dozzle is running on port 7001"
    else
        print_error "Failed to start Dozzle container!"
        docker compose -f "$DOZZLE_DIR/docker-compose.yml" logs
        return 1
    fi
}

# Function to prompt for reboot
prompt_reboot() {
    echo
    echo "=========================================="
    print_warning "REBOOT REQUIRED"
    echo "=========================================="
    echo
    print_status "The following changes require a reboot to take full effect:"
    echo "  - Hostname change (if modified)"
    echo "  - Zsh as default shell"
    echo "  - System updates and kernel changes"
    echo
    
    read -p "Would you like to reboot now? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Rebooting system in 5 seconds..."
        print_warning "Make sure you can reconnect with SSH keys!"
        sleep 5
        reboot
    else
        echo
        print_warning "IMPORTANT: Please reboot the system as soon as possible!"
        print_warning "Some changes will not take effect until after reboot."
        echo
        print_status "To reboot later, run: reboot"
    fi
}

# Function to display final information
display_final_info() {
    echo
    echo "=========================================="
    print_success "VPS Setup Complete!"
    echo "=========================================="
    echo
    echo "Server Information:"
    echo "  Hostname: $NEW_HOSTNAME"
    echo "  Swap: $SWAP_SIZE"
    echo "  Docker: Installed and running"
    echo "  Dozzle: Running on port 7001"
    echo "  Shell: Oh My Zsh (default for new sessions)"
    echo
    echo "Security:"
    echo "  SSH Password: Disabled"
    echo "  SSH Key: Configured"
    echo "  Firewall: Managed at network level"
    echo
    echo "Next Steps:"
    echo "  1. Test SSH connection with your key"
    echo "  2. Access Dozzle at http://$(hostname -I | awk '{print $1}'):7001"
    echo "  3. Configure additional services as needed"
    echo
    print_warning "IMPORTANT: Test SSH key authentication before closing this session!"
    echo
}

# Main execution
main() {
    print_status "Starting VPS automated setup for Debian..."
    
    check_root
    check_debian
    check_dependencies
    check_setup_status
    get_hostname
    update_system
    change_hostname
    setup_ssh
    setup_swap
    install_docker
    install_oh_my_zsh
    
    # Setup Dozzle with error handling
    if ! setup_dozzle; then
        print_error "Dozzle setup failed, but continuing with other setup tasks"
        print_status "You can manually start Dozzle later with: docker compose -f /root/dozzle/docker-compose.yml up -d"
    fi
    
    create_setup_marker
    display_final_info
    prompt_reboot
    
    print_success "Setup script completed successfully!"
}

# Run main function
main "$@"
