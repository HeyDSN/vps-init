#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to print error messages
error() {
    echo "Error: $1" >&2
    exit 1
}

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
   error "This script must be run as root"
fi

# Make sure sudo is installed
apt update || error "Failed to update package list"
apt install -y sudo || error "Failed to install sudo"

# Create ansible user
useradd -m -s /bin/bash ansible || error "Failed to create ansible user"

# Set password for ansible user (you may want to change this)
echo "ansible:ansible" | chpasswd || error "Failed to set password for ansible user"

# Add ansible user to sudo group
usermod -aG sudo ansible || error "Failed to add ansible user to sudo group"

# Allow ansible user to use sudo without password
echo "ansible ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/ansible || error "Failed to set sudo privileges for ansible user"

# Create .ssh directory for ansible user
mkdir -p /home/ansible/.ssh || error "Failed to create .ssh directory"

# Add public key to authorized_keys file
# Replace the text between EOF markers with your actual public key
cat << EOF > /home/ansible/.ssh/authorized_keys || error "Failed to create authorized_keys file"
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuLHrI18E1ypBdN5nGI6SE92pfsqWHoKgenxijpV1ch
EOF

# Set correct ownership and permissions
chown -R ansible:ansible /home/ansible/.ssh || error "Failed to set ownership of .ssh directory"
chmod 700 /home/ansible/.ssh || error "Failed to set permissions on .ssh directory"
chmod 600 /home/ansible/.ssh/authorized_keys || error "Failed to set permissions on authorized_keys file"

echo "Ansible user setup completed successfully!"