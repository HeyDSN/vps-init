# VPS Auto Setup Script for Debian

This repository contains an automated setup script for initializing a fresh Debian VPS server with essential services and security configurations.

## What This Script Does

The setup script automatically configures your VPS with:

- ✅ **System Updates**: Updates all packages to latest versions
- ✅ **Hostname Configuration**: Sets custom hostname
- ✅ **SSH Security**: Disables password authentication, enables key-based access
- ✅ **Swap File**: Creates 1GB swap file for better memory management
- ✅ **Docker**: Installs latest Docker CE with Docker Compose
- ✅ **Oh My Zsh**: Enhanced shell with useful plugins and aliases
- ✅ **Dozzle**: Docker log viewer accessible via web interface
- ✅ **Security Hardening**: Configures secure SSH settings

## Prerequisites

Before running the setup script, you need to prepare your fresh Debian VPS:

### Step 1: Update System Packages
```bash
apt update
```

### Step 2: Upgrade Existing Packages
```bash
apt upgrade -y
```

### Step 3: Install Git
```bash
apt install git -y
```

## Installation

### 1. Clone This Repository
```bash
git clone <your-repository-url>
cd vps-init
```

### 2. Make Script Executable
```bash
chmod +x setup.sh
```

### 3. Run Setup Script
```bash
./setup.sh
```

**Important**: The script must be run as the actual root user (not via sudo).

## Setup Process

The script will guide you through the following steps:

1. **System Validation**: Checks if running on Debian and verifies dependencies
2. **Hostname Configuration**: Prompts for new hostname (optional)
3. **System Updates**: Updates all packages
4. **SSH Security**: Configures key-based authentication and disables password login
5. **Swap Setup**: Creates and enables 1GB swap file
6. **Docker Installation**: Installs Docker CE and Docker Compose
7. **Oh My Zsh Setup**: Installs and configures enhanced shell
8. **Dozzle Deployment**: Sets up Docker log viewer
9. **Reboot Prompt**: Asks if you want to reboot to apply all changes

## SSH Key Configuration

Before running the script, ensure your SSH public key is added to the `PUBLIC_KEYS` array in `setup.sh`:

```bash
PUBLIC_KEYS=(
    "ssh-rsa YOUR_PUBLIC_KEY_HERE"
    # Add more keys as needed
)
```

**Warning**: The script disables password authentication. Make sure your SSH keys work before running the script!

## Services After Setup

### Dozzle (Docker Log Viewer)
- **URL**: `http://your-server-ip:7001`
- **Purpose**: Web-based Docker container log viewer
- **Location**: `/root/dozzle/`

### Oh My Zsh
- **Default Shell**: Zsh with Oh My Zsh framework
- **Theme**: robbyrussell
- **Plugins**: git, docker, docker-compose
- **Aliases**: Includes useful Docker shortcuts (dps, dc, dcu, etc.)

## Useful Commands

### Docker Aliases (Available after setup)
```bash
dps          # docker ps
dpa          # docker ps -a
di           # docker images
dc           # docker compose
dcu          # docker compose up -d
dcd          # docker compose down
dcl          # docker compose logs -f
```

### Manual Dozzle Management
```bash
# Start Dozzle
cd /root/dozzle && docker compose up -d

# Stop Dozzle
cd /root/dozzle && docker compose down

# View Dozzle logs
cd /root/dozzle && docker compose logs -f
```

## Security Features

- **SSH Password Authentication**: Disabled
- **SSH Key Authentication**: Enabled and required
- **Root Login**: Restricted to key-based authentication only
- **Firewall**: Managed at network level (recommended)

## Troubleshooting

### SSH Connection Issues
If you can't connect after setup:
1. Use VPS provider's console access
2. Check SSH key configuration: `cat /root/.ssh/authorized_keys`
3. Temporarily enable password auth: Edit `/etc/ssh/sshd_config`
4. Restart SSH: `systemctl restart sshd`

### Dozzle Not Working
```bash
# Check if container is running
docker ps | grep dozzle

# Restart Dozzle
cd /root/dozzle && docker compose restart

# Check logs
cd /root/dozzle && docker compose logs
```

### Re-running Setup
The script creates a marker file to prevent accidental re-runs. To run again:
```bash
rm /root/.vps-setup-complete
./setup.sh
```

## File Structure

```
vps-init/
├── setup.sh           # Main setup script
├── docker-compose.yml # Dozzle configuration
└── README.md          # This file
```

## Requirements

- **OS**: Debian 12 or newer
- **Access**: Root user access
- **Network**: Internet connection for package downloads
- **SSH**: Valid SSH key pair for secure access

## Support

If you encounter issues:
1. Check the script output for error messages
2. Verify all prerequisites are met
3. Ensure you're running as root user
4. Check that SSH keys are properly configured

## License

This project is provided as-is for educational and practical use.
