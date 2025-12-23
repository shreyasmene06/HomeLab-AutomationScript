# HomeLab Automation Script

A comprehensive automation script that transforms a Linux Mint Xfce laptop into a fully functional home server with NAS, VPN, and media streaming capabilities.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Quick Start](#quick-start)
5. [Script Walkthrough](#script-walkthrough)
6. [Web Setup Guide](#web-setup-guide)
7. [Access Guide](#access-guide)
   - [Jellyfin Media Server](#jellyfin-media-server)
   - [NAS File Storage](#nas-file-storage)
   - [SSH Remote Terminal](#ssh-remote-terminal)
8. [Usage Guide](#usage-guide)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Overview

This script automates the process of converting a Linux Mint Xfce laptop into a home server. It is designed with beginners in mind, providing interactive guidance through each step of the setup process.

### What is a HomeLab?

A HomeLab is a personal server setup that you control. It allows you to run your own media streaming service, file storage, and secure VPN without relying on third-party subscriptions.

### Objectives

| Objective | Description |
|-----------|-------------|
| NAS Setup | Network Attached Storage for accessing files from any device |
| VPN Exit Node | Route internet traffic through your home network from anywhere |
| Media Server | Stream movies and TV shows to any device |
| Remote Access | Secure access to your server from anywhere using Tailscale |

## Important Disclaimer

> **This script is designed and tested for Linux Mint Xfce Edition.**
>
> **Why Xfce is recommended:**
> - Uses approximately 400MB RAM at idle compared to 1-2GB for other desktop environments
> - Minimal resource usage maximizes server application performance
> - Optimal for older hardware or maximizing available resources
> - Stable foundation for 24/7 server operation
>
> The script may function on other Linux Mint editions (Cinnamon, MATE), but Xfce provides the best performance for server workloads.

## Features

After running this script, your system will have:

### CasaOS Dashboard
A web-based control panel for managing your server and installing applications.

### Jellyfin Media Server
A self-hosted media streaming solution compatible with:
- Mobile devices (phones and tablets)
- Desktop computers
- Smart TVs
- Gaming consoles

### NAS (Network Attached Storage)
File access from anywhere:
- Document, photo, and video storage
- Cross-device file sharing
- Data backup capabilities

### Tailscale VPN
Secure remote access features:
- Global access to your server
- End-to-end encryption
- Exit node functionality
- No router configuration required

## Requirements

### Hardware
- A dedicated laptop or computer for server use
- Wired Ethernet connection (recommended) or stable WiFi
- Storage drive for media files (internal or external)

### Software
- Linux Mint Xfce Edition (other editions not officially supported)
- Active internet connection
- Tailscale account (free, created during setup)

### Knowledge
- Basic terminal usage
- Web browser navigation

## Quick Start

### Step 1: Download the Script

Open a terminal and run:

```bash
git clone https://github.com/your-username/HomeLab-Automation.git
cd HomeLab-Automation
```

Or download directly:

```bash
wget https://raw.githubusercontent.com/your-username/HomeLab-Automation/main/setup_homelab.sh
```

### Step 2: Run the Script

```bash
sudo bash setup_homelab.sh
```

### Step 3: Follow the Prompts

The script provides interactive guidance through each step.

## Script Walkthrough

### Step 0: Root Privilege Check

The script verifies it is running with sudo privileges, which are required for system configuration and software installation.

### Step 1: Pre-flight System Verification

Verifies the operating system is Linux Mint and checks for the Xfce desktop environment. The script is optimized for this specific configuration.

### Step 2: System Preparation

Updates package repositories and installs curl if not present. This ensures access to the latest software information and download capabilities.

### Step 3: CasaOS Installation

Downloads and executes the official CasaOS installer. CasaOS provides a web-based interface for server management and application installation.

**Duration:** 3-10 minutes depending on internet speed

### Step 4: Tailscale VPN Installation

Installs the Tailscale VPN client and initiates authentication. Tailscale creates a secure private network for remote access without complex router configuration.

### Step 5: VPN Exit Node and Networking Configuration

Configures the system for VPN exit node functionality:

- Enables IP forwarding in `/etc/sysctl.d/99-tailscale.conf`
- Sets `net.ipv4.ip_forward = 1`
- Sets `net.ipv6.conf.all.forwarding = 1`
- Configures UFW firewall rules for SSH and Tailscale
- Advertises the machine as a Tailscale exit node

### Step 6: Remote Access Information

Displays SSH and SFTP connection details for remote server access.

### Step 7: Power Management Guide

Provides instructions for configuring power settings to prevent the laptop from sleeping when the lid is closed. This is a manual GUI configuration step.

### Step 8: Jellyfin Media Server Preparation

Creates the media directory structure:
- `/DATA/Media/Movies`
- `/DATA/Media/Shows`

Sets appropriate file permissions for media access.

### Final Summary

Displays server information including IP addresses, access URLs, and configuration details.

## Web Setup Guide

### CasaOS Initial Setup

**Timing:** During Step 3 of the script

1. Open a web browser
2. Navigate to `http://YOUR_LOCAL_IP`
3. Create an account with username and password
4. Save the password for future access

### Tailscale Authentication

**Timing:** During Step 4 of the script

1. The script displays an authentication URL
2. Open the URL in a browser
3. Log in to your Tailscale account or create one
4. Authorize the machine when prompted
5. Return to the terminal to confirm success

### Tailscale Admin Console Configuration

**Timing:** During Step 5 of the script

1. Navigate to https://login.tailscale.com/admin/machines
2. Locate your server in the machine list
3. Open the menu and select "Edit route settings"
4. Enable "Use as exit node"
5. Select "Disable key expiry" to prevent automatic disconnection every 90 days

### Installing Jellyfin

**Timing:** After script completion

1. Access CasaOS at `http://YOUR_LOCAL_IP`
2. Open the App Store
3. Search for "Jellyfin"
4. Install the application
5. Access Jellyfin at `http://YOUR_LOCAL_IP:8097`

**Note:** Jellyfin uses port 8097 in CasaOS, not the default 8096.

## Access Guide

### Network Access Types

| Type | Use Case | Address |
|------|----------|---------|
| Local Access | Connected to home network | Local IP address |
| Remote Access | Away from home | Tailscale IP address |

Remote access requires Tailscale to be installed and connected on the client device.

## Jellyfin Media Server

### Web Browser Access

**Local:**
```
http://YOUR_LOCAL_IP:8097
```

**Remote:**
```
http://YOUR_TAILSCALE_IP:8097
```

### Windows

**Web Browser:**
Navigate to `http://YOUR_IP:8097` in Chrome, Firefox, or Edge.

**Jellyfin Desktop App:**
1. Download from https://jellyfin.org/downloads/
2. Install and configure with server address:
   - Local: `http://YOUR_LOCAL_IP:8097`
   - Remote: `http://YOUR_TAILSCALE_IP:8097`

**Jellyfin Media Player:**
Download from https://github.com/jellyfin/jellyfin-media-player/releases for improved video playback and hardware acceleration support.

### macOS

**Web Browser:**
Navigate to `http://YOUR_IP:8097` in Safari, Chrome, or Firefox.

**Jellyfin Media Player:**
Download the .dmg from https://github.com/jellyfin/jellyfin-media-player/releases

**Infuse (App Store):**
Premium application with native interface and excellent playback performance.

### Linux

**Web Browser:**
```bash
firefox http://YOUR_IP:8097
```

**Jellyfin Media Player:**
```bash
# Debian/Ubuntu/Mint
sudo dpkg -i jellyfin-media-player_*.deb

# Flatpak
flatpak install flathub com.github.iwalton3.jellyfin-media-player
```

### Android

**Jellyfin (Play Store):**
Official application. Configure with server address `http://YOUR_IP:8097`.

**Findroid (Play Store):**
Alternative client with Material Design interface.

**Remote Access Setup:**
1. Install Tailscale from Play Store
2. Authenticate with your Tailscale account
3. Connect to your network
4. Use Tailscale IP in Jellyfin configuration

### iOS and iPadOS

**Jellyfin (App Store):**
Official application. Configure with server address `http://YOUR_IP:8097`.

**Swiftfin (App Store):**
Alternative client with native iOS design.

**Remote Access Setup:**
1. Install Tailscale from App Store
2. Authenticate and connect
3. Use Tailscale IP in client configuration

### Smart TVs

**Android TV / Google TV:**
Install Jellyfin from Play Store.

**Amazon Fire TV:**
Install from Amazon App Store or sideload the Android APK.

**LG webOS / Samsung Tizen:**
Use the built-in web browser to access `http://YOUR_IP:8097` or use DLNA.

**Apple TV:**
Install Swiftfin from App Store.

## NAS File Storage

### Protocol Overview

| Protocol | Description | Security |
|----------|-------------|----------|
| SFTP | Secure File Transfer Protocol | Encrypted |
| SMB/CIFS | Windows file sharing | Network-level |
| SSH | Secure shell access | Encrypted |

SFTP is recommended for cross-platform compatibility and security.

### File Storage Location

```
/DATA/Media/
├── Movies/
└── Shows/
```

### Windows

**WinSCP (Recommended):**
1. Download from https://winscp.net/
2. Configure connection:
   - File Protocol: SFTP
   - Host name: YOUR_IP
   - Port: 22
   - User name: YOUR_LINUX_USERNAME
   - Password: YOUR_LINUX_PASSWORD
3. Navigate to `/DATA/Media/`

**FileZilla:**
1. Download from https://filezilla-project.org/
2. Quick Connect:
   - Host: `sftp://YOUR_IP`
   - Username: YOUR_LINUX_USERNAME
   - Password: YOUR_LINUX_PASSWORD
   - Port: 22

### macOS

**Finder:**
1. Press `Cmd + K` or select Go > Connect to Server
2. Enter `sftp://YOUR_IP`
3. Authenticate with Linux credentials
4. Navigate to `/DATA/Media/`

**Cyberduck:**
Download from https://cyberduck.io/ and configure SFTP connection.

### Linux

**File Manager (GUI):**

Nautilus:
```
sftp://YOUR_USERNAME@YOUR_IP
```

Thunar:
```
sftp://YOUR_USERNAME@YOUR_IP
```

Dolphin:
```
sftp://YOUR_USERNAME@YOUR_IP
```

**Terminal:**
```bash
sftp username@YOUR_IP
```

Common commands:
- `ls` - List files
- `cd /DATA/Media` - Change directory
- `get filename` - Download file
- `put filename` - Upload file
- `exit` - Disconnect

**Mount as Network Drive:**
```bash
sudo apt install sshfs
mkdir ~/homelab
sshfs username@YOUR_IP:/DATA/Media ~/homelab

# Unmount
fusermount -u ~/homelab
```

### Android

**Solid Explorer (Play Store):**
1. Menu > New cloud connection > SFTP
2. Configure:
   - Server: YOUR_IP
   - Port: 22
   - Username: YOUR_LINUX_USERNAME
   - Password: YOUR_LINUX_PASSWORD

**Material Files (Play Store/F-Droid):**
Add FTP server with SFTP protocol.

**CX File Explorer (Play Store):**
Network > Remote > SFTP

### iOS and iPadOS

**Secure ShellFish (App Store):**
Configure server connection for Files app integration.

**FE File Explorer (App Store):**
Add SFTP connection with server details.

**Documents by Readdle (App Store):**
Connections > Add Connection > SFTP

## SSH Remote Terminal

### Windows

**Windows Terminal / PowerShell:**
```powershell
ssh YOUR_USERNAME@YOUR_IP
```

**PuTTY:**
1. Download from https://putty.org/
2. Host Name: YOUR_IP
3. Port: 22

### macOS

```bash
ssh YOUR_USERNAME@YOUR_IP
```

### Linux

```bash
ssh YOUR_USERNAME@YOUR_IP
```

### Android

**Termux (F-Droid/Play Store):**
```bash
pkg install openssh
ssh YOUR_USERNAME@YOUR_IP
```

**JuiceSSH (Play Store):**
GUI-based SSH client.

### iOS

**Termius (App Store):**
Add host with server details.

## Usage Guide

### CasaOS Server Management

Access the dashboard:
- Local: `http://YOUR_LOCAL_IP`
- Remote: `http://YOUR_TAILSCALE_IP`

Common tasks:
- Install applications from App Store
- Monitor system resources on dashboard
- Manage files through the Files application
- Configure system settings

### Adding Media to Jellyfin

**Recommended Directory Structure:**

Movies:
```
/DATA/Media/Movies/
├── Inception (2010)/
│   └── Inception.mkv
├── The Matrix (1999)/
│   └── The Matrix.mkv
└── Interstellar (2014)/
    └── Interstellar.mkv
```

TV Shows:
```
/DATA/Media/Shows/
├── Breaking Bad/
│   ├── Season 1/
│   │   ├── S01E01.mkv
│   │   └── S01E02.mkv
│   └── Season 2/
│       └── S02E01.mkv
└── The Office/
    └── Season 1/
        └── S01E01.mkv
```

**Configuring Jellyfin Libraries:**

1. Access Jellyfin at `http://YOUR_IP:8097`
2. Navigate to Dashboard > Libraries
3. Add Library:
   - Movies: `/DATA/Media/Movies`
   - Shows: `/DATA/Media/Shows`
4. Jellyfin will scan and retrieve metadata automatically

### Using the VPN Exit Node

Route all internet traffic through your home network:

**Windows/Mac/Linux:**
1. Open Tailscale application
2. Select your server
3. Enable "Use as exit node"

**Android:**
1. Open Tailscale application
2. Access menu
3. Select "Use exit node"
4. Choose your server

**iOS:**
1. Open Tailscale application
2. Select your server
3. Enable "Use as Exit Node"

### File Transfer Best Practices

1. Connect via SFTP using preferred client
2. Navigate to `/DATA/Media/Movies/` or `/DATA/Media/Shows/`
3. Create folder with proper naming convention
4. Upload files

Naming convention for optimal metadata matching:
- Correct: `Inception (2010)`
- Incorrect: `Inception`

## Troubleshooting

### CasaOS Not Loading

**Symptoms:** Browser displays connection error or continuous loading

**Solutions:**
1. Wait 30-60 seconds and refresh
2. Check service status:
   ```bash
   sudo systemctl status casaos-gateway
   ```
3. Restart service:
   ```bash
   sudo systemctl restart casaos-gateway
   ```

### Tailscale Connection Issues

**Symptoms:** Cannot reach server via Tailscale IP

**Solutions:**
1. Check status:
   ```bash
   tailscale status
   ```
2. Re-authenticate:
   ```bash
   sudo tailscale up
   ```
3. Verify firewall:
   ```bash
   sudo ufw status
   ```

### Jellyfin Permission Errors

**Symptoms:** Jellyfin cannot access media files

**Solutions:**
1. Verify permissions:
   ```bash
   ls -la /DATA/Media/
   ```
2. Correct permissions:
   ```bash
   sudo chown -R YOUR_USERNAME:YOUR_USERNAME /DATA
   sudo chmod -R 775 /DATA
   ```
3. Configure Jellyfin environment variables in CasaOS:
   ```
   PUID = 1000
   PGID = 1000
   ```
   Verify IDs with: `id`

### SFTP Connection Failures

**Symptoms:** Connection refused or timeout

**Solutions:**
1. Check SSH service:
   ```bash
   sudo systemctl status ssh
   ```
2. Start SSH:
   ```bash
   sudo systemctl start ssh
   sudo systemctl enable ssh
   ```
3. Verify firewall:
   ```bash
   sudo ufw allow ssh
   ```

### Server Sleep Issues

**Symptoms:** Server becomes unreachable after period of inactivity

**Solutions:**
1. Open Power Manager from Applications menu
2. System tab: Set "When laptop lid is closed" to "Switch off display"
3. Apply for both battery and plugged in modes
4. Disable screen saver and auto-suspend

## FAQ

### General

**Is this free?**

Yes. CasaOS, Jellyfin, and Tailscale are free. Tailscale offers free personal use for up to 100 devices.

**Can I use old hardware?**

Yes. Most laptops from the past 10-15 years are suitable.

**What is the power consumption?**

Laptops are efficient. Expect approximately $2-5 per month in electricity costs.

**Is it secure?**

Yes. Tailscale uses WireGuard encryption. SFTP is encrypted. Data remains on your hardware.

### Technical

**Why Xfce instead of a headless server OS?**

Xfce provides a GUI for management while remaining lightweight. It is suitable for users who prefer visual feedback.

**Can I install additional applications?**

Yes. CasaOS App Store includes Nextcloud, Plex, Home Assistant, Pi-hole, and others.

**What if my IP address changes?**

Tailscale provides a fixed IP that remains constant regardless of ISP changes.

### Media

**What video formats does Jellyfin support?**

Most common formats including MKV, MP4, and AVI. Jellyfin can transcode unsupported formats.

**Can multiple users stream simultaneously?**

Yes. Performance depends on CPU capabilities for transcoding.

**How does metadata retrieval work?**

Jellyfin automatically downloads metadata when files are properly named (e.g., "Movie Name (Year)").

## Contributing

Contributions are welcome:
- Bug reports
- Feature suggestions
- Documentation improvements
- Pull requests

## License

This project is available under the MIT License.

## Acknowledgments

- [CasaOS](https://casaos.io/)
- [Tailscale](https://tailscale.com/)
- [Jellyfin](https://jellyfin.org/)

---

**Author:** Shreyas Mene  
**Version:** 0.0.1
