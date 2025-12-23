#!/bin/bash

# ==============================================================================
#  ██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗ 
#  ██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗
#  ███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝
#  ██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗
#  ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝
#  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝ 
# ==============================================================================
# Script:      setup_homelab.sh
# Description: Transforms a Linux Mint Xfce laptop into a complete Home Lab Server
#              (NAS + VPN Exit Node + Media Server)
# Target:      Beginners who want a guided, interactive setup experience
# Author:      Shreyas Mene 
# Version:     1.0.0
# ==============================================================================

set -o pipefail

# ==============================================================================
# CONFIGURATION
# ==============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_DIR="/var/log"
readonly LOG_FILE="${LOG_DIR}/homelab_setup.log"
readonly MEDIA_ROOT="/DATA/Media"

# ==============================================================================
# COLORS & FORMATTING
# ==============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m' # No Color

# ==============================================================================
# LOGGING FUNCTIONS
# ==============================================================================

# Initialize logging - fallback to /tmp if /var/log is not writable
init_logging() {
    local log_file="$LOG_FILE"
    if ! touch "$log_file" 2>/dev/null; then
        log_file="/tmp/homelab_setup.log"
    fi
    echo "$log_file"
}

ACTIVE_LOG_FILE=$(init_logging)

# Log message to file with timestamp
log_to_file() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$ACTIVE_LOG_FILE" 2>/dev/null
}

# Print informational message (Blue)
print_info() {
    echo -e "${BLUE}ℹ ${BOLD}[INFO]${NC} ${BLUE}$1${NC}"
    log_to_file "[INFO] $1"
}

# Print success message (Green)
print_success() {
    echo -e "${GREEN}✓ ${BOLD}[SUCCESS]${NC} ${GREEN}$1${NC}"
    log_to_file "[SUCCESS] $1"
}

# Print warning message (Yellow)
print_warning() {
    echo -e "${YELLOW}⚠ ${BOLD}[WARNING]${NC} ${YELLOW}$1${NC}"
    log_to_file "[WARNING] $1"
}

# Print error message (Red)
print_error() {
    echo -e "${RED}✗ ${BOLD}[ERROR]${NC} ${RED}$1${NC}"
    log_to_file "[ERROR] $1"
}

# Print a step header
print_step() {
    local step_num="$1"
    local step_title="$2"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  STEP ${step_num}: ${BOLD}${step_title}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    log_to_file "=== STEP $step_num: $step_title ==="
}

# Print an educational/info box
print_infobox() {
    local title="$1"
    shift
    echo ""
    echo -e "${YELLOW}┌──────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  📘 ${BOLD}$title${NC}"
    echo -e "${YELLOW}├──────────────────────────────────────────────────────────────────────────────┤${NC}"
    for line in "$@"; do
        printf "${YELLOW}│${NC}  %s\n" "$line"
    done
    echo -e "${YELLOW}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Print action required box (for user interaction)
print_action_required() {
    local title="$1"
    shift
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  🚨 ${BOLD}ACTION REQUIRED: $title${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    for line in "$@"; do
        printf "${RED}║${NC}  %s\n" "$line"
    done
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Pause and wait for user confirmation
pause_for_user() {
    local message="${1:-Press [Enter] to continue...}"
    echo ""
    read -rp "$(echo -e "${GREEN}▶ ${message}${NC}")" _
    echo ""
}

# Exit with error
exit_with_error() {
    print_error "$1"
    echo ""
    echo -e "${RED}${BOLD}Setup aborted.${NC} Check the log file for details: ${DIM}$ACTIVE_LOG_FILE${NC}"
    exit 1
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

# Get the LAN IP address (excluding docker, tailscale, loopback interfaces)
get_lan_ip() {
    local ip
    ip=$(ip -4 addr show 2>/dev/null | grep -vE 'docker|tailscale|br-|veth|lo:' | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -n 1)
    
    # Fallback method
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    echo "${ip:-Unable to detect}"
}

# Get Tailscale IP
get_tailscale_ip() {
    tailscale ip -4 2>/dev/null || echo "Not connected"
}

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Check if a systemd service is running
service_is_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# ==============================================================================
# STEP FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# Step 0: Root Privilege Check
# ------------------------------------------------------------------------------
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo ""
        print_error "This script must be run as root (with sudo)."
        echo ""
        echo -e "  ${DIM}Please run the script like this:${NC}"
        echo -e "  ${CYAN}sudo bash setup_homelab.sh${NC}"
        echo ""
        exit 1
    fi
    
    # Detect the actual user (not root)
    ACTUAL_USER="${SUDO_USER:-$(whoami)}"
    ACTUAL_USER_UID=$(id -u "$ACTUAL_USER" 2>/dev/null || echo "1000")
    ACTUAL_USER_GID=$(id -g "$ACTUAL_USER" 2>/dev/null || echo "1000")
}

# ------------------------------------------------------------------------------
# Step 1: Pre-flight System Verification
# ------------------------------------------------------------------------------
preflight_check() {
    print_step "1" "PRE-FLIGHT SYSTEM VERIFICATION"
    
    print_infobox "What is this step?" \
        "We need to verify that your system meets the requirements:" \
        "  • Operating System: Linux Mint" \
        "  • Desktop Environment: Xfce" \
        "" \
        "This script is specifically designed for Linux Mint Xfce systems."
    
    # Check OS
    print_info "Checking operating system..."
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$NAME" == *"Linux Mint"* ]] || [[ "$ID" == "linuxmint" ]]; then
            print_success "Operating System: $PRETTY_NAME"
        else
            exit_with_error "This script requires Linux Mint. Detected: ${NAME:-Unknown OS}"
        fi
    else
        exit_with_error "Cannot determine OS. /etc/os-release not found."
    fi
    
    # Check Desktop Environment
    print_info "Checking desktop environment..."
    local desktop="${XDG_CURRENT_DESKTOP:-}"
    
    # Handle cases where the script is run via SSH or without a desktop session
    if [[ -z "$desktop" ]]; then
        print_warning "Desktop environment not detected (running without GUI session?)."
        print_info "Attempting alternative detection..."
        
        # Check if Xfce is installed
        if command_exists xfce4-session || dpkg -l | grep -q xfce4-session; then
            print_success "Xfce appears to be installed on this system."
        else
            print_warning "Cannot verify Xfce installation. Proceeding anyway..."
        fi
    elif [[ "$desktop" == *"XFCE"* ]] || [[ "$desktop" == *"xfce"* ]] || [[ "$desktop" == *"Xfce"* ]]; then
        print_success "Desktop Environment: Xfce"
    else
        exit_with_error "This script requires Xfce desktop. Detected: $desktop"
    fi
    
    print_success "Pre-flight checks passed!"
}

# ------------------------------------------------------------------------------
# Step 2: System Preparation
# ------------------------------------------------------------------------------
system_prep() {
    print_step "2" "SYSTEM PREPARATION"
    
    print_infobox "What is this step?" \
        "We're preparing your system by:" \
        "  • Updating package repositories (like refreshing an app store)" \
        "  • Installing 'curl' - a tool needed to download installers" \
        "" \
        "This ensures we have the latest software information."
    
    # Update apt repositories
    print_info "Updating package repositories (this may take a moment)..."
    if apt-get update -qq 2>&1 | tee -a "$ACTIVE_LOG_FILE"; then
        print_success "Package repositories updated."
    else
        print_warning "Some repositories may have had issues, but continuing..."
    fi
    
    # Check and install curl
    print_info "Checking for required tools..."
    if command_exists curl; then
        print_success "curl is already installed."
    else
        print_info "Installing curl..."
        if apt-get install -y curl >> "$ACTIVE_LOG_FILE" 2>&1; then
            print_success "curl installed successfully."
        else
            exit_with_error "Failed to install curl. Check your internet connection."
        fi
    fi
    
    print_success "System preparation complete!"
}

# ------------------------------------------------------------------------------
# Step 3: CasaOS Installation
# ------------------------------------------------------------------------------
install_casaos() {
    print_step "3" "CASAOS INSTALLATION"
    
    print_infobox "What is CasaOS?" \
        "CasaOS is a beautiful, easy-to-use home cloud system." \
        "" \
        "Think of it as your personal 'App Store' for server applications!" \
        "  • Install apps like Jellyfin, Plex, Nextcloud with one click" \
        "  • Manage your files through a web interface" \
        "  • Monitor your system resources" \
        "" \
        "After installation, you'll access it through your web browser."
    
    # Check if CasaOS is already installed and running
    if service_is_running casaos-gateway || service_is_running casaos; then
        print_success "CasaOS is already installed and running!"
    else
        print_info "Downloading and running the CasaOS installer..."
        print_warning "This will take several minutes. Please be patient."
        echo ""
        
        # Run the official CasaOS installer
        if curl -fsSL https://get.casaos.io | bash; then
            print_success "CasaOS installation completed!"
        else
            exit_with_error "CasaOS installation failed. Check the log for details."
        fi
    fi
    
    # Detect and display LAN IP
    local lan_ip
    lan_ip=$(get_lan_ip)
    
    print_action_required "VERIFY CASAOS DASHBOARD" \
        "CasaOS is now installed! You need to set it up:" \
        "" \
        "1. Open your web browser" \
        "2. Go to: ${BOLD}http://${lan_ip}${NC}" \
        "3. Create your CasaOS account (remember this password!)" \
        "4. Verify the dashboard loads correctly" \
        "" \
        "${DIM}Tip: If the page doesn't load, wait 30 seconds and refresh.${NC}"
    
    pause_for_user "Press [Enter] AFTER you have created your CasaOS account and verified the dashboard..."
    
    print_success "CasaOS setup verified by user."
}

# ------------------------------------------------------------------------------
# Step 4: Tailscale VPN Installation
# ------------------------------------------------------------------------------
install_tailscale() {
    print_step "4" "TAILSCALE VPN INSTALLATION"
    
    print_infobox "What is Tailscale?" \
        "Tailscale creates a secure private network between your devices." \
        "" \
        "Why do you need it?" \
        "  • Access your home server from ANYWHERE in the world" \
        "  • No complex port forwarding or router configuration" \
        "  • Military-grade encryption protects your data" \
        "  • Use your home server as a VPN exit node" \
        "" \
        "It's like having a secure tunnel directly to your home network!"
    
    # Check if Tailscale is already installed
    if command_exists tailscale; then
        print_success "Tailscale is already installed."
    else
        print_info "Installing Tailscale..."
        if curl -fsSL https://tailscale.com/install.sh | sh; then
            print_success "Tailscale installed successfully!"
        else
            exit_with_error "Tailscale installation failed."
        fi
    fi
    
    # Start Tailscale authentication
    echo ""
    print_info "Starting Tailscale authentication..."
    print_warning "A login URL will appear below. You MUST open it to authenticate."
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
    
    # Run tailscale up (this will output a URL if not authenticated)
    tailscale up
    
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
    echo ""
    
    print_action_required "AUTHENTICATE TAILSCALE" \
        "If a URL appeared above:" \
        "" \
        "1. Open the URL in your web browser" \
        "2. Log in with your Tailscale account (or create one - it's free!)" \
        "3. Authorize this machine when prompted" \
        "4. Wait for 'Success' message in the terminal" \
        "" \
        "${DIM}If you're already authenticated, no URL appears and you can continue.${NC}"
    
    pause_for_user "Press [Enter] AFTER you have authenticated with Tailscale..."
    
    # Verify connection
    if tailscale status &>/dev/null; then
        local ts_ip
        ts_ip=$(get_tailscale_ip)
        print_success "Tailscale connected! Your Tailscale IP: $ts_ip"
    else
        print_warning "Could not verify Tailscale connection. Continuing anyway..."
    fi
}

# ------------------------------------------------------------------------------
# Step 5: VPN Exit Node & Networking Configuration
# ------------------------------------------------------------------------------
configure_networking() {
    print_step "5" "VPN EXIT NODE & NETWORKING CONFIGURATION"
    
    print_infobox "What is an Exit Node?" \
        "An Exit Node lets you route ALL your internet traffic through this server." \
        "" \
        "Use case example:" \
        "  • You're at a coffee shop with sketchy WiFi" \
        "  • Enable this server as your exit node" \
        "  • Now ALL your traffic is encrypted and goes through your home" \
        "  • Websites see your home IP, not the coffee shop's" \
        "" \
        "We'll configure the network settings to enable this feature."
    
    # Enable IP Forwarding
    print_info "Enabling IP forwarding..."
    local sysctl_conf="/etc/sysctl.d/99-tailscale.conf"
    
    # Create or update the sysctl config
    cat > "$sysctl_conf" << 'EOF'
# Tailscale Exit Node Configuration
# Enable IPv4 forwarding
net.ipv4.ip_forward = 1

# Enable IPv6 forwarding
net.ipv6.conf.all.forwarding = 1
EOF
    
    # Apply the settings
    if sysctl -p "$sysctl_conf" >> "$ACTIVE_LOG_FILE" 2>&1; then
        print_success "IP forwarding enabled."
    else
        print_warning "Could not apply sysctl settings. You may need to reboot."
    fi
    
    # Configure UFW Firewall
    print_info "Configuring firewall (UFW)..."
    
    # Install UFW if not present
    if ! command_exists ufw; then
        apt-get install -y ufw >> "$ACTIVE_LOG_FILE" 2>&1
    fi
    
    # Allow SSH
    print_info "Allowing SSH connections..."
    ufw allow ssh >> "$ACTIVE_LOG_FILE" 2>&1
    print_success "SSH allowed through firewall."
    
    # Allow Tailscale interface
    print_info "Allowing Tailscale interface..."
    ufw allow in on tailscale0 >> "$ACTIVE_LOG_FILE" 2>&1
    print_success "Tailscale interface allowed."
    
    # Enable and reload UFW
    ufw --force enable >> "$ACTIVE_LOG_FILE" 2>&1
    ufw reload >> "$ACTIVE_LOG_FILE" 2>&1
    print_success "Firewall configured and active."
    
    # Advertise as Exit Node with SSH
    print_info "Advertising this machine as a Tailscale Exit Node..."
    echo ""
    
    if tailscale up --advertise-exit-node --ssh; then
        print_success "Exit node advertisement configured!"
    else
        print_warning "Exit node configuration may have issues. Check Tailscale admin."
    fi
    
    print_action_required "APPROVE EXIT NODE IN TAILSCALE ADMIN" \
        "You must complete these steps in your browser:" \
        "" \
        "1. Go to: ${BOLD}https://login.tailscale.com/admin/machines${NC}" \
        "2. Find this machine in the list" \
        "3. Click the '...' menu → 'Edit route settings'" \
        "4. Toggle ON: '${BOLD}Use as exit node${NC}'" \
        "5. Click '${BOLD}Disable key expiry${NC}' to prevent 90-day lockout" \
        "" \
        "${YELLOW}⚠ IMPORTANT: Disabling key expiry prevents your server from${NC}" \
        "${YELLOW}  going offline every 90 days requiring re-authentication!${NC}"
    
    pause_for_user "Press [Enter] AFTER you have approved the exit node and disabled key expiry..."
    
    print_success "Networking configuration complete!"
}

# ------------------------------------------------------------------------------
# Step 6: Remote Access Information (SSH/SFTP)
# ------------------------------------------------------------------------------
show_remote_access_info() {
    print_step "6" "REMOTE ACCESS INFORMATION"
    
    local ts_ip
    ts_ip=$(get_tailscale_ip)
    
    print_infobox "SSH & SFTP Access" \
        "Your server is now accessible remotely via Tailscale!" \
        "" \
        "${BOLD}SSH (Command Line Access):${NC}" \
        "  From any device on your Tailscale network, run:" \
        "  ${CYAN}ssh ${ACTUAL_USER}@${ts_ip}${NC}" \
        "" \
        "${BOLD}SFTP (File Transfer via File Manager):${NC}" \
        "  In your file manager (Nautilus, Dolphin, Thunar), go to:" \
        "  ${CYAN}sftp://${ACTUAL_USER}@${ts_ip}${NC}" \
        "" \
        "${BOLD}SFTP (File Transfer via Command Line):${NC}" \
        "  ${CYAN}sftp ${ACTUAL_USER}@${ts_ip}${NC}"
    
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠️  ${BOLD}IMPORTANT PASSWORD REMINDER${NC}                                             ${RED}║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}║${NC}  When connecting via SSH or SFTP, use your ${BOLD}LINUX MINT PASSWORD${NC}            ${RED}║${NC}"
    echo -e "${RED}║${NC}  (the password you use to log into this computer)                           ${RED}║${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}║${NC}  ${DIM}NOT your Tailscale account password!${NC}                                     ${RED}║${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    pause_for_user "Press [Enter] to continue..."
}

# ------------------------------------------------------------------------------
# Step 7: Power Management Guide
# ------------------------------------------------------------------------------
show_power_management_guide() {
    print_step "7" "POWER MANAGEMENT CONFIGURATION"
    
    print_infobox "Why Configure Power Management?" \
        "Since this laptop will run as a server, you don't want it to:" \
        "  • Go to sleep when you close the lid" \
        "  • Suspend after being idle" \
        "  • Turn off unexpectedly" \
        "" \
        "This is a GUI setting that must be configured manually."
    
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  📋 ${BOLD}MANUAL CONFIGURATION REQUIRED${NC}                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}                                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Please follow these steps to prevent the laptop from sleeping:             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  1. Click the ${BOLD}Applications Menu${NC} (bottom-left corner)                      ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  2. Search for and open: ${BOLD}Power Manager${NC}                                    ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  3. Go to the ${BOLD}System${NC} tab                                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  4. Find '${BOLD}When laptop lid is closed${NC}'                                      ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  5. Change it to: ${BOLD}Switch off display${NC} (NOT suspend or hibernate)          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  6. Apply for BOTH 'On Battery' and 'Plugged In'                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${DIM}Tip: You can also disable auto-sleep in the 'Display' and 'System' tabs${NC} ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Additional laptop care tips
    print_infobox "💡 Laptop-as-Server Tips" \
        "Since you're using a laptop as a server:" \
        "" \
        "  • ${BOLD}Battery Care:${NC} If possible, remove the battery or set a charge" \
        "    limit in BIOS to 60-80% to prevent swelling over time." \
        "" \
        "  • ${BOLD}Ventilation:${NC} Keep the laptop open slightly or use a stand" \
        "    to ensure proper airflow. Don't block the vents!" \
        "" \
        "  • ${BOLD}Dust:${NC} Clean the vents periodically to prevent overheating."
    
    pause_for_user "Press [Enter] after configuring power management (or to configure later)..."
}

# ------------------------------------------------------------------------------
# Step 8: Jellyfin Media Server Preparation
# ------------------------------------------------------------------------------
prepare_jellyfin() {
    print_step "8" "JELLYFIN MEDIA SERVER PREPARATION"
    
    print_infobox "What is Jellyfin?" \
        "Jellyfin is a free, open-source media server (like Netflix for YOUR content!)" \
        "" \
        "Features:" \
        "  • Stream your movies and TV shows to any device" \
        "  • Beautiful interface with movie posters and info" \
        "  • Works on phones, tablets, smart TVs, web browsers" \
        "  • No subscriptions, no fees - completely free!" \
        "" \
        "We'll prepare the folder structure for your media files."
    
    # Create directory structure
    print_info "Creating media directory structure..."
    
    mkdir -p "${MEDIA_ROOT}/Movies"
    mkdir -p "${MEDIA_ROOT}/Shows"
    
    print_success "Created: ${MEDIA_ROOT}/Movies"
    print_success "Created: ${MEDIA_ROOT}/Shows"
    
    # Set permissions
    print_info "Setting permissions for media directories..."
    
    # Set ownership to the actual user
    chown -R "${ACTUAL_USER}:${ACTUAL_USER}" "/DATA"
    
    # Set permissions (775 = owner/group can read/write/execute, others can read/execute)
    chmod -R 775 "/DATA"
    
    print_success "Permissions configured (Owner: ${ACTUAL_USER})"
    
    # Display Jellyfin installation instructions
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  📺 ${BOLD}JELLYFIN INSTALLATION INSTRUCTIONS${NC}                                       ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}                                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  To install Jellyfin:                                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  1. Open CasaOS in your browser: ${BOLD}http://$(get_lan_ip)${NC}             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  2. Click on the ${BOLD}App Store${NC} icon                                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  3. Search for '${BOLD}Jellyfin${NC}'                                                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  4. Click ${BOLD}Install${NC}                                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  5. Wait for installation to complete                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠️  ${BOLD}CRITICAL: JELLYFIN PORT NUMBER${NC}                                           ${RED}║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}║${NC}  When accessing Jellyfin, your port will be:  ${BOLD}8097${NC}                         ${RED}║${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}║${NC}  ${DIM}This is different from the default port 8096 mentioned in most guides.${NC}   ${RED}║${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}║${NC}  Jellyfin URL: ${BOLD}http://$(get_lan_ip):8097${NC}                            ${RED}║${NC}"
    echo -e "${RED}║${NC}  Remote URL:   ${BOLD}http://$(get_tailscale_ip):8097${NC}                              ${RED}║${NC}"
    echo -e "${RED}║${NC}                                                                              ${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_infobox "📁 Where to Put Your Media Files" \
        "Copy your media files to these locations:" \
        "" \
        "  Movies: ${BOLD}${MEDIA_ROOT}/Movies/${NC}" \
        "    Example: ${MEDIA_ROOT}/Movies/Inception (2010)/Inception.mkv" \
        "" \
        "  TV Shows: ${BOLD}${MEDIA_ROOT}/Shows/${NC}" \
        "    Example: ${MEDIA_ROOT}/Shows/Breaking Bad/Season 1/S01E01.mkv" \
        "" \
        "  ${DIM}Tip: Jellyfin works best when files are organized in folders!${NC}"
    
    # PUID/PGID information for Jellyfin
    print_infobox "🔧 Advanced: Jellyfin Container Settings" \
        "If Jellyfin has permission issues, set these in CasaOS:" \
        "" \
        "  1. Click on Jellyfin app → Settings → Variables" \
        "  2. Add these environment variables:" \
        "     ${BOLD}PUID = ${ACTUAL_USER_UID}${NC}" \
        "     ${BOLD}PGID = ${ACTUAL_USER_GID}${NC}" \
        "" \
        "  This ensures Jellyfin can read your media files."
    
    pause_for_user "Press [Enter] to continue to the final summary..."
}

# ------------------------------------------------------------------------------
# Final Summary
# ------------------------------------------------------------------------------
show_final_summary() {
    local lan_ip
    local ts_ip
    lan_ip=$(get_lan_ip)
    ts_ip=$(get_tailscale_ip)
    
    clear
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                              ║${NC}"
    echo -e "${GREEN}║    🎉  ${BOLD}CONGRATULATIONS! YOUR HOMELAB SETUP IS COMPLETE!${NC}  🎉               ${GREEN}║${NC}"
    echo -e "${GREEN}║                                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  📊 YOUR SERVER INFORMATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Local Access (Home Network):${NC}"
    echo -e "    • CasaOS Dashboard:  ${CYAN}http://${lan_ip}${NC}"
    echo -e "    • Jellyfin:          ${CYAN}http://${lan_ip}:8097${NC}"
    echo ""
    echo -e "  ${BOLD}Remote Access (Via Tailscale):${NC}"
    echo -e "    • CasaOS Dashboard:  ${CYAN}http://${ts_ip}${NC}"
    echo -e "    • Jellyfin:          ${CYAN}http://${ts_ip}:8097${NC}"
    echo -e "    • SSH:               ${CYAN}ssh ${ACTUAL_USER}@${ts_ip}${NC}"
    echo -e "    • SFTP:              ${CYAN}sftp://${ACTUAL_USER}@${ts_ip}${NC}"
    echo ""
    echo -e "  ${BOLD}Media Directories:${NC}"
    echo -e "    • Movies:            ${CYAN}${MEDIA_ROOT}/Movies/${NC}"
    echo -e "    • TV Shows:          ${CYAN}${MEDIA_ROOT}/Shows/${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  📝 QUICK REFERENCE${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Passwords:${NC}"
    echo -e "    • SSH/SFTP: Use your ${YELLOW}Linux Mint login password${NC}"
    echo -e "    • CasaOS:   Use the password you created during setup"
    echo ""
    echo -e "  ${BOLD}Next Steps:${NC}"
    echo -e "    1. Install Jellyfin from CasaOS App Store"
    echo -e "    2. Configure Power Manager (Step 7)"
    echo -e "    3. Copy your media files to ${MEDIA_ROOT}/"
    echo -e "    4. Set up Jellyfin libraries pointing to your media"
    echo ""
    echo -e "  ${BOLD}Tailscale Admin Console:${NC}"
    echo -e "    ${CYAN}https://login.tailscale.com/admin/machines${NC}"
    echo ""
    echo -e "  ${BOLD}Log File:${NC}"
    echo -e "    ${DIM}${ACTIVE_LOG_FILE}${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${GREEN}  Thank you for using the HomeLab Setup Script! 🏠${NC}"
    echo -e "${DIM}  Version ${SCRIPT_VERSION}${NC}"
    echo ""
}

# ==============================================================================
# MAIN SCRIPT EXECUTION
# ==============================================================================

main() {
    # Display welcome banner
    clear
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}             ${BOLD}Linux Mint → Home Lab Server Setup Script${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                           ${DIM}Version ${SCRIPT_VERSION}${NC}                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}  This script will transform your Linux Mint laptop into a:${NC}"
    echo -e "    ${GREEN}✓${NC} NAS (Network Attached Storage)"
    echo -e "    ${GREEN}✓${NC} VPN Exit Node (secure remote access)"
    echo -e "    ${GREEN}✓${NC} Media Server (stream movies & TV shows)"
    echo ""
    echo -e "${DIM}  The setup is interactive and will guide you through each step.${NC}"
    echo -e "${DIM}  You'll need to perform some actions in your web browser along the way.${NC}"
    echo ""
    
    # Check for root privileges first
    check_root_privileges
    
    print_info "Detected user: ${ACTUAL_USER} (UID: ${ACTUAL_USER_UID}, GID: ${ACTUAL_USER_GID})"
    print_info "Log file: ${ACTIVE_LOG_FILE}"
    echo ""
    
    pause_for_user "Press [Enter] to begin the setup..."
    
    # Execute all steps in order
    preflight_check
    system_prep
    install_casaos
    install_tailscale
    configure_networking
    show_remote_access_info
    show_power_management_guide
    prepare_jellyfin
    show_final_summary
}

# Run the script
main "$@"
