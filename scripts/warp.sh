#!/bin/bash

#===================
# WARP-WGCF MANAGER
#===================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

readonly LOG_FILE="/root/warp-output.txt"

readonly CHECK="✓"
readonly CROSS="✗"
readonly WARNING="!"
readonly INFO="*"
readonly ARROW="→"

error_exit() {
    echo -e "${RED}${CROSS}${NC} $1"
    SHOW_LOG_HINT=1
    exit 1
}

ok() {
    echo -e "${GREEN}${CHECK}${NC} $1"
}

warn() {
    echo -e "${YELLOW}${WARNING}${NC} $1"
}

info() {
    echo -e "${CYAN}${INFO}${NC} $1"
}

#====================
# UNINSTALL FUNCTION
#====================

perform_uninstall() {
    echo
    echo -e "${PURPLE}====================${NC}"
    echo -e "${WHITE}WARP Uninstallation${NC}"
    echo -e "${PURPLE}====================${NC}"
    echo

    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    if [ ! -f "/usr/local/bin/wgcf" ] && [ ! -f "/etc/wireguard/warp.conf" ]; then
        warn "WARP is not installed on this system."
        echo
        exit 0
    fi

    echo -ne "${YELLOW}Are you sure you want to continue? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        exit 0
    fi

    echo
    info "Stopping WARP service..."
    echo -e "${GRAY}  ${ARROW}${NC} Stopping wg-quick@warp"
    systemctl stop wg-quick@warp 2>/dev/null
    echo -e "${GRAY}  ${ARROW}${NC} Disabling autostart"
    systemctl disable wg-quick@warp 2>/dev/null
    ok "Service stopped and disabled"

    echo
    info "Removing configuration files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing /etc/wireguard/warp.conf"
    rm -f /etc/wireguard/warp.conf
    echo -e "${GRAY}  ${ARROW}${NC} Removing wgcf binary"
    rm -f /usr/local/bin/wgcf
    echo -e "${GRAY}  ${ARROW}${NC} Removing account files"
    rm -f ~/wgcf-account.toml ~/wgcf-profile.conf
    echo -e "${GRAY}  ${ARROW}${NC} Removing log file"
    rm -f "$LOG_FILE"
    ok "Configuration files removed"

    echo
    info "Removing WireGuard packages..."
    echo -e "${GRAY}  ${ARROW}${NC} Uninstalling wireguard and wireguard-tools"
    apt-get remove -y wireguard wireguard-tools >/dev/null 2>&1
    ok "WireGuard packages removed"

    echo
    echo -e "${PURPLE}===========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Uninstallation complete!"
    echo -e "${PURPLE}===========================${NC}"
    echo
    exit 0
}

#========================
# INSTALLATION FUNCTIONS
#========================

prepare_system() {
    echo -e "${GREEN}System Preparation${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    export DEBIAN_FRONTEND=noninteractive

    info "Updating package list and installing dependencies..."
    echo -e "${GRAY}  ${ARROW}${NC} Updating package repositories"
    apt-get update -qq >> "$LOG_FILE" 2>&1 || error_exit "Failed to update package list"
    
    echo -e "${GRAY}  ${ARROW}${NC} Installing WireGuard and tools"
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        wireguard wireguard-tools curl wget >> "$LOG_FILE" 2>&1 || error_exit "Failed to install WireGuard"
    
    ok "Dependencies installed successfully"
    echo
}

setup_temp_dns() {
    echo -e "${GREEN}DNS Configuration${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    info "Setting temporary DNS servers..."
    echo -e "${GRAY}  ${ARROW}${NC} Backing up current DNS configuration"
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null
    echo -e "${GRAY}  ${ARROW}${NC} Setting DNS to 1.1.1.1 and 8.8.8.8"
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
    ok "Temporary DNS configured"
    echo
}

restore_dns() {
    if [ -f /etc/resolv.conf.backup ]; then
        echo
        info "Restoring original DNS configuration..."
        echo -e "${GRAY}  ${ARROW}${NC} Restoring from backup"
        cp /etc/resolv.conf.backup /etc/resolv.conf
        rm -f /etc/resolv.conf.backup
        ok "DNS configuration restored"
        echo
    fi
}

cleanup_on_exit() {
    restore_dns
    if [ -n "$SHOW_LOG_HINT" ] && [ -f "$LOG_FILE" ]; then
        echo -e "${WHITE}View log for details:${NC}"
        echo -e "${WHITE}cat $LOG_FILE${NC}"
        echo
    fi
}

trap cleanup_on_exit EXIT

install_wgcf() {
    echo -e "${GREEN}wgcf Installation${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    info "Downloading and installing wgcf..."
    
    echo -e "${GRAY}  ${ARROW}${NC} Getting latest version from GitHub"
    WGCF_RELEASE_URL="https://api.github.com/repos/ViRb3/wgcf/releases/latest"
    WGCF_VERSION=$(curl -s "$WGCF_RELEASE_URL" | grep tag_name | cut -d '"' -f 4)
    
    if [ -z "$WGCF_VERSION" ]; then
        error_exit "Failed to get wgcf version"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Detecting system architecture"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) WGCF_ARCH="amd64" ;;
        aarch64|arm64) WGCF_ARCH="arm64" ;;
        armv7l) WGCF_ARCH="armv7" ;;
        *) WGCF_ARCH="amd64" ;;
    esac
    echo -e "${GRAY}  ${ARROW}${NC} Architecture: $ARCH -> $WGCF_ARCH"
    
    WGCF_URL="https://github.com/ViRb3/wgcf/releases/download/${WGCF_VERSION}/wgcf_${WGCF_VERSION#v}_linux_${WGCF_ARCH}"
    WGCF_BINARY="wgcf_${WGCF_VERSION#v}_linux_${WGCF_ARCH}"
    
    echo -e "${GRAY}  ${ARROW}${NC} Downloading wgcf $WGCF_VERSION"
    wget -q "$WGCF_URL" -O "$WGCF_BINARY" || error_exit "Failed to download wgcf"
    echo -e "${GRAY}  ${ARROW}${NC} Making binary executable"
    chmod +x "$WGCF_BINARY" || error_exit "Failed to make wgcf executable"
    echo -e "${GRAY}  ${ARROW}${NC} Installing to /usr/local/bin/wgcf"
    mv "$WGCF_BINARY" /usr/local/bin/wgcf || error_exit "Failed to install wgcf"
    
    ok "wgcf $WGCF_VERSION installed successfully"
    echo
}

register_warp() {
    echo -e "${GREEN}WARP Registration${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    cd ~ || exit 1

    if [ -f wgcf-account.toml ]; then
        info "Checking existing account..."
        echo -e "${GRAY}  ${ARROW}${NC} Account file already exists"
        ok "Using existing WARP account"
    else
        info "Registering new WARP account..."
        
        echo -e "${GRAY}  ${ARROW}${NC} Checking wgcf binary"
        if ! wgcf --help &>/dev/null; then
            chmod +x /usr/local/bin/wgcf
        fi
        
        echo -e "${GRAY}  ${ARROW}${NC} Contacting Cloudflare WARP API"
        output=$(timeout 60 bash -c 'yes | wgcf register' 2>&1)
        ret=$?
        echo "$output" >> "$LOG_FILE"
        
        if [[ $ret -ne 0 ]]; then
            if [[ "$output" == *"429 Too Many Requests"* ]]; then
                error_exit "Cloudflare rate limit, try again later"
            fi
            error_exit "Registration failed (exit code $ret)"
        fi
        
        if [ ! -f wgcf-account.toml ]; then
            error_exit "Failed to create wgcf-account.toml"
        fi
        
        ok "WARP account registered successfully"
    fi

    echo
    info "Generating WARP configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Running wgcf generate"
    wgcf generate >> "$LOG_FILE" 2>&1 || error_exit "Failed to generate config"
    ok "Configuration generated successfully"
    echo
}

create_warp_config() {
    echo -e "${GREEN}Configuration Setup${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    cd ~ || exit 1

    WGCF_CONF="wgcf-profile.conf"
    
    if [ ! -f "$WGCF_CONF" ]; then
        error_exit "Configuration file not found"
    fi

    info "Editing WARP configuration..."
    
    echo -e "${GRAY}  ${ARROW}${NC} Removing DNS settings"
    sed -i '/^DNS =/d' "$WGCF_CONF" || error_exit "Failed to remove DNS"
    
    echo -e "${GRAY}  ${ARROW}${NC} Adding Table = off"
    if ! grep -q "Table = off" "$WGCF_CONF"; then
        sed -i '/^MTU =/aTable = off' "$WGCF_CONF"
    fi
    
    echo -e "${GRAY}  ${ARROW}${NC} Adding PersistentKeepalive = 25"
    if ! grep -q "PersistentKeepalive = 25" "$WGCF_CONF"; then
        sed -i '/^Endpoint =/aPersistentKeepalive = 25' "$WGCF_CONF"
    fi
    
    ok "Configuration edited successfully"

    echo
    info "Checking IPv6 support..."
    
    echo -e "${GRAY}  ${ARROW}${NC} Checking system IPv6 settings"
    if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q ' = 0' && \
       sysctl net.ipv6.conf.default.disable_ipv6 2>/dev/null | grep -q ' = 0' && \
       ip -6 addr show scope global 2>/dev/null | grep -qv 'inet6 .*fe80::'; then
        echo -e "${GRAY}  ${ARROW}${NC} IPv6 is enabled, keeping IPv6 addresses in config"
        ok "IPv6 support confirmed"
    else
        echo -e "${GRAY}  ${ARROW}${NC} IPv6 is disabled, removing IPv6 addresses from config"
        sed -i 's/,\s*[0-9a-fA-F:]\+\/128//' "$WGCF_CONF"
        sed -i '/Address = [0-9a-fA-F:]\+\/128/d' "$WGCF_CONF"
        ok "Configuration adjusted for IPv4 only"
    fi

    echo
    info "Installing WARP configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating /etc/wireguard directory"
    mkdir -p /etc/wireguard
    echo -e "${GRAY}  ${ARROW}${NC} Moving configuration to /etc/wireguard/warp.conf"
    mv "$WGCF_CONF" /etc/wireguard/warp.conf || error_exit "Failed to move config"
    ok "Configuration installed successfully"
    echo
}

start_warp() {
    echo -e "${GREEN}Starting WARP${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    info "Starting WARP interface..."
    echo -e "${GRAY}  ${ARROW}${NC} Running systemctl start wg-quick@warp"
    systemctl start wg-quick@warp || error_exit "Failed to start WARP"
    ok "WARP interface started successfully"

    echo
    info "Verifying WARP connection..."
    
    local handshake_ok=false
    echo -e "${GRAY}  ${ARROW}${NC} Waiting for WireGuard handshake"
    for i in {1..10}; do
        if wg show warp &>/dev/null; then
            handshake=$(wg show warp 2>/dev/null | grep "latest handshake" | awk -F': ' '{print $2}')
            if [[ "$handshake" == *"second"* || "$handshake" == *"minute"* ]]; then
                echo -e "${GRAY}  ${ARROW}${NC} Handshake received: $handshake"
                ok "WARP connection established"
                handshake_ok=true
                break
            fi
        fi
        sleep 1
    done

    if [[ "$handshake_ok" != true ]]; then
        warn "Handshake not received within timeout"
    fi

    echo
    info "Testing connection to Cloudflare..."
    echo -e "${GRAY}  ${ARROW}${NC} Checking WARP status via API"
    sleep 2
    
    curl_result=$(curl -s --max-time 10 --interface warp https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "warp=" | cut -d= -f2)
    
    if [[ "$curl_result" == "plus" ]]; then
        echo -e "${GRAY}  ${ARROW}${NC} Response: warp=plus"
        ok "WARP+ is active!"
    elif [[ "$curl_result" == "on" ]]; then
        echo -e "${GRAY}  ${ARROW}${NC} Response: warp=on"
        ok "WARP connection confirmed"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Response: $curl_result"
        warn "Could not confirm WARP status via API, but interface is working"
    fi

    echo
    info "Enabling autostart on boot..."
    echo -e "${GRAY}  ${ARROW}${NC} Running systemctl enable wg-quick@warp"
    systemctl enable wg-quick@warp &>/dev/null || error_exit "Failed to enable autostart"
    ok "Autostart enabled successfully"
}

display_completion_info() {
    echo -e "${PURPLE}=========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete!"
    echo -e "${PURPLE}=========================${NC}"
    echo
    echo -e "${CYAN}WARP Interface:${NC} ${WHITE}warp${NC}"
    echo
    echo -e "${CYAN}Management Commands:${NC}"
    echo -e "${WHITE}• systemctl status wg-quick@warp  ${GRAY}- Check status${NC}"
    echo -e "${WHITE}• systemctl stop wg-quick@warp    ${GRAY}- Stop WARP${NC}"
    echo -e "${WHITE}• systemctl start wg-quick@warp   ${GRAY}- Start WARP${NC}"
    echo -e "${WHITE}• systemctl restart wg-quick@warp ${GRAY}- Restart WARP${NC}"
    echo -e "${WHITE}• wg show warp                    ${GRAY}- Show interface info${NC}"
    echo
    echo -e "${CYAN}Test Commands:${NC}"
    echo -e "${WHITE}• curl --interface warp https://ipinfo.io${NC}"
    echo -e "${WHITE}• curl --interface warp https://www.cloudflare.com/cdn-cgi/trace${NC}"
    echo
}

is_installed() {
    [ -f "/etc/wireguard/warp.conf" ]
}

#=================
# STATUS FUNCTION
#=================

show_status() {
    echo
    echo -e "${PURPLE}============${NC}"
    echo -e "${WHITE}WARP Status${NC}"
    echo -e "${PURPLE}============${NC}"
    echo

    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    if systemctl is-active wg-quick@warp &>/dev/null; then
        ok "Service is running"
    else
        warn "Service is not running"
    fi

    echo
    info "Interface details..."
    wg show warp 2>/dev/null || echo -e "${GRAY}  No interface data${NC}"

    echo
    info "Checking IP via WARP..."
    local ip_info
    ip_info=$(curl -s --max-time 10 --interface warp https://ipinfo.io 2>/dev/null)
    if [ -n "$ip_info" ]; then
        local ip country city
        ip=$(echo "$ip_info" | grep '"ip"' | cut -d'"' -f4)
        country=$(echo "$ip_info" | grep '"country"' | cut -d'"' -f4)
        city=$(echo "$ip_info" | grep '"city"' | cut -d'"' -f4)
        echo -e "${GRAY}  ${ARROW}${NC} IP: ${WHITE}$ip${NC} — $city, $country"
    else
        warn "Could not reach ipinfo.io via WARP"
    fi

    echo
    info "Checking WARP status via Cloudflare..."
    local warp_status
    warp_status=$(curl -s --max-time 10 --interface warp https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "warp=" | cut -d= -f2)
    if [[ "$warp_status" == "plus" ]]; then
        ok "WARP+ is active"
    elif [[ "$warp_status" == "on" ]]; then
        ok "WARP is active"
    else
        warn "Could not confirm WARP status"
    fi
    echo
}

#================
# MENU FUNCTIONS
#================

show_main_menu() {
    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${WHITE}WARP-WGCF MANAGER${NC}"
    echo -e "${PURPLE}==================${NC}"
    echo
    echo -e "${CYAN}Please select an action:${NC}"
    echo

    if is_installed; then
        echo -e "${GREEN}1.${NC} Status"
        echo -e "${YELLOW}2.${NC} Uninstall"
        echo -e "${RED}3.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Install"
        echo -e "${RED}2.${NC} Exit"
    fi
    echo
}

handle_user_choice() {
    if is_installed; then
        while true; do
            echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
            read CHOICE
            case $CHOICE in
                1)
                    ACTION="status"
                    break
                    ;;
                2)
                    ACTION="uninstall"
                    break
                    ;;
                3)
                    echo -e "${CYAN}Goodbye!${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${RED}${CROSS}${NC} Invalid choice. Please enter 1, 2, or 3."
                    ;;
            esac
        done
    else
        while true; do
            echo -ne "${CYAN}Enter your choice (1-2): ${NC}"
            read CHOICE
            case $CHOICE in
                1)
                    ACTION="install"
                    break
                    ;;
                2)
                    echo -e "${CYAN}Goodbye!${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${RED}${CROSS}${NC} Invalid choice. Please enter 1 or 2."
                    ;;
            esac
        done
    fi
}

#================
# MAIN FUNCTIONS
#================

perform_installation() {
    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${WHITE}WARP Installation${NC}"
    echo -e "${PURPLE}==================${NC}"
    echo

    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    if [ -f "/etc/wireguard/warp.conf" ]; then
        warn "WARP appears to be already installed."
        echo
        echo -ne "${YELLOW}Do you want to reinstall? (y/N): ${NC}"
        read -r REINSTALL
        
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}Installation cancelled.${NC}"
            exit 0
        fi
        
        echo
        info "Stopping existing WARP installation..."
        echo -e "${GRAY}  ${ARROW}${NC} Stopping wg-quick@warp service"
        systemctl stop wg-quick@warp 2>/dev/null
        ok "Existing installation stopped"
        echo
    fi

    echo "WARP install log — $(date)" > "$LOG_FILE"

    prepare_system
    setup_temp_dns
    install_wgcf
    register_warp
    create_warp_config
    start_warp
    restore_dns
    display_completion_info
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    if [ "$1" = "uninstall" ] || [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
        ACTION="uninstall"
    elif [ "$1" = "install" ] || [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
        ACTION="install"
    elif [ "$1" = "status" ] || [ "$1" = "--status" ] || [ "$1" = "-s" ]; then
        ACTION="status"
    else
        show_main_menu
        handle_user_choice
    fi

    if [ "$ACTION" = "uninstall" ]; then
        perform_uninstall
    elif [ "$ACTION" = "status" ]; then
        show_status
    else
        perform_installation
    fi
}

main "$@"
exit 0
