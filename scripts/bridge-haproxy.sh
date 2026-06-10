#!/bin/bash

#==============================
# REMNAWAVE BRIDGE PROXY SETUP
#==============================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

readonly CHECK="✓"
readonly CROSS="✗"
readonly WARNING="!"
readonly INFO="*"
readonly ARROW="→"

DIR_BRIDGE="/usr/local/remnawave_bridge/"
NODES_FILE="${DIR_BRIDGE}nodes.conf"

#======================
# VALIDATION FUNCTIONS
#======================

validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$domain" =~ [[:space:]] ]]; then
        return 0
    fi
    return 1
}

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

#========================
# SYSTEM CHECK FUNCTIONS
#========================

error() {
    echo -e "${RED}${CROSS}${NC} $1"
    exit 1
}

log_entry() {
    mkdir -p ${DIR_BRIDGE}
    LOGFILE="${DIR_BRIDGE}rm-bridge-setup.log"
    exec > >(tee -a "$LOGFILE") 2>&1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script must be run as root"
    fi
}

install_system_packages() {
    echo -e "${CYAN}${INFO}${NC} Installing system packages..."

    echo -e "${GRAY}  ${ARROW}${NC} Updating package lists"
    if ! apt-get update -y > /dev/null 2>&1; then
        error "Failed to update package list"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing essential packages"
    if ! apt-get install -y ca-certificates curl ufw haproxy unattended-upgrades > /dev/null 2>&1; then
        error "Failed to install required packages"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring TCP optimizations (BBR)"
    if ! grep -qE '^\s*net\.core\.default_qdisc\s*=\s*fq' /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi
    if ! grep -qE '^\s*net\.ipv4\.tcp_congestion_control\s*=\s*bbr' /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    fi
    if ! grep -qE '^\s*net\.core\.somaxconn\s*=' /etc/sysctl.conf; then
        echo "net.core.somaxconn = 8192" >> /etc/sysctl.conf
    fi
    if ! grep -qE '^\s*net\.ipv4\.tcp_max_syn_backlog\s*=' /etc/sysctl.conf; then
        echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null

    echo -e "${GRAY}  ${ARROW}${NC} Configuring UFW firewall"
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1

    echo -e "${GRAY}  ${ARROW}${NC} Configuring automatic security updates"
    echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades > /dev/null 2>&1
    systemctl restart unattended-upgrades > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} System packages configured"
}

#=====================
# MAIN MENU FUNCTIONS
#=====================

show_main_menu() {
    HAPROXY_INSTALLED=false
    command -v haproxy > /dev/null 2>&1 && HAPROXY_INSTALLED=true

    echo
    echo -e "${PURPLE}======================${NC}"
    echo -e "${WHITE}REMNAWAVE BRIDGE${NC}"
    echo -e "${PURPLE}======================${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    if [ "$HAPROXY_INSTALLED" = true ]; then
        echo -e "${GREEN}1.${NC} Add node"
        echo -e "${RED}2.${NC} Remove node"
        echo -e "${RED}3.${NC} Remove bridge"
        echo -e "${YELLOW}4.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Setup bridge"
        echo -e "${YELLOW}2.${NC} Exit"
    fi
    echo
    echo -ne "${CYAN}Enter your choice: ${NC}"
}

#=================
# INPUT FUNCTIONS
#=================

input_bridge_domain() {
    echo -ne "${CYAN}Bridge domain (e.g., bridge.example.com): ${NC}"
    read BRIDGE_DOMAIN
    while [[ -z "$BRIDGE_DOMAIN" ]] || ! validate_domain "$BRIDGE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain (e.g., bridge.example.com)."
        echo
        echo -ne "${CYAN}Bridge domain: ${NC}"
        read BRIDGE_DOMAIN
    done
}

input_node_ip() {
    echo -ne "${CYAN}Node IP address: ${NC}"
    read NODE_IP
    while [[ -z "$NODE_IP" ]] || ! validate_ip "$NODE_IP"; do
        echo -e "${RED}${CROSS}${NC} Invalid IP! Please enter a valid IPv4 address (e.g., 1.2.3.4)."
        echo
        echo -ne "${CYAN}Node IP address: ${NC}"
        read NODE_IP
    done
}

#==================
# HAPROXY FUNCTIONS
#==================

generate_haproxy_config() {
    {
        cat <<'EOF'
global
    log /dev/log local0
    maxconn 50000

defaults
    log global
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend main_front
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content set-var(sess.ssl_sni) req.ssl_sni
    tcp-request content accept if { req_ssl_hello_type 1 }
EOF

        while IFS=: read -r domain ip; do
            local backend_name
            backend_name=$(echo "$domain" | sed 's/[.-]/_/g')
            echo "    use_backend ${backend_name}_backend if { req.ssl_sni -i ${domain} }"
        done < "$NODES_FILE"

        while IFS=: read -r domain ip; do
            local backend_name
            backend_name=$(echo "$domain" | sed 's/[.-]/_/g')
            printf '\nbackend %s_backend\n    server node %s:443\n' "$backend_name" "$ip"
        done < "$NODES_FILE"
    } > /etc/haproxy/haproxy.cfg
}

reload_haproxy() {
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg > /dev/null 2>&1; then
        error "HAProxy configuration validation failed"
    fi
    if ! systemctl restart haproxy > /dev/null 2>&1; then
        error "Failed to restart HAProxy"
    fi
}

#======================
# MAIN ENTRY FUNCTIONS
#======================

install_bridge() {
    set -e

    echo
    echo -e "${GREEN}Installing packages${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    install_system_packages

    echo
    echo -e "${GREEN}Configuring bridge${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Configuring HAProxy..."

    echo "${BRIDGE_DOMAIN}:${NODE_IP}" > "$NODES_FILE"

    echo -e "${GRAY}  ${ARROW}${NC} Writing configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Validating configuration"
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg > /dev/null 2>&1; then
        error "HAProxy configuration validation failed"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Enabling and starting HAProxy"
    systemctl enable haproxy > /dev/null 2>&1
    if ! systemctl restart haproxy > /dev/null 2>&1; then
        error "Failed to start HAProxy"
    fi

    echo -e "${GREEN}${CHECK}${NC} HAProxy configured"

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    local server_ip
    server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}• Update the A record of ${BRIDGE_DOMAIN} to point to ${server_ip}${NC}"
    echo -e "${WHITE}• In Remnawave, update the node host to use ${BRIDGE_DOMAIN}${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check status: systemctl status haproxy${NC}"
    echo -e "${WHITE}• Check logs: journalctl -u haproxy -f${NC}"
    echo -e "${WHITE}• Restart service: systemctl restart haproxy${NC}"
    echo
}

add_node() {
    echo
    echo -e "${PURPLE}=============${NC}"
    echo -e "${WHITE}Add Node${NC}"
    echo -e "${PURPLE}=============${NC}"
    echo

    input_bridge_domain
    input_node_ip

    local escaped_domain
    escaped_domain=$(printf '%s' "$BRIDGE_DOMAIN" | sed 's/[.[\*^$]/\\&/g')
    if grep -q "^${escaped_domain}:" "$NODES_FILE" 2>/dev/null; then
        error "Domain ${BRIDGE_DOMAIN} is already configured"
    fi

    echo -e "${CYAN}${INFO}${NC} Adding node..."

    echo "${BRIDGE_DOMAIN}:${NODE_IP}" >> "$NODES_FILE"

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} Node added"

    echo
    local server_ip
    server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}• Update the A record of ${BRIDGE_DOMAIN} to point to ${server_ip}${NC}"
    echo -e "${WHITE}• In Remnawave, update the node host to use ${BRIDGE_DOMAIN}${NC}"
    echo
}

remove_node() {
    if [ ! -f "$NODES_FILE" ] || [ ! -s "$NODES_FILE" ]; then
        error "No nodes configured"
    fi

    echo
    echo -e "${PURPLE}================${NC}"
    echo -e "${WHITE}Remove Node${NC}"
    echo -e "${PURPLE}================${NC}"
    echo

    echo -e "${CYAN}Configured nodes:${NC}"
    echo
    local i=1
    local domains=()
    while IFS=: read -r domain ip; do
        echo -e "${WHITE}${i}.${NC} ${domain} → ${ip}"
        domains+=("$domain")
        i=$((i + 1))
    done < "$NODES_FILE"
    echo
    echo -ne "${CYAN}Select node to remove (1-${#domains[@]}): ${NC}"
    read selection

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#domains[@]}" ]; then
        error "Invalid selection"
    fi

    local selected_domain="${domains[$((selection - 1))]}"

    echo -e "${CYAN}${INFO}${NC} Removing node ${selected_domain}..."

    local escaped_domain
    escaped_domain=$(printf '%s' "$selected_domain" | sed 's/[.[\*^$]/\\&/g')
    sed -i "/^${escaped_domain}:/d" "$NODES_FILE"

    if [ ! -s "$NODES_FILE" ]; then
        echo -e "${YELLOW}${WARNING}${NC} No nodes remaining, removing bridge"
        remove_bridge
        return
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} Node removed"
    echo
}

remove_bridge() {
    echo
    echo -e "${GREEN}Removing bridge${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Stopping HAProxy..."
    echo -e "${GRAY}  ${ARROW}${NC} Stopping service"
    systemctl stop haproxy > /dev/null 2>&1 || true
    systemctl disable haproxy > /dev/null 2>&1 || true
    echo -e "${GREEN}${CHECK}${NC} HAProxy stopped"

    echo
    echo -e "${CYAN}${INFO}${NC} Removing HAProxy..."
    echo -e "${GRAY}  ${ARROW}${NC} Uninstalling package"
    apt-get purge -y haproxy > /dev/null 2>&1 || true
    echo -e "${GREEN}${CHECK}${NC} HAProxy removed"

    echo
    echo -e "${CYAN}${INFO}${NC} Cleaning up files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing ${DIR_BRIDGE}"
    rm -rf "${DIR_BRIDGE}"
    echo -e "${GREEN}${CHECK}${NC} Files removed"

    echo
    echo -e "${PURPLE}=================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Bridge removed"
    echo -e "${PURPLE}=================${NC}"
    echo
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    check_root

    show_main_menu
    read SETUP_TYPE

    if [ "$HAPROXY_INSTALLED" = true ]; then
        case $SETUP_TYPE in
            1) add_node ;;
            2) remove_node ;;
            3) remove_bridge ;;
            4)
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting..."
                exit 0
                ;;
            *)
                echo
                echo -e "${RED}${CROSS}${NC} Invalid option. Please enter 1-4."
                exit 1
                ;;
        esac
    else
        case $SETUP_TYPE in
            1)
                echo
                echo -e "${PURPLE}================${NC}"
                echo -e "${WHITE}Bridge Setup${NC}"
                echo -e "${PURPLE}================${NC}"
                echo

                input_bridge_domain
                input_node_ip

                install_bridge
                ;;
            2)
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting..."
                exit 0
                ;;
            *)
                echo
                echo -e "${RED}${CROSS}${NC} Invalid option. Please enter 1-2."
                exit 1
                ;;
        esac
    fi
}

main
exec 1>&- 2>&-
wait
exit 0
