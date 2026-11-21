#!/bin/bash

#===================
# BRIDGE YANDEX CDN
#===================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
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

DIR_BRIDGE="/usr/local/bridge_ya_cdn/"
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
    LOGFILE="${DIR_BRIDGE}rm-bridge-ya-cdn-setup.log"
    exec > >(tee -a "$LOGFILE") 2>&1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script must be run as root"
    fi
}

ensure_dns() {
    echo -e "${CYAN}${INFO}${NC} Checking DNS resolution..."

    local probe="one.one.one.one"

    echo -e "${GRAY}  ${ARROW}${NC} Resolving ${probe}"
    if getent hosts "$probe" > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} DNS working"
        return 0
    fi

    echo -e "${YELLOW}  ${WARNING}${NC} DNS resolution failed, fixing resolvers"

    if [ -L /etc/resolv.conf ]; then
        error "DNS broken and /etc/resolv.conf is managed (systemd-resolved). Fix DNS manually."
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Writing public resolvers"
    if ! printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf; then
        error "DNS broken and /etc/resolv.conf is not writable."
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Re-checking resolution"
    if getent hosts "$probe" > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} DNS working"
        return 0
    fi

    error "DNS resolution still failing. Check /etc/resolv.conf on the server."
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
    if [ "$HAPROXY_INSTALLED" = true ] && [ ! -s "$NODES_FILE" ]; then
        error "HAProxy is already installed outside this Yandex CDN bridge. Use a separate server."
    fi

    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${WHITE}BRIDGE YANDEX CDN${NC}"
    echo -e "${PURPLE}==================${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    if [ "$HAPROXY_INSTALLED" = true ]; then
        echo -e "${GREEN}1.${NC} Add origin"
        echo -e "${RED}2.${NC} Remove origin"
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

input_node_domain() {
    echo -ne "${CYAN}Origin SNI/Host (e.g., origin.example.com): ${NC}"
    read -r NODE_DOMAIN
    while [[ -z "$NODE_DOMAIN" ]] || ! validate_domain "$NODE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Origin SNI/Host: ${NC}"
        read -r NODE_DOMAIN
    done
}

get_bridge_ip() {
    BRIDGE_IP=$(curl -s https://api.ipify.org 2>/dev/null)
    if ! validate_ip "$BRIDGE_IP"; then
        error "Failed to detect bridge server IP"
    fi
    echo -e "${CYAN}Bridge IP: ${WHITE}${BRIDGE_IP}${NC}"
}

input_node_ip() {
    echo -ne "${CYAN}Origin server IP address: ${NC}"
    read -r NODE_IP
    while [[ -z "$NODE_IP" ]] || ! validate_ip "$NODE_IP"; do
        echo -e "${RED}${CROSS}${NC} Invalid IP! Please enter a valid IPv4 address (e.g., 1.2.3.4)."
        echo
        echo -ne "${CYAN}Origin server IP address: ${NC}"
        read -r NODE_IP
    done
}

#==================
# HAPROXY FUNCTIONS
#==================

generate_haproxy_config() {
    local node_domain node_ip bridge_ip
    {
        cat <<'EOF'
global
    log /dev/log local0
    maxconn 50000

defaults
    log global
    mode tcp
    timeout connect 5s
    timeout client 1h
    timeout server 1h

frontend main_front
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content set-var(sess.ssl_sni) req.ssl_sni
    tcp-request content accept if { req_ssl_hello_type 1 }
EOF

        while IFS=: read -r node_domain node_ip bridge_ip; do
            local backend_name
            backend_name=$(echo "$node_domain" | sed 's/[.-]/_/g')
            echo "    use_backend ${backend_name}_backend if { req.ssl_sni -i ${node_domain} }"
        done < "$NODES_FILE"

        while IFS=: read -r node_domain node_ip bridge_ip; do
            local backend_name
            backend_name=$(echo "$node_domain" | sed 's/[.-]/_/g')
            printf '\nbackend %s_backend\n    server node %s:443\n' "$backend_name" "$node_ip"
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

#========================
# CDN SETTINGS FUNCTIONS
#========================

print_cdn_settings() {
    local node_domain=$1
    local node_ip=$2
    local bridge_ip=$3

    echo -e "${CYAN}In Yandex Cloud CDN, configure the origin for ${node_domain}:${NC}"
    echo -e "${WHITE}Origin address: ${bridge_ip}${NC}"
    echo -e "${WHITE}Origin protocol: HTTPS${NC}"
    echo -e "${WHITE}Origin port: 443${NC}"
    echo -e "${WHITE}Origin Host: ${node_domain}${NC}"
    echo -e "${WHITE}Origin SNI: ${node_domain}${NC}"
    echo
    echo -e "${GRAY}  ${ARROW}${NC} Keep Remnawave client Host settings unchanged"
    echo -e "${GRAY}  ${ARROW}${NC} Keep ${node_domain} DNS pointing to ${node_ip}"
    echo -e "${GRAY}  ${ARROW}${NC} Keep origin port 443 open until the CDN path is verified"
}

print_restore_cdn_settings() {
    local node_domain=$1
    local node_ip=$2

    echo -e "${CYAN}In Yandex Cloud CDN, restore the direct origin for ${node_domain}:${NC}"
    echo -e "${WHITE}Origin address: ${node_ip}${NC}"
    echo -e "${WHITE}Origin protocol: HTTPS${NC}"
    echo -e "${WHITE}Origin port: 443${NC}"
    echo -e "${WHITE}Origin Host: ${node_domain}${NC}"
    echo -e "${WHITE}Origin SNI: ${node_domain}${NC}"
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

    ensure_dns
    echo
    install_system_packages

    echo
    echo -e "${GREEN}Configuring bridge${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Configuring HAProxy..."

    echo "${NODE_DOMAIN}:${NODE_IP}:${BRIDGE_IP}" > "$NODES_FILE"

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
    echo -e "${YELLOW}${WARNING} Action required${NC}"
    print_cdn_settings "$NODE_DOMAIN" "$NODE_IP" "$BRIDGE_IP"
    echo
}

add_node() {
    echo
    echo -e "${PURPLE}===========${NC}"
    echo -e "${WHITE}Add Origin${NC}"
    echo -e "${PURPLE}===========${NC}"
    echo

    input_node_domain
    input_node_ip
    get_bridge_ip

    local escaped_domain
    escaped_domain=$(printf '%s' "$NODE_DOMAIN" | sed 's/[.[\*^$]/\\&/g')
    if grep -q "^${escaped_domain}:" "$NODES_FILE" 2>/dev/null; then
        error "Origin SNI ${NODE_DOMAIN} is already configured"
    fi

    echo
    echo -e "${CYAN}${INFO}${NC} Adding origin..."

    echo "${NODE_DOMAIN}:${NODE_IP}:${BRIDGE_IP}" >> "$NODES_FILE"

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} Origin added"

    echo
    echo -e "${PURPLE}===============${NC}"
    echo -e "${GREEN}${CHECK}${NC} Origin added"
    echo -e "${PURPLE}===============${NC}"
    echo
    echo -e "${YELLOW}${WARNING} Action required${NC}"
    print_cdn_settings "$NODE_DOMAIN" "$NODE_IP" "$BRIDGE_IP"
    echo
}

remove_node() {
    if [ ! -f "$NODES_FILE" ] || [ ! -s "$NODES_FILE" ]; then
        error "No origins configured"
    fi

    echo
    echo -e "${PURPLE}==============${NC}"
    echo -e "${WHITE}Remove Origin${NC}"
    echo -e "${PURPLE}==============${NC}"
    echo

    echo -e "${CYAN}Configured origins:${NC}"
    echo
    local i=1
    local node_domains=()
    while IFS=: read -r node_domain node_ip bridge_ip; do
        echo -e "${WHITE}${i}.${NC} ${node_domain} → ${node_ip} (bridge IP: ${bridge_ip})"
        node_domains+=("$node_domain")
        i=$((i + 1))
    done < "$NODES_FILE"
    echo
    echo -ne "${CYAN}Select origin to remove (1-${#node_domains[@]}): ${NC}"
    read -r selection
    echo

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#node_domains[@]}" ]; then
        error "Invalid selection"
    fi

    local selected_node="${node_domains[$((selection - 1))]}"

    echo -e "${CYAN}${INFO}${NC} Removing origin ${selected_node}..."

    local escaped_domain
    escaped_domain=$(printf '%s' "$selected_node" | sed 's/[.[\*^$]/\\&/g')

    local node_ip bridge_ip
    IFS=: read -r _ node_ip bridge_ip < <(grep "^${escaped_domain}:" "$NODES_FILE")

    sed -i "/^${escaped_domain}:/d" "$NODES_FILE"

    if [ ! -s "$NODES_FILE" ]; then
        echo -e "${YELLOW}${WARNING}${NC} No origins remaining, removing bridge"
        echo
        _remove_bridge_services
        echo -e "${YELLOW}${WARNING} Action required${NC}"
        print_restore_cdn_settings "$selected_node" "$node_ip"
        echo
        return
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} HAProxy updated"
    echo
    echo -e "${PURPLE}=================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Origin removed"
    echo -e "${PURPLE}=================${NC}"
    echo
    echo -e "${YELLOW}${WARNING} Action required${NC}"
    print_restore_cdn_settings "$selected_node" "$node_ip"
    echo
}

_remove_bridge_services() {
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

remove_bridge() {
    echo
    echo -e "${GREEN}CDN origin settings${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    local restore_out=""

    if [ -f "$NODES_FILE" ] && [ -s "$NODES_FILE" ]; then
        while IFS=: read -r node_domain node_ip bridge_ip; do
            restore_out+="$(print_restore_cdn_settings "$node_domain" "$node_ip")"$'\n\n'
        done < "$NODES_FILE"
    fi

    _remove_bridge_services

    if [ -n "$restore_out" ]; then
        echo -e "${YELLOW}${WARNING} Action required${NC}"
        printf '%s' "$restore_out"
    fi
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    exec < /dev/tty
    log_entry
    check_root

    show_main_menu
    read -r SETUP_TYPE

    if [ "$HAPROXY_INSTALLED" = true ]; then
        case $SETUP_TYPE in
            1) add_node ;;
            2) remove_node ;;
            3)
                echo
                echo -e "${YELLOW}${WARNING}${NC} This will remove HAProxy. Restore the CDN origins before proceeding."
                echo -ne "${YELLOW}Are you sure? (y/n): ${NC}"
                read -r confirm
                confirm=$(printf '%s' "$confirm" | tr -cd 'a-zA-Z')
                if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                    echo -e "${YELLOW}${WARNING}${NC} Cancelled"
                    exit 0
                fi
                remove_bridge
                ;;
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
                echo -e "${PURPLE}=============${NC}"
                echo -e "${WHITE}Bridge Setup${NC}"
                echo -e "${PURPLE}=============${NC}"
                echo

                input_node_domain
                input_node_ip
                get_bridge_ip

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
