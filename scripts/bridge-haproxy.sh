#!/bin/bash

#==============================
# REMNAWAVE BRIDGE PROXY SETUP
#==============================

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

DIR_BRIDGE="/usr/local/remnawave_bridge/"
NODES_FILE="${DIR_BRIDGE}nodes.conf"
CREDS_FILE="${DIR_BRIDGE}rm-bridge-config.env"

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
    if ! apt-get install -y ca-certificates curl jq ufw haproxy unattended-upgrades > /dev/null 2>&1; then
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

input_panel_url() {
    echo -ne "${CYAN}Panel domain (e.g., panel.example.com): ${NC}"
    read -r PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]] || ! validate_domain "$PANEL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read -r PANEL_DOMAIN
    done
    PANEL_URL="https://${PANEL_DOMAIN}"
}

input_api_token() {
    echo -ne "${CYAN}API token: ${NC}"
    read -r API_TOKEN
    while [[ -z "$API_TOKEN" ]]; do
        echo -e "${RED}${CROSS}${NC} API token cannot be empty!"
        echo
        echo -ne "${CYAN}API token: ${NC}"
        read -r API_TOKEN
    done
}

input_node_domain() {
    echo -ne "${CYAN}Node selfsteal domain (nginx server_name, e.g., node.example.com): ${NC}"
    read -r NODE_DOMAIN
    while [[ -z "$NODE_DOMAIN" ]] || ! validate_domain "$NODE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Node selfsteal domain: ${NC}"
        read -r NODE_DOMAIN
    done
}

input_bridge_domain() {
    echo -ne "${CYAN}Bridge domain (public address for DNS, e.g., bridge.example.com): ${NC}"
    read -r BRIDGE_DOMAIN
    while [[ -z "$BRIDGE_DOMAIN" ]] || ! validate_domain "$BRIDGE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Bridge domain: ${NC}"
        read -r BRIDGE_DOMAIN
    done
}

input_node_ip() {
    echo -ne "${CYAN}Node IP address: ${NC}"
    read -r NODE_IP
    while [[ -z "$NODE_IP" ]] || ! validate_ip "$NODE_IP"; do
        echo -e "${RED}${CROSS}${NC} Invalid IP! Please enter a valid IPv4 address (e.g., 1.2.3.4)."
        echo
        echo -ne "${CYAN}Node IP address: ${NC}"
        read -r NODE_IP
    done
}

#=====================
# CREDENTIALS
#=====================

save_credentials() {
    printf 'PANEL_DOMAIN="%s"\nAPI_TOKEN="%s"\n' "$PANEL_DOMAIN" "$API_TOKEN" > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
}

load_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CREDS_FILE"
        PANEL_URL="https://${PANEL_DOMAIN}"
    else
        input_panel_url
        input_api_token
        save_credentials
    fi
}

#=================
# API FUNCTIONS
#=================

make_api_request() {
    local method=$1
    local path=$2
    local data=${3:-}

    if [ -n "$data" ]; then
        curl -s -X "$method" "${PANEL_URL}${path}" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser" \
            -d "$data"
    else
        curl -s -X "$method" "${PANEL_URL}${path}" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser"
    fi
}

update_panel_host() {
    local node_domain=$1
    local bridge_domain=$2

    echo -e "${CYAN}${INFO}${NC} Updating host in panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching hosts"
    local hosts_response
    hosts_response=$(make_api_request GET "/api/hosts")

    local host_uuid
    host_uuid=$(echo "$hosts_response" | jq -r \
        --arg domain "$node_domain" \
        '[.response[] | select(.address == $domain or .sni == $domain)] | first | .uuid // empty')

    if [ -z "$host_uuid" ]; then
        echo -e "${RED}${CROSS}${NC} Host for ${node_domain} not found in panel"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Setting address=${bridge_domain}, sni=${node_domain}"
    local patch_response
    patch_response=$(make_api_request PATCH "/api/hosts" "$(jq -n \
        --arg uuid "$host_uuid" \
        --arg address "$bridge_domain" \
        --arg sni "$node_domain" \
        --arg host "$node_domain" \
        '{ uuid: $uuid, address: $address, sni: $sni, host: $host }')")

    if ! echo "$patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update host: $patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Host updated"
}

restore_panel_host() {
    local node_domain=$1

    echo -e "${CYAN}${INFO}${NC} Restoring host in panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching hosts"
    local hosts_response
    hosts_response=$(make_api_request GET "/api/hosts")

    local host_uuid
    host_uuid=$(echo "$hosts_response" | jq -r \
        --arg domain "$node_domain" \
        '[.response[] | select(.sni == $domain)] | first | .uuid // empty')

    if [ -z "$host_uuid" ]; then
        echo -e "${YELLOW}  ${WARNING}${NC} Host for ${node_domain} not found, skipping"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Restoring address=${node_domain}, sni=${node_domain}"
    local patch_response
    patch_response=$(make_api_request PATCH "/api/hosts" "$(jq -n \
        --arg uuid "$host_uuid" \
        --arg domain "$node_domain" \
        '{ uuid: $uuid, address: $domain, sni: $domain, host: $domain }')")

    if ! echo "$patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${YELLOW}  ${WARNING}${NC} Failed to restore host: $patch_response"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} Host restored"
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

        while IFS=: read -r node_domain node_ip bridge_domain; do
            local backend_name
            backend_name=$(echo "$node_domain" | sed 's/[.-]/_/g')
            echo "    use_backend ${backend_name}_backend if { req.ssl_sni -i ${node_domain} }"
        done < "$NODES_FILE"

        while IFS=: read -r node_domain node_ip bridge_domain; do
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

    echo "${NODE_DOMAIN}:${NODE_IP}:${BRIDGE_DOMAIN}" > "$NODES_FILE"

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
    echo -e "${GREEN}Updating panel${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    update_panel_host "$NODE_DOMAIN" "$BRIDGE_DOMAIN"
    save_credentials

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    local server_ip
    server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}• Update the A record of ${BRIDGE_DOMAIN} to point to ${server_ip} (DNS only)${NC}"
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

    load_credentials

    echo
    input_node_domain
    input_bridge_domain
    input_node_ip

    local escaped_domain
    escaped_domain=$(printf '%s' "$NODE_DOMAIN" | sed 's/[.[\*^$]/\\&/g')
    if grep -q "^${escaped_domain}:" "$NODES_FILE" 2>/dev/null; then
        error "Node domain ${NODE_DOMAIN} is already configured"
    fi

    echo -e "${CYAN}${INFO}${NC} Adding node..."

    echo "${NODE_DOMAIN}:${NODE_IP}:${BRIDGE_DOMAIN}" >> "$NODES_FILE"

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} Node added"

    echo
    echo -e "${GREEN}Updating panel${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    update_panel_host "$NODE_DOMAIN" "$BRIDGE_DOMAIN"

    echo
    local server_ip
    server_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}• Update the A record of ${BRIDGE_DOMAIN} to point to ${server_ip} (DNS only)${NC}"
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

    load_credentials

    echo
    echo -e "${CYAN}Configured nodes:${NC}"
    echo
    local i=1
    local node_domains=()
    while IFS=: read -r node_domain node_ip bridge_domain; do
        echo -e "${WHITE}${i}.${NC} ${node_domain} → ${node_ip} (bridge: ${bridge_domain})"
        node_domains+=("$node_domain")
        i=$((i + 1))
    done < "$NODES_FILE"
    echo
    echo -ne "${CYAN}Select node to remove (1-${#node_domains[@]}): ${NC}"
    read -r selection

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#node_domains[@]}" ]; then
        error "Invalid selection"
    fi

    local selected_node="${node_domains[$((selection - 1))]}"

    echo -e "${CYAN}${INFO}${NC} Removing node ${selected_node}..."

    local escaped_domain
    escaped_domain=$(printf '%s' "$selected_node" | sed 's/[.[\*^$]/\\&/g')
    sed -i "/^${escaped_domain}:/d" "$NODES_FILE"

    if [ ! -s "$NODES_FILE" ]; then
        echo -e "${YELLOW}${WARNING}${NC} No nodes remaining, removing bridge"
        echo
        restore_panel_host "$selected_node"
        _remove_bridge_services
        return
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating configuration"
    generate_haproxy_config

    echo -e "${GRAY}  ${ARROW}${NC} Reloading HAProxy"
    reload_haproxy

    echo -e "${GREEN}${CHECK}${NC} Node removed"

    echo
    restore_panel_host "$selected_node"
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
    echo -e "${GREEN}Restoring hosts${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    if [ -f "$NODES_FILE" ] && [ -s "$NODES_FILE" ]; then
        while IFS=: read -r node_domain node_ip bridge_domain; do
            restore_panel_host "$node_domain"
            echo
        done < "$NODES_FILE"
    fi

    _remove_bridge_services
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    check_root

    show_main_menu
    read -r SETUP_TYPE

    if [ "$HAPROXY_INSTALLED" = true ]; then
        case $SETUP_TYPE in
            1) add_node ;;
            2) remove_node ;;
            3)
                load_credentials
                echo
                echo -e "${YELLOW}${WARNING}${NC} This will restore all node hosts in the panel and remove HAProxy."
                echo -ne "${YELLOW}Are you sure? (y/n): ${NC}"
                read -r confirm
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
                echo -e "${PURPLE}================${NC}"
                echo -e "${WHITE}Bridge Setup${NC}"
                echo -e "${PURPLE}================${NC}"
                echo

                input_panel_url
                input_api_token
                input_node_domain
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
