#!/bin/bash

#==================
# WS YANDEX CDN NODE
#==================

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

DIR_REMNAWAVE="/usr/local/remnawave_reverse/"

SCRIPT_VERSION="1.0.0"
NODE_VERSION="2.8.0"
PROFILE_NAME="StealConfig"
WS_INBOUND_TAG="Vless WS Yandex"
WS_INBOUND_PORT=10000
SQUAD_NAME="Default-Squad"

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

check_os() {
    if ! grep -q "bullseye" /etc/os-release && ! grep -q "bookworm" /etc/os-release && ! grep -q "jammy" /etc/os-release && ! grep -q "noble" /etc/os-release && ! grep -q "trixie" /etc/os-release; then
        error "Supported only Debian 11/12 and Ubuntu 22.04/24.04"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script must be run as root"
    fi
}

#=====================
# MAIN MENU FUNCTIONS
#=====================

show_main_menu() {
    NODE_INSTALLED=false
    [ -d /opt/remnanode ] && NODE_INSTALLED=true

    echo
    echo -e "${PURPLE}==============${NC}"
    echo -e "${WHITE}WS YANDEX CDN${NC}"
    echo -e "${PURPLE}==============${NC}"
    echo
    echo -e "${CYAN}Script version: ${WHITE}${SCRIPT_VERSION}${NC}"
    echo -e "${CYAN}Node version: ${WHITE}${NODE_VERSION}${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    if [ "$NODE_INSTALLED" = true ]; then
        echo -e "${RED}1.${NC} Delete Node"
        echo -e "${YELLOW}2.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Add Node"
        echo -e "${YELLOW}2.${NC} Exit"
    fi
    echo
    echo -ne "${CYAN}Enter your choice: ${NC}"
}

#===================
# UTILITY FUNCTIONS
#===================

log_entry() {
    mkdir -p ${DIR_REMNAWAVE}
    LOGFILE="${DIR_REMNAWAVE}remnawave_reverse.log"
    exec > >(tee -a "$LOGFILE") 2>&1
}

add_cron_rule() {
    local rule="$1"
    local logged_rule="${rule} >> ${DIR_REMNAWAVE}cron_jobs.log 2>&1"

    if ! crontab -u root -l > /dev/null 2>&1; then
        crontab -u root -l 2>/dev/null | crontab -u root -
    fi

    if ! crontab -u root -l | grep -Fxq "$logged_rule"; then
        (crontab -u root -l 2>/dev/null; echo "$logged_rule") | crontab -u root -
    fi
}

pause_step() {
    echo
    echo -ne "${YELLOW}Press Enter once the step above is done in the console...${NC}"
    read -r _
    echo
}

#======================
# INPUT FUNCTIONS
#======================

input_cloudflare_api_key() {
    echo -ne "${CYAN}Cloudflare API Key: ${NC}"
    read -r CLOUDFLARE_API_KEY
    while [[ -z "$CLOUDFLARE_API_KEY" ]]; do
        echo -e "${RED}${CROSS}${NC} Cloudflare API Key cannot be empty!"
        echo
        echo -ne "${CYAN}Cloudflare API Key: ${NC}"
        read -r CLOUDFLARE_API_KEY
    done
}

input_cloudflare_email() {
    echo -ne "${CYAN}Cloudflare Email: ${NC}"
    read -r CLOUDFLARE_EMAIL
    while [[ -z "$CLOUDFLARE_EMAIL" ]]; do
        echo -e "${RED}${CROSS}${NC} Cloudflare Email cannot be empty!"
        echo
        echo -ne "${CYAN}Cloudflare Email: ${NC}"
        read -r CLOUDFLARE_EMAIL
    done
}

input_node_selfsteal_domain() {
    echo -ne "${CYAN}Node self-steal domain (e.g., example.com): ${NC}"
    read -r SELFSTEAL_DOMAIN
    SELFSTEAL_DOMAIN=$(printf '%s' "$SELFSTEAL_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    while [[ -z "$SELFSTEAL_DOMAIN" ]] || ! validate_domain "$SELFSTEAL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Node self-steal domain (e.g., example.com): ${NC}"
        read -r SELFSTEAL_DOMAIN
        SELFSTEAL_DOMAIN=$(printf '%s' "$SELFSTEAL_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    done
}

input_cdn_domain() {
    echo -ne "${CYAN}CDN domain (e.g., cdn.example.com): ${NC}"
    read -r CDN_DOMAIN
    CDN_DOMAIN=$(printf '%s' "$CDN_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    while [[ -z "$CDN_DOMAIN" ]] || ! validate_domain "$CDN_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}CDN domain (e.g., cdn.example.com): ${NC}"
        read -r CDN_DOMAIN
        CDN_DOMAIN=$(printf '%s' "$CDN_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    done
}

input_panel_ip() {
    echo -ne "${CYAN}Panel IP address: ${NC}"
    read -r PANEL_IP
    PANEL_IP=$(printf '%s' "$PANEL_IP" | tr -d '[:space:]')
    while [[ -z "$PANEL_IP" ]] || ! validate_ip "$PANEL_IP"; do
        echo -e "${RED}${CROSS}${NC} Invalid IP! Please enter a valid IPv4 address (e.g., 1.2.3.4)."
        echo
        echo -ne "${CYAN}Panel IP address: ${NC}"
        read -r PANEL_IP
        PANEL_IP=$(printf '%s' "$PANEL_IP" | tr -d '[:space:]')
    done
}

input_node_panel_domain() {
    echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
    read -r PANEL_NODE_DOMAIN
    PANEL_NODE_DOMAIN=$(printf '%s' "$PANEL_NODE_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    while [[ -z "$PANEL_NODE_DOMAIN" ]] || ! validate_domain "$PANEL_NODE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read -r PANEL_NODE_DOMAIN
        PANEL_NODE_DOMAIN=$(printf '%s' "$PANEL_NODE_DOMAIN" | tr -cd 'a-zA-Z0-9.-')
    done
    PANEL_NODE_URL="https://${PANEL_NODE_DOMAIN}"
}

input_node_api_token() {
    echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
    read -r PANEL_NODE_TOKEN
    PANEL_NODE_TOKEN=$(printf '%s' "$PANEL_NODE_TOKEN" | tr -d '[:space:]')
    while [[ -z "$PANEL_NODE_TOKEN" ]]; do
        echo -e "${RED}${CROSS}${NC} API token cannot be empty!"
        echo
        echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
        read -r PANEL_NODE_TOKEN
        PANEL_NODE_TOKEN=$(printf '%s' "$PANEL_NODE_TOKEN" | tr -d '[:space:]')
    done
}

input_node_name() {
    echo -ne "${CYAN}Node name (e.g., DE-CDN, NL-CDN, FI-CDN, PL-CDN, RU-CDN): ${NC}"
    read NODE_NAME
    while [[ -z "$NODE_NAME" ]]; do
        echo -e "${RED}${CROSS}${NC} Node name cannot be empty!"
        echo
        echo -ne "${CYAN}Node name: ${NC}"
        read -r NODE_NAME
    done
}

input_host_remark() {
    echo -ne "${CYAN}Host remark (e.g., 🇩🇪 Германия (CDN), 🇳🇱 Нидерланды (CDN)): ${NC}"
    read HOST_REMARK
    while [[ -z "$HOST_REMARK" ]]; do
        echo -e "${RED}${CROSS}${NC} Host remark cannot be empty!"
        echo
        echo -ne "${CYAN}Host remark: ${NC}"
        read -r HOST_REMARK
    done
}

NODE_CREDS_FILE="/opt/remnanode/rm-node-config.env"

save_node_credentials() {
    mkdir -p /opt/remnanode
    printf 'PANEL_NODE_DOMAIN="%s"\nPANEL_NODE_TOKEN="%s"\nPANEL_IP="%s"\nSELFSTEAL_DOMAIN="%s"\nCDN_DOMAIN="%s"\n' \
        "$PANEL_NODE_DOMAIN" "$PANEL_NODE_TOKEN" "$PANEL_IP" "$SELFSTEAL_DOMAIN" "$CDN_DOMAIN" > "$NODE_CREDS_FILE"
    chmod 600 "$NODE_CREDS_FILE"
}

load_saved_node_credentials() {
    if [ -f "$NODE_CREDS_FILE" ]; then
        source "$NODE_CREDS_FILE"
        PANEL_NODE_URL="https://${PANEL_NODE_DOMAIN}"
    else
        input_panel_ip
        input_node_panel_domain
        input_node_api_token
        input_node_selfsteal_domain
        input_cdn_domain
        save_node_credentials
    fi
}

save_node_variables_to_file() {
    echo -e "${CYAN}${INFO}${NC} Saving node configuration variables..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating variables file"
    cat > remnawave-node-vars.sh << EOF
# User provided node configuration
export SELFSTEAL_DOMAIN="$SELFSTEAL_DOMAIN"
export CDN_DOMAIN="$CDN_DOMAIN"
export PANEL_IP="$PANEL_IP"
export PANEL_NODE_DOMAIN="$PANEL_NODE_DOMAIN"
export PANEL_NODE_TOKEN="$PANEL_NODE_TOKEN"
export PANEL_NODE_URL="https://${PANEL_NODE_DOMAIN}"
export NODE_NAME="$NODE_NAME"
export HOST_REMARK="$HOST_REMARK"
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Loading environment variables"
    source remnawave-node-vars.sh
    echo -e "${GREEN}${CHECK}${NC} Variables saved to remnawave-node-vars.sh"
}

move_variables_file() {
    echo -e "${CYAN}${INFO}${NC} Moving configuration files..."
    echo -e "${GRAY}  ${ARROW}${NC} Moving variables file to project directory"
    mkdir -p "$APP_DIR"
    if [ -f /root/remnawave-node-vars.sh ]; then
        mv /root/remnawave-node-vars.sh "$APP_DIR/"
    fi
    echo -e "${GREEN}${CHECK}${NC} Configuration files moved"
}

#===============================
# SYSTEM INSTALLATION FUNCTIONS
#===============================

install_system_packages() {
    echo -e "${CYAN}${INFO}${NC} Installing basic packages..."
    echo -e "${GRAY}  ${ARROW}${NC} Updating package lists"

    if ! apt-get update -y > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update package list"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing essential packages"
    if ! apt-get install -y ca-certificates curl jq ufw wget gnupg unzip nano dialog git certbot python3-certbot-dns-cloudflare unattended-upgrades locales dnsutils coreutils grep gawk > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to install required packages"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing and configuring cron service"
    if ! dpkg -l cron 2>/dev/null | grep -q '^ii'; then
        if ! apt-get install -y cron > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to install cron"
            return 1
        fi
    fi

    if ! systemctl is-active --quiet cron; then
        if ! systemctl start cron > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Not able to start cron. Please start it manually."
            return 1
        fi
    fi
    if ! systemctl is-enabled --quiet cron; then
        if ! systemctl enable cron > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Not able to start cron. Please start it manually."
            return 1
        fi
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring locales"
    if [ ! -f /etc/locale.gen ]; then
        echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
    fi
    if ! grep -q "^en_US.UTF-8 UTF-8" /etc/locale.gen; then
        if grep -q "^# en_US.UTF-8 UTF-8" /etc/locale.gen; then
            sed -i 's/^# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
        else
            echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
        fi
    fi
    if ! locale-gen > /dev/null 2>&1 || ! update-locale LANG=en_US.UTF-8 > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Error: Failed to configure locales"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Checking Docker DNS connectivity"
    if ! curl -s --max-time 5 https://download.docker.com >/dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Error: Unable to reach download.docker.com. Check your DNS settings."
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Adding Docker repository"
    if grep -q "Ubuntu" /etc/os-release; then
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null; then
            echo -e "${RED}${CROSS}${NC} Failed to download Docker GPG key"
            return 1
        fi
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    elif grep -q "Debian" /etc/os-release; then
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL https://download.docker.com/linux/debian/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null; then
            echo -e "${RED}${CROSS}${NC} Failed to download Docker GPG key"
            return 1
        fi
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating package list after adding Docker repository"
    if ! apt-get update > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update package list after adding Docker repository"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing Docker packages"
    if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to install Docker"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Verifying Docker installation"
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Docker is not installed"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Starting Docker service"
    if ! systemctl is-active --quiet docker; then
        if ! systemctl start docker > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to start Docker"
            return 1
        fi
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Enabling Docker auto-start"
    if ! systemctl is-enabled --quiet docker; then
        if ! systemctl enable docker > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to enable Docker auto-start"
            return 1
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Docker is not working properly"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring UFW firewall"
    if ! ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1 || ! ufw allow 443/tcp comment 'Yandex CDN origin (caddy WS)' > /dev/null 2>&1 || ! ufw --force enable > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to configure UFW"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring automatic security updates"
    echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    if ! dpkg-reconfigure -f noninteractive unattended-upgrades > /dev/null 2>&1 || ! systemctl restart unattended-upgrades > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to configure unattended-upgrades"
        return 1
    fi

    touch ${DIR_REMNAWAVE}install_packages
    echo -e "${GREEN}${CHECK}${NC} System packages configured"
}

configure_tcp_optimizations() {
    echo -e "${CYAN}${INFO}${NC} Applying TCP optimizations..."
    echo -e "${GRAY}  ${ARROW}${NC} Writing sysctl configuration"
    cat > /etc/sysctl.d/99-xray.conf << 'EOF'
# Connection queues
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192

# Ephemeral ports
net.ipv4.ip_local_port_range = 10240 65535

# Fast connection release
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Socket buffers (TLS / gRPC / WS)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# TCP behavior
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# Protection
net.ipv4.tcp_syncookies = 1
fs.file-max = 1000000
EOF
    sysctl -p /etc/sysctl.d/99-xray.conf >/dev/null
    echo -e "${GREEN}${CHECK}${NC} TCP optimizations configured"
}

#========================
# DOMAIN CHECK FUNCTIONS
#========================

check_domain() {
    local domain="$1"
    local show_warning="${2:-true}"

    local domain_ip=$(dig +short A "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
    local server_ip=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org || curl -s -4 ipinfo.io/ip)
    local local_ips=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)

    if [ -z "$domain_ip" ] || [ -z "$server_ip" ]; then
        if [ "$show_warning" = true ]; then
            echo -e "${YELLOW}${WARNING}${NC} ${RED}Failed to determine the domain or server IP address.${NC}"
            printf "${YELLOW}Ensure that the domain %s is correctly configured and points to this server (%s).${NC}\n" "$domain" "$server_ip"
            echo
            echo -ne "${CYAN}Enter 'y' to continue or 'n' to exit (y/n): ${NC}"
            read confirm
            confirm=$(printf '%s' "$confirm" | tr -cd 'a-zA-Z')
            echo
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                return 0
            else
                return 2
            fi
        fi
        return 1
    fi

    if [ "$domain_ip" = "$server_ip" ] || printf '%s\n' $local_ips | grep -qxF "$domain_ip"; then
        return 0
    fi

    if [ "$show_warning" = true ]; then
        echo -e "${YELLOW}${WARNING}${NC} ${RED}The domain $domain points to IP address $domain_ip, which differs from this server's IP ($server_ip).${NC}"
        echo -e "${YELLOW}For proper operation, the domain must point to the current server (DNS only, not proxied).${NC}"
        echo
        echo -ne "${CYAN}Enter 'y' to continue or 'n' to exit (y/n): ${NC}"
        read confirm
        confirm=$(printf '%s' "$confirm" | tr -cd 'a-zA-Z')
        echo
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            return 0
        else
            return 2
        fi
    fi
    return 1
}

check_api() {
    local attempts=3
    local attempt=1

    while [ $attempt -le $attempts ]; do
        if [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; then
            api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "Authorization: Bearer ${CLOUDFLARE_API_KEY}" --header "Content-Type: application/json")
        else
            api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "X-Auth-Key: ${CLOUDFLARE_API_KEY}" --header "X-Auth-Email: ${CLOUDFLARE_EMAIL}" --header "Content-Type: application/json")
        fi

        if echo "$api_response" | grep -q '"success":true'; then
            echo -e "${GRAY}  ${ARROW}${NC} Cloudflare API key and email are valid"
            return 0
        else
            echo -e "${RED}Invalid Cloudflare API key or email. Attempt $attempt of $attempts.${NC}"
            if [ $attempt -lt $attempts ]; then
                echo -ne "${CYAN}Enter your Cloudflare API token or global API key: ${NC}"
                read CLOUDFLARE_API_KEY
                echo -ne "${CYAN}Enter your Cloudflare registered email: ${NC}"
                read CLOUDFLARE_EMAIL
            fi
            attempt=$((attempt + 1))
        fi
    done
    echo -e "${RED}Invalid Cloudflare API token or email after $attempts attempts.${NC}"
    exit 1
}

setup_certificate() {
    echo -e "${CYAN}${INFO}${NC} Obtaining SSL certificate..."

    if [ -d "/etc/letsencrypt/live/$SELFSTEAL_DOMAIN" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Certificate already exists for $SELFSTEAL_DOMAIN"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Validating Cloudflare credentials"
        check_api

        echo -e "${GRAY}  ${ARROW}${NC} Writing Cloudflare credentials"
        mkdir -p ~/.secrets/certbot > /dev/null 2>&1
        cat > ~/.secrets/certbot/cloudflare.ini <<EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_key = $CLOUDFLARE_API_KEY
EOF
        chmod 600 ~/.secrets/certbot/cloudflare.ini

        echo -e "${GRAY}  ${ARROW}${NC} Requesting certificate for $SELFSTEAL_DOMAIN"
        if ! certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
            --dns-cloudflare-propagation-seconds 30 \
            -d "$SELFSTEAL_DOMAIN" -d "*.$SELFSTEAL_DOMAIN" \
            --email "$CLOUDFLARE_EMAIL" --agree-tos --non-interactive \
            --key-type ecdsa --elliptic-curve secp384r1 > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to obtain certificate for $SELFSTEAL_DOMAIN"
            exit 1
        fi
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring auto-renewal (caddy restart)"
    local conf="/etc/letsencrypt/renewal/$SELFSTEAL_DOMAIN.conf"
    if [ -f "$conf" ]; then
        sed -i '/^renew_hook/d' "$conf"
        echo "renew_hook = docker restart caddy" >> "$conf"
    fi
    add_cron_rule "0 5 1 */2 * /usr/bin/certbot renew --quiet"

    echo -e "${GREEN}${CHECK}${NC} Certificate ready"
}

#=====================================
# NODE PANEL INTEGRATION FUNCTIONS
#=====================================

make_panel_api_request() {
    local method=$1
    local path=$2
    local data=${3:-}

    if [ -n "$data" ]; then
        curl -s -X "$method" "${PANEL_NODE_URL}${path}" \
            -H "Authorization: Bearer $PANEL_NODE_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser" \
            -d "$data"
    else
        curl -s -X "$method" "${PANEL_NODE_URL}${path}" \
            -H "Authorization: Bearer $PANEL_NODE_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser"
    fi
}

check_panel_api() {
    echo -e "${CYAN}${INFO}${NC} Checking panel API..."
    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X GET "${PANEL_NODE_URL}/api/config-profiles" \
        -H "Authorization: Bearer $PANEL_NODE_TOKEN" \
        -H "X-Remnawave-Client-Type: browser") || true
    if [ "$code" != "200" ]; then
        echo -e "${RED}${CROSS}${NC} Panel API not reachable or unauthorized (HTTP ${code:-000}) — check domain and token"
        exit 1
    fi
    echo -e "${GREEN}${CHECK}${NC} Panel API reachable"
}

resolve_ws_inbound_uuid() {
    local profiles_response
    profiles_response=$(make_panel_api_request GET "/api/config-profiles")
    WS_INBOUND_UUID=$(echo "$profiles_response" | jq -r \
        --arg u "$PROFILE_UUID" --arg tag "$WS_INBOUND_TAG" \
        '.response.configProfiles[] | select(.uuid == $u) | .inbounds[] | select(.tag == $tag) | .uuid' | head -n1)
}

ensure_ws_inbound_in_profile() {
    echo -e "${CYAN}${INFO}${NC} Ensuring ${WS_INBOUND_TAG} inbound in ${PROFILE_NAME} profile..."

    echo -e "${GRAY}  ${ARROW}${NC} Locating ${PROFILE_NAME} profile"
    local profiles_response
    profiles_response=$(make_panel_api_request GET "/api/config-profiles")
    PROFILE_UUID=$(echo "$profiles_response" | jq -r --arg n "$PROFILE_NAME" '.response.configProfiles[] | select(.name == $n) | .uuid' | head -n1)
    if [ -z "$PROFILE_UUID" ] || [ "$PROFILE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Config profile '${PROFILE_NAME}' not found in panel"
        exit 1
    fi

    local full_profile config
    full_profile=$(make_panel_api_request GET "/api/config-profiles/$PROFILE_UUID")
    config=$(echo "$full_profile" | jq -c '.response.config')
    if [ -z "$config" ] || [ "$config" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to read config of profile '${PROFILE_NAME}'"
        exit 1
    fi

    if echo "$config" | jq -e --arg tag "$WS_INBOUND_TAG" '.inbounds[] | select(.tag == $tag)' > /dev/null 2>&1; then
        echo -e "${YELLOW}${WARNING}${NC} Inbound '${WS_INBOUND_TAG}' already exists in '${PROFILE_NAME}', reusing it"
        local existing_path
        existing_path=$(echo "$config" | jq -r --arg tag "$WS_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .streamSettings.wsSettings.path // empty')
        RANDOM_PATH=$(printf '%s' "$existing_path" | sed 's|^/||; s|?ed=2560$||')
        if [ -z "$RANDOM_PATH" ]; then
            echo -e "${RED}${CROSS}${NC} Failed to recover WS path from existing inbound"
            exit 1
        fi
        resolve_ws_inbound_uuid
        if [ -z "$WS_INBOUND_UUID" ] || [ "$WS_INBOUND_UUID" = "null" ]; then
            echo -e "${RED}${CROSS}${NC} Failed to resolve existing inbound UUID"
            exit 1
        fi
        echo -e "${GREEN}${CHECK}${NC} Reusing existing ${WS_INBOUND_TAG} inbound"
        return 0
    fi

    if echo "$config" | jq -e --argjson port "$WS_INBOUND_PORT" '.inbounds[] | select(.port == $port)' > /dev/null 2>&1; then
        echo -e "${YELLOW}${WARNING}${NC} Port ${WS_INBOUND_PORT} is already used by another inbound in '${PROFILE_NAME}'"
        echo -e "${YELLOW}Resolve it manually (rename it to '${WS_INBOUND_TAG}' or free the port), then re-run.${NC}"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Generating x25519 key"
    local key_response private_key
    key_response=$(make_panel_api_request GET "/api/system/tools/x25519/generate")
    private_key=$(echo "$key_response" | jq -r '.response.keypairs[0].privateKey')
    if [ -z "$private_key" ] || [ "$private_key" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to generate keys: $key_response"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Generating WS path"
    RANDOM_PATH="$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c15)"

    echo -e "${GRAY}  ${ARROW}${NC} Appending ${WS_INBOUND_TAG} inbound"
    local decryption updated_config
    decryption="mlkem768x25519plus.native.600s.$private_key"
    updated_config=$(echo "$config" | jq -c \
        --arg tag "$WS_INBOUND_TAG" \
        --argjson port "$WS_INBOUND_PORT" \
        --arg dec "$decryption" \
        --arg path "/$RANDOM_PATH?ed=2560" \
        '.inbounds += [{
            tag: $tag,
            port: $port,
            listen: "127.0.0.1",
            protocol: "vless",
            settings: { clients: [], decryption: $dec },
            sniffing: { enabled: true, destOverride: ["http", "tls"] },
            streamSettings: {
                network: "ws",
                wsSettings: { path: $path }
            }
        }]')

    local patch_data
    patch_data=$(jq -n --arg uuid "$PROFILE_UUID" --argjson config "$updated_config" '{ uuid: $uuid, config: $config }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local response
    response=$(make_panel_api_request PATCH "/api/config-profiles" "$patch_data")
    if ! echo "$response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update profile: $response"
        exit 1
    fi

    resolve_ws_inbound_uuid
    if [ -z "$WS_INBOUND_UUID" ] || [ "$WS_INBOUND_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to resolve new inbound UUID"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} ${WS_INBOUND_TAG} inbound added to ${PROFILE_NAME}"
}

activate_inbound_in_squad() {
    echo -e "${CYAN}${INFO}${NC} Activating ${WS_INBOUND_TAG} inbound in ${SQUAD_NAME}..."

    echo -e "${GRAY}  ${ARROW}${NC} Locating ${SQUAD_NAME}"
    local squads_response squad_uuid
    squads_response=$(make_panel_api_request GET "/api/internal-squads")
    squad_uuid=$(echo "$squads_response" | jq -r --arg n "$SQUAD_NAME" '.response.internalSquads[] | select(.name == $n) | .uuid' | head -n1)

    if echo "$squads_response" | jq -e --arg n "$SQUAD_NAME" --arg u "$WS_INBOUND_UUID" '.response.internalSquads[] | select(.name == $n) | .inbounds[] | select(.uuid == $u)' > /dev/null 2>&1; then
        echo -e "${GRAY}  ${ARROW}${NC} Inbound already active in ${SQUAD_NAME}"
        echo -e "${GREEN}${CHECK}${NC} Inbound active in ${SQUAD_NAME}"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Adding inbound to squad"
    local inbounds_json patch_data
    inbounds_json=$(echo "$squads_response" | jq -c --arg n "$SQUAD_NAME" --arg u "$WS_INBOUND_UUID" '[(.response.internalSquads[] | select(.name == $n) | .inbounds[].uuid), $u] | unique')
    patch_data=$(jq -n --arg uuid "$squad_uuid" --argjson inbounds "$inbounds_json" '{ uuid: $uuid, inbounds: $inbounds }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    make_panel_api_request PATCH "/api/internal-squads" "$patch_data" > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Inbound active in ${SQUAD_NAME}"
}

create_node_in_panel() {
    echo -e "${CYAN}${INFO}${NC} Creating node in panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local node_data
    node_data=$(jq -n \
        --arg name "$NODE_NAME" \
        --arg address "$SELFSTEAL_DOMAIN" \
        --arg profile_uuid "$PROFILE_UUID" \
        --arg inbound_uuid "$WS_INBOUND_UUID" \
        '{
            name: $name,
            address: $address,
            port: 2222,
            configProfile: {
                activeConfigProfileUuid: $profile_uuid,
                activeInbounds: [$inbound_uuid]
            },
            isTrafficTrackingActive: false,
            trafficLimitBytes: 0,
            notifyPercent: 0,
            trafficResetDay: 1,
            excludedInbounds: [],
            countryCode: "XX",
            consumptionMultiplier: 1.0
        }')

    local node_response
    node_response=$(make_panel_api_request POST "/api/nodes" "$node_data")

    NODE_UUID=$(echo "$node_response" | jq -r '.response.uuid')

    if [ -z "$NODE_UUID" ] || [ "$NODE_UUID" = "null" ]; then
        local error_code
        error_code=$(echo "$node_response" | jq -r '.errorCode // empty')
        if [ "$error_code" = "A033" ]; then
            local nodes_response
            nodes_response=$(make_panel_api_request GET "/api/nodes")
            NODE_UUID=$(echo "$nodes_response" | jq -r --arg name "$NODE_NAME" '.response[] | select(.name == $name) | .uuid')
            if [ -z "$NODE_UUID" ] || [ "$NODE_UUID" = "null" ]; then
                echo -e "${RED}${CROSS}${NC} Failed to find existing node '$NODE_NAME'"
                exit 1
            fi
            echo -e "${GREEN}${CHECK}${NC} Node created"
        else
            echo -e "${RED}${CROSS}${NC} Failed to create node: $node_response"
            exit 1
        fi
    else
        echo -e "${GREEN}${CHECK}${NC} Node created"
    fi
    echo
    echo -e "${CYAN}Enter the node's Secret Key from the panel and press \"Enter\" twice:${NC}"
    CERTIFICATE=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            if [ -n "$CERTIFICATE" ]; then
                break
            fi
        else
            CERTIFICATE="$CERTIFICATE$line"
        fi
    done

    echo -ne "${YELLOW}Are you sure the Secret Key is correct? (y/n): ${NC}"
    read confirm
    confirm=$(printf '%s' "$confirm" | tr -cd 'a-zA-Z')

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}${CROSS}${NC} Installation aborted by user"
        exit 1
    fi
}

create_cdn_host_in_panel() {
    echo -e "${CYAN}${INFO}${NC} Creating CDN host in panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Waiting for CDN to become reachable"
    local max_attempts=10
    local attempt=1
    local cdn_up=false
    while [ $attempt -le $max_attempts ]; do
        echo -e "${GRAY}  ${ARROW}${NC} Attempt $attempt of $max_attempts"
        if curl -skI --max-time 10 "https://$CDN_DOMAIN/" | grep -qiE 'HTTP/'; then
            cdn_up=true
            break
        fi
        sleep 15
        ((attempt++))
    done

    if [ "$cdn_up" != true ]; then
        echo -e "${YELLOW}${WARNING}${NC} CDN did not respond at https://$CDN_DOMAIN"
        echo -e "${YELLOW}Verify the Yandex certificate import, CDN resource and the cdn CNAME record, then re-run the host step.${NC}"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Reading pinned peer certificate SHA256"
    local pin
    pin=$(echo | openssl s_client -connect "$CDN_DOMAIN:443" -servername yastatic.net 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')

    if [ -z "$pin" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to read pinned peer certificate from $CDN_DOMAIN"
        exit 1
    fi

    local hosts_response existing_uuid
    hosts_response=$(make_panel_api_request GET "/api/hosts")
    existing_uuid=$(echo "$hosts_response" | jq -r --arg addr "$CDN_DOMAIN" '(.response // [])[] | select(.address == $addr) | .uuid' | head -n 1)
    if [ -n "$existing_uuid" ] && [ "$existing_uuid" != "null" ]; then
        echo -e "${GREEN}${CHECK}${NC} Host created"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Building host config"
    local host_data
    host_data=$(jq -n \
        --arg remark "$HOST_REMARK" \
        --arg address "$CDN_DOMAIN" \
        --arg sni "yastatic.net" \
        --arg reqhost "$CDN_DOMAIN" \
        --arg path "/$RANDOM_PATH?ed=2560" \
        --arg pin "$pin" \
        --arg profile_uuid "$PROFILE_UUID" \
        --arg inbound_uuid "$WS_INBOUND_UUID" \
        '{
            remark: $remark,
            address: $address,
            port: 443,
            sni: $sni,
            host: $reqhost,
            path: $path,
            alpn: "http/1.1",
            fingerprint: "firefox",
            securityLayer: "TLS",
            isDisabled: false,
            pinnedPeerCertSha256: $pin,
            muxParams: {
                enabled: true,
                concurrency: 8,
                xudpConcurrency: 16,
                xudpProxyUDP443: "skip"
            },
            inbound: {
                configProfileUuid: $profile_uuid,
                configProfileInboundUuid: $inbound_uuid
            }
        }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local host_response
    host_response=$(make_panel_api_request POST "/api/hosts" "$host_data")

    if ! echo "$host_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to create host: $host_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Host created"
}

#=============================
# NODE INSTALLATION FUNCTIONS
#=============================

create_cdn_node() {
    mkdir -p /opt/remnanode && cd /opt/remnanode

    check_domain "$SELFSTEAL_DOMAIN" true
    local domain_check_result=$?
    if [ $domain_check_result -eq 2 ]; then
        echo -e "${RED}Installation aborted by user${NC}"
        exit 1
    fi

    echo -e "${CYAN}${INFO}${NC} Writing node configuration..."

    echo -e "${GRAY}  ${ARROW}${NC} Creating .env-node"
    cat > .env-node <<EOL
### APP ###
NODE_PORT=2222

### XRAY ###
SECRET_KEY=$CERTIFICATE
EOL

    echo -e "${GRAY}  ${ARROW}${NC} Creating Caddyfile"
    mkdir -p /opt/remnanode/caddy
    cat > /opt/remnanode/caddy/Caddyfile <<EOF
{
    admin off
    auto_https off
}

https://$SELFSTEAL_DOMAIN:443 {
    tls /etc/letsencrypt/live/$SELFSTEAL_DOMAIN/fullchain.pem /etc/letsencrypt/live/$SELFSTEAL_DOMAIN/privkey.pem

    handle /$RANDOM_PATH {
        reverse_proxy http://127.0.0.1:10000 {
            header_up Host "$SELFSTEAL_DOMAIN"
            header_up Connection "Upgrade"
            header_up Upgrade "websocket"
        }
    }

    handle {
        reverse_proxy http://127.0.0.1:8800
    }
}
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Creating docker-compose.yml"
    cat > /opt/remnanode/docker-compose.yml <<EOF
services:
  remnanode:
    image: remnawave/node:${NODE_VERSION}
    container_name: remnanode
    hostname: remnanode
    restart: always
    cap_add:
      - NET_ADMIN
    network_mode: host
    env_file:
      - path: /opt/remnanode/.env-node
        required: false
    volumes:
      - /dev/shm:/dev/shm:rw
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  caddy:
    image: caddy:2
    container_name: caddy
    hostname: caddy
    restart: always
    network_mode: host
    depends_on:
      - remnanode
    volumes:
      - /opt/remnanode/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  owncloud:
    image: owncloud:10
    container_name: owncloud
    hostname: owncloud
    restart: always
    ports:
      - '8800:80'
    volumes:
      - /var/www/owncloud:/var/www/html
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'
EOF

    echo -e "${GREEN}${CHECK}${NC} Node configuration written"
}

start_cdn_services() {
    echo -e "${CYAN}${INFO}${NC} Starting node services..."

    echo -e "${GRAY}  ${ARROW}${NC} Allowing panel IP to node port"
    ufw allow from $PANEL_IP to any port 2222 > /dev/null 2>&1
    ufw reload > /dev/null 2>&1

    echo -e "${GRAY}  ${ARROW}${NC} Launching containers"
    sleep 3
    cd /opt/remnanode
    if ! docker_compose_up; then
        echo -e "${RED}${CROSS}${NC} Failed to start Docker containers:"
        cat /tmp/.compose.log
        exit 1
    fi
    echo -e "${GREEN}${CHECK}${NC} Docker containers started successfully"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking origin connection..."
    local max_attempts=5
    local attempt=1
    local delay=15

    while [ $attempt -le $max_attempts ]; do
        echo -e "${GRAY}  ${ARROW}${NC} Attempt $attempt of $max_attempts"
        if curl -skI --max-time 10 "https://$SELFSTEAL_DOMAIN/" | grep -qiE 'HTTP/'; then
            echo -e "${GREEN}${CHECK}${NC} Origin connection established successfully"
            break
        else
            echo -e "${GRAY}  ${ARROW}${NC} Origin unavailable on attempt $attempt"
            if [ $attempt -eq $max_attempts ]; then
                echo -e "${RED}${CROSS}${NC} Origin connection failed"
                echo -e "${YELLOW}${WARNING}${NC} Check the caddy container, the certificate, and that $SELFSTEAL_DOMAIN has an A record pointing to this node"
                echo
                exit 1
            fi
            sleep $delay
        fi
        ((attempt++))
    done
}

docker_compose_up() {
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        docker compose pull > /tmp/.compose.log 2>&1 || true
        if docker compose up -d --pull never >> /tmp/.compose.log 2>&1; then
            return 0
        fi
        if [ $attempt -eq $max_attempts ]; then
            return 1
        fi
        echo -e "${YELLOW}${WARNING}${NC} Attempt $attempt failed, retrying in 10s..."
        sleep 10
        ((attempt++))
    done
}

verify_cdn() {
    echo -e "${CYAN}${INFO}${NC} Verifying CDN connectivity..."

    echo -e "${GRAY}  ${ARROW}${NC} Testing WebSocket handshake (expecting 101)"
    local ws_status
    ws_status=$(curl -ski --http1.1 --connect-to "yastatic.net:443:$CDN_DOMAIN:443" \
        -H "Host: $CDN_DOMAIN" \
        -H "Connection: Upgrade" -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" \
        --max-time 10 "https://yastatic.net/$RANDOM_PATH?ed=2560" 2>/dev/null | grep -oiE 'HTTP/[0-9.]+ [0-9]+' | head -n 1)
    if ! echo "$ws_status" | grep -q '101'; then
        echo -e "${YELLOW}${WARNING}${NC} Unexpected WebSocket response: ${ws_status:-none}"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Testing origin fallback (expecting 302)"
    local http_status
    http_status=$(curl -skI --max-time 10 "https://$CDN_DOMAIN/" 2>/dev/null | grep -oiE 'HTTP/[0-9.]+ [0-9]+' | head -n 1)
    if ! echo "$http_status" | grep -q '302'; then
        echo -e "${YELLOW}${WARNING}${NC} Unexpected origin response: ${http_status:-none}"
    fi

    echo -e "${GREEN}${CHECK}${NC} CDN verified"
}

#==========================
# MANUAL STEPS
#==========================

continue_by_instruction() {
    echo -e "${YELLOW}${WARNING}${NC} Continue with ws-ya-cdn.md"
    pause_step
}

#==========================
# NODE DELETE FUNCTIONS
#==========================

find_node_to_delete() {
    echo -e "${CYAN}${INFO}${NC} Locating this node in panel..."

    if [ -z "$SELFSTEAL_DOMAIN" ]; then
        echo -e "${RED}${CROSS}${NC} Origin domain unknown (missing saved credentials)"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local nodes_response selected
    nodes_response=$(make_panel_api_request GET "/api/nodes")
    selected=$(echo "$nodes_response" | jq -c --arg addr "$SELFSTEAL_DOMAIN" '[.response[] | select(.address == $addr)] | .[0] // empty')

    if [ -z "$selected" ] || [ "$selected" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} No node found for $SELFSTEAL_DOMAIN"
        exit 1
    fi

    DELETE_NODE_UUID=$(echo "$selected" | jq -r '.uuid')
    DELETE_NODE_NAME=$(echo "$selected" | jq -r '.name')
    DELETE_NODE_ADDRESS=$(echo "$selected" | jq -r '.address')

    echo -e "${GREEN}${CHECK}${NC} Found node $DELETE_NODE_NAME"
}

delete_node_host_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Removing host from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching hosts list"
    local hosts_response
    hosts_response=$(make_panel_api_request GET "/api/hosts")

    local host_uuid
    host_uuid=$(echo "$hosts_response" | jq -r \
        --arg addr "$CDN_DOMAIN" \
        '.response[] | select(.address == $addr) | .uuid' | head -n 1)

    if [ -z "$host_uuid" ] || [ "$host_uuid" = "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} No host found for this node, skipping"
        echo -e "${GREEN}${CHECK}${NC} Host step skipped"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Deleting host"
    local delete_response
    delete_response=$(make_panel_api_request DELETE "/api/hosts/$host_uuid")

    if echo "$delete_response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} Host removed"
    else
        echo -e "${YELLOW}${WARNING}${NC} Host delete response unexpected: $delete_response"
    fi
}

delete_node_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Deleting node from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending delete request"
    local delete_response
    delete_response=$(make_panel_api_request DELETE "/api/nodes/$DELETE_NODE_UUID")

    if echo "$delete_response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} Node deleted from panel"
    else
        echo -e "${RED}${CROSS}${NC} Failed to delete node: $delete_response"
        exit 1
    fi
}

cleanup_node_server() {
    echo -e "${CYAN}${INFO}${NC} Cleaning up server..."

    if [ -f /opt/remnanode/docker-compose.yml ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Docker containers"
        (cd /opt/remnanode && docker compose down > /dev/null 2>&1 || true)
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Removing node directory"
    rm -rf /opt/remnanode

    echo -e "${GRAY}  ${ARROW}${NC} Removing ownCloud data"
    rm -rf /var/www/owncloud

    echo -e "${GRAY}  ${ARROW}${NC} Removing UFW rules"
    ufw delete allow from "$PANEL_IP" to any port 2222 > /dev/null 2>&1 || true
    ufw delete allow 443/tcp > /dev/null 2>&1 || true
    ufw reload > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Server cleanup complete"
}

delete_node() {
    set -e

    echo
    echo -e "${GREEN}Checking panel${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    check_panel_api

    echo
    echo -e "${GREEN}Selecting node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    find_node_to_delete

    echo
    echo -e "${YELLOW}${WARNING}${NC} You are about to delete node: ${WHITE}$DELETE_NODE_NAME${NC} ${GRAY}($DELETE_NODE_ADDRESS)${NC}"
    echo -e "${RED}This will remove the node and its host from the panel and clean up this server.${NC}"
    echo
    echo -ne "${YELLOW}Are you sure? (y/n): ${NC}"
    read -r confirm
    confirm=$(printf '%s' "$confirm" | tr -cd 'a-zA-Z')
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}${WARNING}${NC} Deletion cancelled"
        echo
        exit 0
    fi

    echo
    echo -e "${GREEN}Removing from panel${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    delete_node_host_from_panel
    echo
    delete_node_from_panel

    echo
    echo -e "${GREEN}Cleaning up server${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    cleanup_node_server

    echo
    echo -e "${PURPLE}=========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Node deletion complete"
    echo -e "${PURPLE}=========================${NC}"
    echo
}

#======================
# MAIN ENTRY FUNCTIONS
#======================

install_node() {
    set -e

    INSTALL_DIR="/opt"
    APP_NAME="remnanode"
    APP_DIR="$INSTALL_DIR/$APP_NAME"

    echo
    echo -e "${GREEN}Checking panel${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    check_panel_api

    echo
    echo -e "${GREEN}Installing packages${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    install_system_packages

    echo
    echo -e "${GREEN}Configuring TCP optimizations${NC}"
    echo -e "${GREEN}=============================${NC}"
    echo

    configure_tcp_optimizations

    echo
    echo -e "${GREEN}Preparing installation${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    move_variables_file

    echo
    echo -e "${GREEN}Obtaining certificate${NC}"
    echo -e "${GREEN}=====================${NC}"
    echo

    setup_certificate

    echo
    echo -e "${GREEN}Configuring inbound and node${NC}"
    echo -e "${GREEN}============================${NC}"
    echo

    ensure_ws_inbound_in_profile
    echo
    activate_inbound_in_squad
    echo
    create_node_in_panel

    echo
    echo -e "${GREEN}Installing node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    create_cdn_node
    echo
    start_cdn_services

    echo
    echo -e "${GREEN}Yandex Cloud${NC}"
    echo -e "${GREEN}============${NC}"
    echo

    continue_by_instruction

    echo
    echo -e "${GREEN}Creating host${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    create_cdn_host_in_panel
    save_node_credentials

    echo
    echo -e "${GREEN}Verifying CDN${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    verify_cdn

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    local server_ip
    server_ip=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org || curl -s -4 ipinfo.io/ip)

    echo -e "${CYAN}ownCloud:${NC}"
    echo -e "${WHITE}• Create the admin account at http://${server_ip}:8800/${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check logs: cd /opt/remnanode && docker compose logs -f${NC}"
    echo -e "${WHITE}• Restart service: cd /opt/remnanode && docker compose restart${NC}"
    echo
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    exec < /dev/tty
    check_root
    check_os

    show_main_menu
    read INSTALL_TYPE

    if [ "$NODE_INSTALLED" = true ]; then
        case $INSTALL_TYPE in
            1)
                echo
                echo -e "${PURPLE}==============${NC}"
                echo -e "${WHITE}Node Deletion${NC}"
                echo -e "${PURPLE}==============${NC}"
                load_saved_node_credentials
                delete_node
                ;;
            2)
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting installation..."
                exit 0
                ;;
            *)
                echo
                echo -e "${RED}${CROSS}${NC} Invalid choice. Please select 1-2."
                exit 1
                ;;
        esac
    else
        case $INSTALL_TYPE in
            1)
                echo
                echo -e "${PURPLE}==================${NC}"
                echo -e "${WHITE}Node Installation${NC}"
                echo -e "${PURPLE}==================${NC}"
                echo
                input_panel_ip
                input_node_panel_domain
                input_node_api_token
                input_node_selfsteal_domain
                input_cdn_domain
                input_node_name
                input_host_remark
                input_cloudflare_email
                input_cloudflare_api_key

                echo
                echo -e "${GREEN}Environment variables${NC}"
                echo -e "${GREEN}=====================${NC}"
                echo
                save_node_variables_to_file
                install_node
                ;;
            2)
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting installation..."
                exit 0
                ;;
            *)
                echo
                echo -e "${RED}${CROSS}${NC} Invalid choice. Please select 1-2."
                exit 1
                ;;
        esac
    fi
}

main
exit 0
