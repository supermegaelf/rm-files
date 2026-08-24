#!/bin/bash

#=============
# TG-SUB NODE
#=============

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
    echo -e "${PURPLE}============${NC}"
    echo -e "${WHITE}TG-SUB NODE${NC}"
    echo -e "${PURPLE}============${NC}"
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

extract_domain() {
    local SUBDOMAIN=$1
    echo "$SUBDOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}'
}

input_cloudflare_api_key() {
    echo -ne "${CYAN}Cloudflare API Key: ${NC}"
    read CLOUDFLARE_API_KEY
    while [[ -z "$CLOUDFLARE_API_KEY" ]]; do
        echo -e "${RED}${CROSS}${NC} Cloudflare API Key cannot be empty!"
        echo
        echo -ne "${CYAN}Cloudflare API Key: ${NC}"
        read CLOUDFLARE_API_KEY
    done
}

input_cloudflare_email() {
    echo -ne "${CYAN}Cloudflare Email: ${NC}"
    read CLOUDFLARE_EMAIL
    while [[ -z "$CLOUDFLARE_EMAIL" ]]; do
        echo -e "${RED}${CROSS}${NC} Cloudflare Email cannot be empty!"
        echo
        echo -ne "${CYAN}Cloudflare Email: ${NC}"
        read CLOUDFLARE_EMAIL
    done
}

#======================
# NODE INPUT FUNCTIONS
#======================

input_node_selfsteal_domain() {
    echo -ne "${CYAN}Node self-steal domain (e.g., example.com): ${NC}"
    read SELFSTEAL_DOMAIN
    while [[ -z "$SELFSTEAL_DOMAIN" ]] || ! validate_domain "$SELFSTEAL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Node self-steal domain (e.g., example.com): ${NC}"
        read SELFSTEAL_DOMAIN
    done
}


input_panel_ip() {
    echo -ne "${CYAN}Panel IP address: ${NC}"
    read PANEL_IP
    while [[ -z "$PANEL_IP" ]] || ! validate_ip "$PANEL_IP"; do
        echo -e "${RED}${CROSS}${NC} Invalid IP! Please enter a valid IPv4 address (e.g., 1.2.3.4)."
        echo
        echo -ne "${CYAN}Panel IP address: ${NC}"
        read PANEL_IP
    done
}

input_node_panel_domain() {
    echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
    read PANEL_NODE_DOMAIN
    while [[ -z "$PANEL_NODE_DOMAIN" ]] || ! validate_domain "$PANEL_NODE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read PANEL_NODE_DOMAIN
    done
    PANEL_NODE_URL="https://${PANEL_NODE_DOMAIN}"
}

input_node_api_token() {
    echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
    read PANEL_NODE_TOKEN
    while [[ -z "$PANEL_NODE_TOKEN" ]]; do
        echo -e "${RED}${CROSS}${NC} API token cannot be empty!"
        echo
        echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
        read PANEL_NODE_TOKEN
    done
}

input_node_name() {
    echo -ne "${CYAN}Node name (e.g., NL-1, DE-1, FI-1, PL-1, RU-1): ${NC}"
    read NODE_NAME
    while [[ -z "$NODE_NAME" ]]; do
        echo -e "${RED}${CROSS}${NC} Node name cannot be empty!"
        echo
        echo -ne "${CYAN}Node name: ${NC}"
        read NODE_NAME
    done
}

input_node_host_remark() {
    echo -ne "${CYAN}Host flag (e.g., 🇳🇱, 🇩🇪, 🇫🇮, 🇵🇱, 🇷🇺): ${NC}"
    read HOST_FLAG
    while [[ -z "$HOST_FLAG" ]]; do
        echo -e "${RED}${CROSS}${NC} Host flag cannot be empty!"
        echo
        echo -ne "${CYAN}Host flag: ${NC}"
        read HOST_FLAG
    done
    HOST_REMARK="${HOST_FLAG} Телеграм"
}


NODE_CREDS_FILE="/opt/remnanode/rm-node-config.env"

save_node_credentials() {
    mkdir -p /opt/remnanode
    printf 'PANEL_NODE_DOMAIN="%s"\nPANEL_NODE_TOKEN="%s"\nPANEL_IP="%s"\n' \
        "$PANEL_NODE_DOMAIN" "$PANEL_NODE_TOKEN" "$PANEL_IP" > "$NODE_CREDS_FILE"
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
        save_node_credentials
    fi
}

save_node_variables_to_file() {
    echo -e "${CYAN}${INFO}${NC} Saving node configuration variables..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating variables file"
    cat > remnawave-node-vars.sh << EOF
# User provided node configuration
export SELFSTEAL_DOMAIN="$SELFSTEAL_DOMAIN"
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
    if ! ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1 || ! ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1 || ! ufw --force enable > /dev/null 2>&1; then
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
    local allow_cf_proxy="${3:-true}"

    local domain_ip=$(dig +short A "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
    local server_ip=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org || curl -s -4 ipinfo.io/ip)

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

    local cf_ranges=$(curl -s https://www.cloudflare.com/ips-v4)
    local cf_array=()
    if [ -n "$cf_ranges" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && cf_array+=("$line")
        done <<< "$cf_ranges"
    fi

    local ip_in_cloudflare=false
    local IFS='.'
    read -r a b c d <<<"$domain_ip"
    local domain_ip_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))

    if [ ${#cf_array[@]} -gt 0 ]; then
        for cidr in "${cf_array[@]}"; do
            if [[ -z "$cidr" ]]; then
                continue
            fi
            local network=$(echo "$cidr" | cut -d'/' -f1)
            local mask=$(echo "$cidr" | cut -d'/' -f2)
            read -r a b c d <<<"$network"
            local network_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))
            local mask_bits=$(( 32 - mask ))
            local range_size=$(( 1 << mask_bits ))
            local min_ip_int=$network_int
            local max_ip_int=$(( network_int + range_size - 1 ))

            if [ "$domain_ip_int" -ge "$min_ip_int" ] && [ "$domain_ip_int" -le "$max_ip_int" ]; then
                ip_in_cloudflare=true
                break
            fi
        done
    fi

    if [ "$domain_ip" = "$server_ip" ]; then
        return 0
    elif [ "$ip_in_cloudflare" = true ]; then
        if [ "$allow_cf_proxy" = true ]; then
            return 0
        else
            if [ "$show_warning" = true ]; then
                echo -e "${YELLOW}${WARNING}${NC} ${RED}The domain $domain points to a Cloudflare IP ($domain_ip).${NC}"
                echo -e "${YELLOW}Cloudflare proxying is not allowed for the selfsteal domain. Disable proxying (switch to 'DNS Only').${NC}"
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
    else
        if [ "$show_warning" = true ]; then
            echo -e "${YELLOW}${WARNING}${NC} ${RED}The domain $domain points to IP address $domain_ip, which differs from this server's IP ($server_ip).${NC}"
            echo -e "${YELLOW}For proper operation, the domain must point to the current server.${NC}"
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

    return 0
}

is_wildcard_cert() {
    local domain=$1
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"

    if [ ! -f "$cert_path" ]; then
        return 1
    fi

    if openssl x509 -noout -text -in "$cert_path" | grep -q "\*\.$domain"; then
        return 0
    else
        return 1
    fi
}

check_certificates() {
    local DOMAIN=$1
    local cert_dir="/etc/letsencrypt/live"

    if [ ! -d "$cert_dir" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Certificate not found for $DOMAIN${NC}"
        return 1
    fi

    local live_dir=$(find "$cert_dir" -maxdepth 1 -type d -name "${DOMAIN}*" 2>/dev/null | sort -V | tail -n 1)
    if [ -n "$live_dir" ] && [ -d "$live_dir" ]; then
        local files=("cert.pem" "chain.pem" "fullchain.pem" "privkey.pem")
        for file in "${files[@]}"; do
            local file_path="$live_dir/$file"
            if [ ! -f "$file_path" ]; then
                echo -e "${GRAY}  ${ARROW}${NC} Certificate not found for $DOMAIN (missing $file)${NC}"
                return 1
            fi
            if [ ! -L "$file_path" ]; then
                fix_letsencrypt_structure "$(basename "$live_dir")"
                if [ $? -ne 0 ]; then
                    echo -e "${GRAY}  ${ARROW}${NC} Certificate not found for $DOMAIN (failed to fix structure)${NC}"
                    return 1
                fi
            fi
        done
        echo -e "${GRAY}  ${ARROW}${NC} Certificates for $(basename "$live_dir")"
        return 0
    fi

    local base_domain=$(extract_domain "$DOMAIN")
    if [ "$base_domain" != "$DOMAIN" ]; then
        live_dir=$(find "$cert_dir" -maxdepth 1 -type d -name "${base_domain}*" 2>/dev/null | sort -V | tail -n 1)
        if [ -n "$live_dir" ] && [ -d "$live_dir" ] && is_wildcard_cert "$base_domain"; then
            echo -e "${GRAY}  ${ARROW}${NC} Wildcard certificate found for $DOMAIN"
            return 0
        fi
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Certificate not found for $DOMAIN${NC}"
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
            echo -e "${GREEN}Cloudflare API key and email are valid${NC}"
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

get_certificates() {
    local DOMAIN=$1
    local BASE_DOMAIN=$(extract_domain "$DOMAIN")
    local WILDCARD_DOMAIN="*.$BASE_DOMAIN"

    if [ -d "/etc/letsencrypt/live/$BASE_DOMAIN" ] && is_wildcard_cert "$BASE_DOMAIN"; then
        echo -e "${GREEN}${CHECK}${NC} Wildcard certificate already exists for $BASE_DOMAIN"
        return 0
    fi

    if [[ -z "$CLOUDFLARE_EMAIL" || -z "$CLOUDFLARE_API_KEY" ]]; then
        echo -e "${YELLOW}${WARNING}${NC} Cloudflare credentials not provided. Skipping SSL certificate generation."
        echo -e "${YELLOW}You can manually obtain certificates later or use existing ones.${NC}"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Generating wildcard certificates for $BASE_DOMAIN"

    mkdir -p ~/.secrets/certbot > /dev/null 2>&1
    cat > ~/.secrets/certbot/cloudflare.ini <<EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_key = $CLOUDFLARE_API_KEY
EOF
    chmod 600 ~/.secrets/certbot/cloudflare.ini

    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 30 \
        -d "$BASE_DOMAIN" \
        -d "$WILDCARD_DOMAIN" \
        --email "$CLOUDFLARE_EMAIL" \
        --agree-tos \
        --non-interactive \
        --key-type ecdsa \
        --elliptic-curve secp384r1 > /dev/null 2>&1; then
        echo -e "${GRAY}  ${ARROW}${NC} Successfully received certificates for $BASE_DOMAIN"
    else
        echo -e "${RED}  ${CROSS}${NC} Failed to generate certificates for $BASE_DOMAIN"
        return 1
    fi

    if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        echo -e "${RED}Certificate generation failed for $DOMAIN${NC}"
        exit 1
    fi
}

check_cert_expiry() {
    local domain="$1"
    local cert_dir="/etc/letsencrypt/live"
    local live_dir=$(find "$cert_dir" -maxdepth 1 -type d -name "${domain}*" | sort -V | tail -n 1)
    if [ -z "$live_dir" ] || [ ! -d "$live_dir" ]; then
        return 1
    fi
    local cert_file="$live_dir/fullchain.pem"
    if [ ! -f "$cert_file" ]; then
        return 1
    fi
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//')
    if [ -z "$expiry_date" ]; then
        echo -e "${RED}Error parsing certificate expiry date.${NC}"
        return 1
    fi
    local expiry_epoch=$(TZ=UTC date -d "$expiry_date" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error parsing certificate expiry date.${NC}"
        return 1
    fi
    local current_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    echo "$days_left"
    return 0
}

fix_letsencrypt_structure() {
    local domain=$1
    local live_dir="/etc/letsencrypt/live/$domain"
    local archive_dir="/etc/letsencrypt/archive/$domain"
    local renewal_conf="/etc/letsencrypt/renewal/$domain.conf"

    if [ ! -d "$live_dir" ]; then
        echo -e "${RED}Certificate not found${NC}"
        return 1
    fi
    if [ ! -d "$archive_dir" ]; then
        echo -e "${RED}Archive directory not found${NC}"
        return 1
    fi
    if [ ! -f "$renewal_conf" ]; then
        echo -e "${RED}Renewal configuration not found${NC}"
        return 1
    fi

    local conf_archive_dir=$(grep "^archive_dir" "$renewal_conf" | cut -d'=' -f2 | tr -d ' ')
    if [ "$conf_archive_dir" != "$archive_dir" ]; then
        echo -e "${RED}Archive directory mismatch${NC}"
        return 1
    fi

    local latest_version=$(ls -1 "$archive_dir" | grep -E 'cert[0-9]+.pem' | sort -V | tail -n 1 | sed -E 's/.*cert([0-9]+)\.pem/\1/')
    if [ -z "$latest_version" ]; then
        echo -e "${RED}Certificate version not found${NC}"
        return 1
    fi

    local files=("cert" "chain" "fullchain" "privkey")
    for file in "${files[@]}"; do
        local archive_file="$archive_dir/$file$latest_version.pem"
        local live_file="$live_dir/$file.pem"
        if [ ! -f "$archive_file" ]; then
            echo -e "${RED}File not found: $archive_file${NC}"
            return 1
        fi
        if [ -f "$live_file" ] && [ ! -L "$live_file" ]; then
            rm "$live_file"
        fi
        ln -sf "$archive_file" "$live_file"
    done

    local cert_path="$live_dir/cert.pem"
    local chain_path="$live_dir/chain.pem"
    local fullchain_path="$live_dir/fullchain.pem"
    local privkey_path="$live_dir/privkey.pem"
    if ! grep -q "^cert = $cert_path" "$renewal_conf"; then
        sed -i "s|^cert =.*|cert = $cert_path|" "$renewal_conf"
    fi
    if ! grep -q "^chain = $chain_path" "$renewal_conf"; then
        sed -i "s|^chain =.*|chain = $chain_path|" "$renewal_conf"
    fi
    if ! grep -q "^fullchain = $fullchain_path" "$renewal_conf"; then
        sed -i "s|^fullchain =.*|fullchain = $fullchain_path|" "$renewal_conf"
    fi
    if ! grep -q "^privkey = $privkey_path" "$renewal_conf"; then
        sed -i "s|^privkey =.*|privkey = $privkey_path|" "$renewal_conf"
    fi

    local target_dir="/opt/remnawave"
    if [ -d "/opt/remnanode" ]; then
        target_dir="/opt/remnanode"
    fi
    local expected_hook="renew_hook = sh -c 'cd $target_dir && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx && docker compose exec remnawave-nginx nginx -s reload'"
    sed -i '/^renew_hook/d' "$renewal_conf"
    echo "$expected_hook" >> "$renewal_conf"

    chmod 644 "$live_dir/cert.pem" "$live_dir/chain.pem" "$live_dir/fullchain.pem"
    chmod 600 "$live_dir/privkey.pem"
    return 0
}

handle_certificates() {
    local -n domains_to_check_ref=$1
    local cert_method="$2"
    local letsencrypt_email="$3"
    local target_dir="${4:-/opt/remnawave}"

    declare -A unique_domains
    local need_certificates=false
    local min_days_left=9999

    echo -e "${CYAN}${INFO}${NC} Checking certificates..."
    sleep 1

    for domain in "${!domains_to_check_ref[@]}"; do
        if ! check_certificates "$domain"; then
            need_certificates=true
        else
            if days_left=$(check_cert_expiry "$domain"); then
                if [ "$days_left" -lt "$min_days_left" ]; then
                    min_days_left=$days_left
                fi
            fi
        fi
    done

    if [ "$need_certificates" = true ]; then
        cert_method="1"
    else
        echo -e "${GREEN}${CHECK}${NC} All certificates already exist"
        echo
        cert_method="1"
    fi

    declare -A cert_domains_added
    if [ "$need_certificates" = true ] && [ "$cert_method" == "1" ]; then
        for domain in "${!domains_to_check_ref[@]}"; do
            local base_domain=$(extract_domain "$domain")
            unique_domains["$base_domain"]="1"
        done

        for domain in "${!unique_domains[@]}"; do
            get_certificates "$domain"
            if [ $? -ne 0 ]; then
                echo -e "${RED}Certificate generation failed. Please check your input and DNS settings. $domain${NC}"
                return 1
            fi
            min_days_left=90
            if [ -z "${cert_domains_added[$domain]}" ]; then
                echo "      - /etc/letsencrypt/live/$domain/fullchain.pem:/etc/nginx/ssl/$domain/fullchain.pem:ro" >> "$target_dir/docker-compose.yml"
                echo "      - /etc/letsencrypt/live/$domain/privkey.pem:/etc/nginx/ssl/$domain/privkey.pem:ro" >> "$target_dir/docker-compose.yml"
                cert_domains_added["$domain"]="1"
            fi
        done
        echo -e "${GREEN}${CHECK}${NC} Certificates created successfully"
        echo
    else
        for domain in "${!domains_to_check_ref[@]}"; do
            local base_domain=$(extract_domain "$domain")
            local cert_domain="$domain"
            if [ -d "/etc/letsencrypt/live/$base_domain" ] && is_wildcard_cert "$base_domain"; then
                cert_domain="$base_domain"
            fi
            if [ -z "${cert_domains_added[$cert_domain]}" ]; then
                echo "      - /etc/letsencrypt/live/$cert_domain/fullchain.pem:/etc/nginx/ssl/$cert_domain/fullchain.pem:ro" >> "$target_dir/docker-compose.yml"
                echo "      - /etc/letsencrypt/live/$cert_domain/privkey.pem:/etc/nginx/ssl/$cert_domain/privkey.pem:ro" >> "$target_dir/docker-compose.yml"
                cert_domains_added["$cert_domain"]="1"
            fi
        done
    fi

    local cron_command="/usr/bin/certbot renew --quiet"

    echo -e "${CYAN}${INFO}${NC} Configuring certificate renewal..."
    if ! crontab -u root -l 2>/dev/null | grep -q "/usr/bin/certbot renew"; then
        echo -e "${GRAY}  ${ARROW}${NC} Adding cron job for certificate renewal"
        if [ "$min_days_left" -le 30 ]; then
            echo -e "${GRAY}  ${ARROW}${NC} Certificates will expire soon in $min_days_left days"
            add_cron_rule "0 5 * * * $cron_command"
        else
            add_cron_rule "0 5 1 */2 * $cron_command"
        fi
        echo -e "${GREEN}${CHECK}${NC} Certificate renewal configured"
        echo
    else
        echo -e "${GRAY}  ${ARROW}${NC} Cron job for certificate renewal already exists"
        echo -e "${GREEN}${CHECK}${NC} Certificate renewal configured"
        echo
    fi

    for domain in "${!unique_domains[@]}"; do
        if [ -f "/etc/letsencrypt/renewal/$domain.conf" ]; then
            desired_hook="renew_hook = sh -c 'cd $target_dir && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'"
            if ! grep -q "renew_hook" "/etc/letsencrypt/renewal/$domain.conf"; then
                echo "$desired_hook" >> "/etc/letsencrypt/renewal/$domain.conf"
            elif ! grep -Fx "$desired_hook" "/etc/letsencrypt/renewal/$domain.conf"; then
                sed -i "/renew_hook/c\\$desired_hook" "/etc/letsencrypt/renewal/$domain.conf"
                echo -e "${YELLOW}Updating cron job to match certificate expiry.${NC}"
            fi
        fi
    done
}

#===============================
# TEMPLATE MANAGEMENT FUNCTIONS
#===============================

randomhtml() {
    local template_source="$1"

    cd /opt/ || { echo "Error unpacking archive"; exit 1; }

    rm -f main.zip 2>/dev/null
    rm -rf simple-web-templates-main/ 2>/dev/null

    echo -e "${GRAY}  ${ARROW}${NC} Installing random template for camouflage site"
    echo -e "${GRAY}  ${ARROW}${NC} Downloading and extracting template"

    template_urls=(
        "https://github.com/supermegaelf/simple-web-templates/archive/refs/heads/main.zip"
    )

    selected_url=${template_urls[0]}

    while ! wget -q --timeout=30 --tries=10 --retry-connrefused "$selected_url"; do
        echo "Download failed, retrying..."
        sleep 3
    done

    unzip -o main.zip &>/dev/null || { echo "Error unpacking archive"; exit 1; }
    rm -f main.zip

    cd simple-web-templates-main/ || { echo "Error unpacking archive"; exit 1; }
    rm -rf assets ".gitattributes" "README.md" "_config.yml" 2>/dev/null

    mapfile -t templates < <(find . -maxdepth 1 -type d -not -path . | sed 's|./||')

    RandomHTML="${templates[$RANDOM % ${#templates[@]}]}"

    local random_meta_id=$(openssl rand -hex 16)
    local random_comment=$(openssl rand -hex 8)
    local random_class_suffix=$(openssl rand -hex 4)
    local random_title_prefix="Page_"
    local random_title_suffix=$(openssl rand -hex 4)
    local random_footer_text="Designed by RandomSite_${random_title_suffix}"
    local random_id_suffix=$(openssl rand -hex 4)

    local meta_names=("viewport-id" "session-id" "track-id" "render-id" "page-id" "config-id")
    local random_meta_name=${meta_names[$RANDOM % ${#meta_names[@]}]}

    local class_prefixes=("style" "data" "ui" "layout" "theme" "view")
    local random_class_prefix=${class_prefixes[$RANDOM % ${#class_prefixes[@]}]}
    local random_class="$random_class_prefix-$random_class_suffix"
    local random_title="${random_title_prefix}${random_title_suffix}"

    find "./$RandomHTML" -type f -name "*.html" -exec sed -i \
        -e "s|<!-- Website template by freewebsitetemplates.com -->||" \
        -e "s|<!-- Theme by: WebThemez.com -->||" \
        -e "s|<a href=\"http://freewebsitetemplates.com\">Free Website Templates</a>|<span>${random_footer_text}</span>|" \
        -e "s|<a href=\"http://webthemez.com\" alt=\"webthemez\">WebThemez.com</a>|<span>${random_footer_text}</span>|" \
        -e "s|id=\"Content\"|id=\"rnd_${random_id_suffix}\"|" \
        -e "s|id=\"subscribe\"|id=\"sub_${random_id_suffix}\"|" \
        -e "s|<title>.*</title>|<title>${random_title}</title>|" \
        -e "s/<\/head>/<meta name=\"$random_meta_name\" content=\"$random_meta_id\">\n<!-- $random_comment -->\n<\/head>/" \
        -e "s/<body/<body class=\"$random_class\"/" \
        {} \;

    find "./$RandomHTML" -type f -name "*.css" -exec sed -i \
        -e "1i\/* $random_comment */" \
        -e "1i.$random_class { display: block; }" \
        {} \;

    echo -e "${GRAY}  ${ARROW}${NC} Selected template: $RandomHTML"

    if [[ -d "${RandomHTML}" ]]; then
        if [[ ! -d "/var/www/html/" ]]; then
            mkdir -p "/var/www/html/" || { echo "Failed to create /var/www/html/"; exit 1; }
        fi
        rm -rf /var/www/html/*
        cp -a "${RandomHTML}"/. "/var/www/html/"
        echo -e "${GRAY}  ${ARROW}${NC} Template copied to /var/www/html/"
    else
        echo "Error unpacking archive" && exit 1
    fi

    if ! find "/var/www/html" -type f -name "*.html" -exec grep -q "$random_meta_name" {} \; 2>/dev/null; then
        echo -e "${RED}Failed to modify HTML files${NC}"
        return 1
    fi

    cd /opt/
    rm -rf simple-web-templates-main/
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

create_node_in_panel() {
    echo -e "${CYAN}${INFO}${NC} Creating node in panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local node_data
    node_data=$(jq -n \
        --arg name "$NODE_NAME" \
        --arg address "$SELFSTEAL_DOMAIN" \
        --arg profile_uuid "$NEW_PROFILE_UUID" \
        --arg inbound_uuid "$NEW_PROFILE_INBOUND_UUID" \
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

create_node_host_in_panel() {
    echo -e "${CYAN}${INFO}${NC} Creating host in panel..."

    local hosts_response
    hosts_response=$(make_panel_api_request GET "/api/hosts")
    local existing_uuid
    existing_uuid=$(echo "$hosts_response" | jq -r --arg addr "$SELFSTEAL_DOMAIN" '(.response // [])[] | select(.address == $addr) | .uuid' | head -n 1)
    if [ -n "$existing_uuid" ] && [ "$existing_uuid" != "null" ]; then
        echo -e "${GREEN}${CHECK}${NC} Host created"
        return 0
    fi

    local tmpl_uuid tmpl_response
    tmpl_response=$(make_panel_api_request GET "/api/subscription-templates")
    tmpl_uuid=$(echo "$tmpl_response" | jq -r '[.. | objects | select(.name? == "tg" and .templateType? == "XRAY_JSON") | .uuid] | .[0] // empty')
    if [ -n "$tmpl_uuid" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Binding Xray JSON template tg"
    else
        echo -e "${YELLOW}  ${WARNING}${NC} Xray JSON template tg not found, host created without client routing"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Building host config"
    local host_data
    host_data=$(jq -n \
        --arg remark "$HOST_REMARK" \
        --arg address "$SELFSTEAL_DOMAIN" \
        --arg profile_uuid "$NEW_PROFILE_UUID" \
        --arg inbound_uuid "$NEW_PROFILE_INBOUND_UUID" \
        --arg tmpl "$tmpl_uuid" \
        '{
            remark: $remark,
            address: $address,
            port: 443,
            sni: $address,
            fingerprint: "firefox",
            allowInsecure: false,
            isDisabled: false,
            inbound: {
                configProfileUuid: $profile_uuid,
                configProfileInboundUuid: $inbound_uuid
            }
        } + (if $tmpl != "" then {xrayJsonTemplateUuid: $tmpl} else {} end)')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local host_response
    host_response=$(make_panel_api_request POST "/api/hosts" "$host_data")

    if ! echo "$host_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to create host: $host_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Host created"
}

create_tg_config_profile() {
    echo -e "${CYAN}${INFO}${NC} Creating TG-Only config profile..."

    local profiles_response
    profiles_response=$(make_panel_api_request GET "/api/config-profiles")
    NEW_PROFILE_UUID=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "TG-Only") | .uuid' | head -n1)
    if [ -n "$NEW_PROFILE_UUID" ] && [ "$NEW_PROFILE_UUID" != "null" ]; then
        NEW_PROFILE_INBOUND_UUID=$(echo "$profiles_response" | jq -r --arg u "$NEW_PROFILE_UUID" '.response.configProfiles[] | select(.uuid == $u) | .inbounds[0].uuid')
        echo -e "${GRAY}  ${ARROW}${NC} Profile exists, reusing"
        echo -e "${GREEN}${CHECK}${NC} TG-Only profile reused"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Generating x25519 keys"
    local key_response
    key_response=$(make_panel_api_request GET "/api/system/tools/x25519/generate")
    local private_key
    private_key=$(echo "$key_response" | jq -r '.response.keypairs[0].privateKey')
    if [ -z "$private_key" ] || [ "$private_key" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to generate keys: $key_response"
        exit 1
    fi

    local short_id
    short_id=$(openssl rand -hex 8)

    echo -e "${GRAY}  ${ARROW}${NC} Building profile"
    local request_body
    request_body=$(jq -n \
        --arg name "TG-Only" \
        --arg domain "$SELFSTEAL_DOMAIN" \
        --arg private_key "$private_key" \
        --arg short_id "$short_id" \
        '{
        name: $name,
        config: {
            log: { loglevel: "warning" },
            dns: {
                queryStrategy: "ForceIPv4",
                servers: [{ address: "https://dns.google/dns-query", skipFallback: false }]
            },
            inbounds: [{
                tag: "Vless TCP REALITY",
                port: 443,
                protocol: "vless",
                settings: { clients: [], decryption: "none" },
                streamSettings: {
                    network: "tcp",
                    security: "reality",
                    realitySettings: {
                        target: "/dev/shm/nginx.sock",
                        show: false,
                        xver: 1,
                        shortIds: [$short_id],
                        privateKey: $private_key,
                        serverNames: [$domain]
                    }
                },
                sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] }
            }],
            outbounds: [
                { tag: "DIRECT", protocol: "freedom" },
                { tag: "BLOCK", protocol: "blackhole" }
            ],
            routing: {
                domainStrategy: "IPIfNonMatch",
                rules: [
                    { type: "field", ip: ["91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24", "95.161.64.0/20"], network: "tcp,udp", outboundTag: "DIRECT" },
                    { type: "field", domain: ["geosite:telegram"], outboundTag: "DIRECT" },
                    { type: "field", network: "tcp,udp", outboundTag: "BLOCK" }
                ]
            }
        }
    }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local response
    response=$(make_panel_api_request POST "/api/config-profiles" "$request_body")

    NEW_PROFILE_UUID=$(echo "$response" | jq -r '.response.uuid')
    NEW_PROFILE_INBOUND_UUID=$(echo "$response" | jq -r '.response.inbounds[0].uuid')

    if [ -z "$NEW_PROFILE_UUID" ] || [ "$NEW_PROFILE_UUID" = "null" ] || [ -z "$NEW_PROFILE_INBOUND_UUID" ] || [ "$NEW_PROFILE_INBOUND_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create profile: $response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} TG-Only profile created"
}

create_tg_squad() {
    echo -e "${CYAN}${INFO}${NC} Creating TG-Only squad..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local body response
    body=$(jq -n --arg inbound "$NEW_PROFILE_INBOUND_UUID" \
        '{ name: "TG-Only", inbounds: [$inbound] }')
    response=$(make_panel_api_request POST "/api/internal-squads" "$body")

    TG_SQUAD_UUID=$(echo "$response" | jq -r '.response.uuid')
    if [ -z "$TG_SQUAD_UUID" ] || [ "$TG_SQUAD_UUID" = "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Squad exists, rebinding to new inbound"
        local squads_response
        squads_response=$(make_panel_api_request GET "/api/internal-squads")
        TG_SQUAD_UUID=$(echo "$squads_response" | jq -r '.response.internalSquads[] | select(.name == "TG-Only") | .uuid' | head -n1)
        if [ -z "$TG_SQUAD_UUID" ] || [ "$TG_SQUAD_UUID" = "null" ]; then
            echo -e "${RED}${CROSS}${NC} Failed to create squad: $response"
            exit 1
        fi
        local rebind_body rebind_response
        rebind_body=$(jq -n --arg uuid "$TG_SQUAD_UUID" --arg inbound "$NEW_PROFILE_INBOUND_UUID" \
            '{ uuid: $uuid, inbounds: [$inbound] }')
        rebind_response=$(make_panel_api_request PATCH "/api/internal-squads" "$rebind_body")
        if ! echo "$rebind_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to rebind squad: $rebind_response"
            exit 1
        fi
        echo -e "${GREEN}${CHECK}${NC} TG-Only squad reused"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} TG-Only squad created"
}

create_tg_service_user() {
    echo -e "${CYAN}${INFO}${NC} Creating tg-service user..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local body response
    body=$(jq -n --arg sq "$TG_SQUAD_UUID" '{
        username: "tg-service",
        status: "ACTIVE",
        trafficLimitBytes: 0,
        trafficLimitStrategy: "NO_RESET",
        expireAt: "2099-01-01T00:00:00.000Z",
        activeInternalSquads: [$sq]
    }')
    response=$(make_panel_api_request POST "/api/users" "$body")

    TG_SERVICE_SHORT_UUID=$(echo "$response" | jq -r '.response.shortUuid')
    if [ -z "$TG_SERVICE_SHORT_UUID" ] || [ "$TG_SERVICE_SHORT_UUID" = "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} User exists, reassigning to TG-Only squad"
        local user_response user_id
        user_response=$(make_panel_api_request GET "/api/users/by-username/tg-service")
        user_id=$(echo "$user_response" | jq -r '.response.id // empty')
        TG_SERVICE_SHORT_UUID=$(echo "$user_response" | jq -r '.response.shortUuid // empty')
        if [ -z "$user_id" ] || [ -z "$TG_SERVICE_SHORT_UUID" ]; then
            echo -e "${RED}${CROSS}${NC} Failed to create user: $response"
            exit 1
        fi
        local reassign_body reassign_response
        reassign_body=$(jq -n --argjson id "$user_id" --arg sq "$TG_SQUAD_UUID" \
            '{
                id: $id,
                status: "ACTIVE",
                trafficLimitBytes: 0,
                trafficLimitStrategy: "NO_RESET",
                expireAt: "2099-01-01T00:00:00.000Z",
                activeInternalSquads: [$sq]
            }')
        reassign_response=$(make_panel_api_request PATCH "/api/users" "$reassign_body")
        if ! echo "$reassign_response" | jq -e '.response.id' > /dev/null 2>&1; then
            echo -e "${RED}${CROSS}${NC} Failed to reassign user: $reassign_response"
            exit 1
        fi
        echo -e "${GREEN}${CHECK}${NC} tg-service user reused (shortUuid: ${TG_SERVICE_SHORT_UUID})"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} tg-service user created (shortUuid: ${TG_SERVICE_SHORT_UUID})"
}

#=============================
# NODE INSTALLATION FUNCTIONS
#=============================

create_node() {
    mkdir -p /opt/remnanode && cd /opt/remnanode

    check_domain "$SELFSTEAL_DOMAIN" true false
    local domain_check_result=$?
    if [ $domain_check_result -eq 2 ]; then
        echo -e "${RED}Installation aborted by user${NC}"
        exit 1
    fi

    cat > .env-node <<EOL
### APP ###
NODE_PORT=2222

### XRAY ###
SECRET_KEY=$(echo -e "$CERTIFICATE" | sed 's/\\n$//')
EOL

    local SELFSTEAL_BASE_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")
    declare -A unique_domains
    unique_domains["$SELFSTEAL_BASE_DOMAIN"]=1

    declare -A domains_to_check
    domains_to_check["$SELFSTEAL_DOMAIN"]=1
    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL" "/opt/remnanode"

    NODE_CERT_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")

    cat > docker-compose.yml <<EOF
services:
  remnawave-nginx:
    image: nginx:1.28
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    restart: always
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /dev/shm:/dev/shm:rw
      - /var/www/html:/var/www/html:ro
      - /etc/letsencrypt/live/${NODE_CERT_DOMAIN}/fullchain.pem:/etc/nginx/ssl/${NODE_CERT_DOMAIN}/fullchain.pem:ro
      - /etc/letsencrypt/live/${NODE_CERT_DOMAIN}/privkey.pem:/etc/nginx/ssl/${NODE_CERT_DOMAIN}/privkey.pem:ro
    command: sh -c 'rm -f /dev/shm/nginx.sock && nginx -g "daemon off;"'
    network_mode: host
    depends_on:
      - remnanode
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

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
EOF
}

start_node_services() {
    sleep 1

    local NODE_CERT_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")

    echo -e "${CYAN}${INFO}${NC} Configuring Docker Compose..."

    echo -e "${GRAY}  ${ARROW}${NC} Configuring SSL and Unix socket"
    cat > /opt/remnanode/nginx.conf <<EOL
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;

server {
    server_name $SELFSTEAL_DOMAIN;
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$NODE_CERT_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$NODE_CERT_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$NODE_CERT_DOMAIN/fullchain.pem";

    access_log /dev/null;
    error_log /dev/null;

    root /var/www/html;
    index index.html;
}

server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;

    access_log /dev/null;
    error_log /dev/null;

    ssl_reject_handshake on;
    return 444;
}
EOL

    echo -e "${GRAY}  ${ARROW}${NC} Allowing panel IP to node port"
    ufw allow from $PANEL_IP to any port 2222 > /dev/null 2>&1
    ufw reload > /dev/null 2>&1

    echo -e "${GRAY}  ${ARROW}${NC} Launching node services"
    sleep 3
    cd /opt/remnanode
    if ! docker_compose_up; then
        echo -e "${RED}${CROSS}${NC} Failed to start Docker containers:"
        cat /tmp/.compose.log
        exit 1
    fi
    echo -e "${GREEN}${CHECK}${NC} Docker containers started successfully"
    echo
    echo -e "${CYAN}${INFO}${NC} Installing camouflage template..."
    echo -e "${GRAY}  ${ARROW}${NC} Selecting random template"
    randomhtml
    echo -e "${GREEN}${CHECK}${NC} Camouflage template installed successfully"
    echo
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^remnabridge-nginx$"; then
        echo -e "${CYAN}${INFO}${NC} Bridge server detected, skipping connection check"
    else
        echo -e "${CYAN}${INFO}${NC} Checking node connection..."
        local max_attempts=5
        local attempt=1
        local delay=15

        while [ $attempt -le $max_attempts ]; do
            echo -e "${GRAY}  ${ARROW}${NC} Attempt $attempt of $max_attempts"
            if curl -sk --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -qi "html"; then
                echo -e "${GREEN}${CHECK}${NC} Node connection established successfully"
                break
            else
                echo -e "${GRAY}  ${ARROW}${NC} Node unavailable on attempt $attempt"
                if [ $attempt -eq $max_attempts ]; then
                    echo -e "${RED}${CROSS}${NC} Node connection failed"
                    echo -e "${YELLOW}${WARNING}${NC} Check configuration or restart panel"
                    echo
                    exit 1
                fi
                sleep $delay
            fi
            ((attempt++))
        done
    fi
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

#==========================
# NODE DELETE FUNCTIONS
#==========================

list_nodes_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Fetching TG-Only nodes from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local nodes_response
    nodes_response=$(make_panel_api_request GET "/api/nodes")

    echo -e "${GRAY}  ${ARROW}${NC} Filtering TG-Only nodes"
    local profiles_response
    profiles_response=$(make_panel_api_request GET "/api/config-profiles")

    local tg_profile_uuids
    tg_profile_uuids=$(echo "$profiles_response" | jq -c '[.response.configProfiles[] | select(.name == "TG-Only") | .uuid]')

    NODE_LIST_JSON=$(echo "$nodes_response" | jq -c --argjson tg "$tg_profile_uuids" \
        '[.response[] | select((.configProfile.activeConfigProfileUuid // "") as $u | ($tg | index($u)) != null)]')

    NODE_COUNT=$(echo "$NODE_LIST_JSON" | jq 'length')

    if [ -z "$NODE_COUNT" ] || [ "$NODE_COUNT" = "null" ] || [ "$NODE_COUNT" -eq 0 ]; then
        echo -e "${RED}${CROSS}${NC} No TG-Only nodes found in panel"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Found $NODE_COUNT TG-Only node(s)"
}

select_node_to_delete() {
    local selected_node
    selected_node=$(echo "$NODE_LIST_JSON" | jq -c '.[0]')

    DELETE_NODE_UUID=$(echo "$selected_node" | jq -r '.uuid')
    DELETE_NODE_NAME=$(echo "$selected_node" | jq -r '.name')
    DELETE_NODE_ADDRESS=$(echo "$selected_node" | jq -r '.address')
    DELETE_NODE_PROFILE_UUID=$(echo "$selected_node" | jq -r '.configProfile.activeConfigProfileUuid // empty')
}

delete_tg_service_user_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Removing tg-service user from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Looking up user"
    local user_response user_id
    user_response=$(make_panel_api_request GET "/api/users/by-username/tg-service")
    user_id=$(echo "$user_response" | jq -r '.response.id // empty')

    if [ -z "$user_id" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} User not found, skipping"
        echo -e "${GREEN}${CHECK}${NC} User step skipped"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Deleting user"
    local delete_response
    delete_response=$(make_panel_api_request DELETE "/api/users/${user_id}")

    if echo "$delete_response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} tg-service user removed"
    else
        echo -e "${YELLOW}  ${WARNING}${NC} User delete response unexpected: $delete_response"
    fi
}

delete_tg_squad_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Removing TG-Only squad from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Looking up squad"
    local squads_response squad_uuid
    squads_response=$(make_panel_api_request GET "/api/internal-squads")
    squad_uuid=$(echo "$squads_response" | jq -r '.response.internalSquads[] | select(.name == "TG-Only") | .uuid' | head -n1)

    if [ -z "$squad_uuid" ] || [ "$squad_uuid" = "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Squad not found, skipping"
        echo -e "${GREEN}${CHECK}${NC} Squad step skipped"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Deleting squad"
    local delete_response
    delete_response=$(make_panel_api_request DELETE "/api/internal-squads/${squad_uuid}")

    if echo "$delete_response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} TG-Only squad removed"
    else
        echo -e "${YELLOW}  ${WARNING}${NC} Squad delete response unexpected: $delete_response"
    fi
}

delete_node_host_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Removing host from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching hosts list"
    local hosts_response
    hosts_response=$(make_panel_api_request GET "/api/hosts")

    local host_uuid
    host_uuid=$(echo "$hosts_response" | jq -r \
        --arg addr "$DELETE_NODE_ADDRESS" \
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

delete_tg_config_profile_from_panel() {
    echo -e "${CYAN}${INFO}${NC} Removing TG-Only profile from panel..."

    if [ -z "$DELETE_NODE_PROFILE_UUID" ] || [ "$DELETE_NODE_PROFILE_UUID" = "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Node had no config profile, skipping"
        echo -e "${GREEN}${CHECK}${NC} Profile step skipped"
        return 0
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Deleting profile ${DELETE_NODE_PROFILE_UUID}"
    local delete_response
    delete_response=$(make_panel_api_request DELETE "/api/config-profiles/${DELETE_NODE_PROFILE_UUID}")

    if ! echo "$delete_response" | jq -e '.response.isDeleted == true' > /dev/null 2>&1; then
        echo -e "${YELLOW}  ${WARNING}${NC} Failed to delete profile: $delete_response"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} TG-Only profile removed"
}

cleanup_node_server() {
    echo -e "${CYAN}${INFO}${NC} Cleaning up server..."

    if [ -f /opt/remnanode/docker-compose.yml ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Docker containers"
        (cd /opt/remnanode && docker compose down > /dev/null 2>&1 || true)
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Removing node directory"
    rm -rf /opt/remnanode

    echo -e "${GRAY}  ${ARROW}${NC} Removing UFW rules"
    ufw delete allow from "$PANEL_IP" to any port 2222 > /dev/null 2>&1 || true
    ufw delete allow 443/tcp > /dev/null 2>&1 || true
    ufw reload > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Server cleanup complete"
}

delete_node() {
    set -e

    echo
    echo -e "${GREEN}Selecting node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    list_nodes_from_panel
    select_node_to_delete

    echo
    echo -e "${YELLOW}${WARNING}${NC} You are about to delete node: ${WHITE}$DELETE_NODE_NAME${NC} ${GRAY}($DELETE_NODE_ADDRESS)${NC}"
    echo -e "${RED}This will remove the node from the panel and clean up this server.${NC}"
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

    delete_tg_service_user_from_panel
    echo
    delete_tg_squad_from_panel
    echo
    delete_node_host_from_panel
    echo
    delete_node_from_panel
    echo
    delete_tg_config_profile_from_panel

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
    echo -e "${GREEN}Creating profile and node${NC}"
    echo -e "${GREEN}=========================${NC}"
    echo

    create_tg_config_profile
    echo
    create_node_in_panel

    echo
    echo -e "${GREEN}Installing node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    create_node

    echo -e "${GREEN}Creating host${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    create_node_host_in_panel

    echo
    echo -e "${GREEN}Creating squad and user${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    create_tg_squad
    echo
    create_tg_service_user

    echo
    echo -e "${GREEN}Starting node${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    start_node_services
    save_node_credentials

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Panel setup:${NC}"
    echo -e "${WHITE}• tg-service shortUuid: ${TG_SERVICE_SHORT_UUID}${NC}"
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
                input_node_name
                input_node_host_remark
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
