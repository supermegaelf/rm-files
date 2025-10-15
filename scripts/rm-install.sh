#!/bin/bash

#===================
# REMNAWAVE MANAGER
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

readonly CHECK="✓"
readonly CROSS="✗"
readonly WARNING="!"
readonly INFO="*"
readonly ARROW="→"

DIR_REMNAWAVE="/usr/local/remnawave_reverse/"

SCRIPT_VERSION="1.0.0"
PANEL_VERSION="2.1.19"
NODE_VERSION="2.1.7"

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
    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${WHITE}REMNAWAVE MANAGER${NC}"
    echo -e "${PURPLE}==================${NC}"
    echo
    echo -e "${CYAN}Script version: ${WHITE}${SCRIPT_VERSION}${NC}"
    echo -e "${CYAN}Panel version: ${WHITE}${PANEL_VERSION}${NC}"
    echo -e "${CYAN}Node version: ${WHITE}${NODE_VERSION}${NC}"
    echo
    echo -e "${CYAN}Please select installation type:${NC}"
    echo
    echo -e "${GREEN}1.${NC} Install Panel"
    echo -e "${GREEN}2.${NC} Install Node"
    echo -e "${RED}3.${NC} Exit"
    echo
    echo -ne "${CYAN}Enter your choice (1, 2, or 3): ${NC}"
}

#===================
# UTILITY FUNCTIONS
#===================

generate_user() {
    local length=8
    tr -dc 'a-zA-Z' < /dev/urandom | fold -w $length | head -n 1
}

generate_password() {
    local length=24
    local password=""
    local upper_chars='A-Z'
    local lower_chars='a-z'
    local digit_chars='0-9'
    local special_chars='_+-'
    local all_chars='A-Za-z0-9_+-'

    password+=$(head /dev/urandom | tr -dc "$upper_chars" | head -c 1)
    password+=$(head /dev/urandom | tr -dc "$lower_chars" | head -c 1)
    password+=$(head /dev/urandom | tr -dc "$digit_chars" | head -c 1)
    password+=$(head /dev/urandom | tr -dc "$special_chars" | head -c 3)
    password+=$(head /dev/urandom | tr -dc "$all_chars" | head -c $(($length - 6)))

    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')

    echo "$password"
}

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

#=======================
# PANEL INPUT FUNCTIONS
#=======================

input_panel_domain() {
    echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
    read PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]] || ! validate_domain "$PANEL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read PANEL_DOMAIN
    done
}

input_sub_domain() {
    echo -ne "${CYAN}Sub domain (e.g., example.com): ${NC}"
    read SUB_DOMAIN
    while [[ -z "$SUB_DOMAIN" ]] || ! validate_domain "$SUB_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Subscription domain: ${NC}"
        read SUB_DOMAIN
    done
}

input_selfsteal_domain() {
    echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
    read SELFSTEAL_DOMAIN
    while [[ -z "$SELFSTEAL_DOMAIN" ]] || ! validate_domain "$SELFSTEAL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Selfsteal domain: ${NC}"
        read SELFSTEAL_DOMAIN
    done
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
    echo -ne "${CYAN}Selfsteal domain (e.g., example.com): ${NC}"
    read SELFSTEAL_DOMAIN
    while [[ -z "$SELFSTEAL_DOMAIN" ]] || ! validate_domain "$SELFSTEAL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Selfsteal domain for node: ${NC}"
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

input_ssl_certificate() {
    echo -e "${CYAN}Enter the node's SSL certificate from the panel and press \"Enter\" twice:${NC}"
    CERTIFICATE=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            if [ -n "$CERTIFICATE" ]; then
                break
            fi
        else
            CERTIFICATE="$CERTIFICATE$line\n"
        fi
    done

    echo -ne "${YELLOW}Are you sure the certificate is correct? (y/n): ${NC}"
    read confirm

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}${CROSS}${NC} Installation aborted by user"
        exit 1
    fi
}

#====================================
# CONFIGURATION GENERATION FUNCTIONS
#====================================

generate_configuration() {
    echo -e "${CYAN}${INFO}${NC} Generating all configuration variables..."
    
    echo -e "${GRAY}  ${ARROW}${NC} Creating admin credentials"
    SUPERADMIN_USERNAME=$(generate_user)
    SUPERADMIN_PASSWORD=$(generate_password)
    
    echo -e "${GRAY}  ${ARROW}${NC} Creating cookies and metrics credentials"
    cookies_random1=$(generate_user)
    cookies_random2=$(generate_user)
    METRICS_USER=$(generate_user)
    METRICS_PASS=$(generate_user)

    echo -e "${GRAY}  ${ARROW}${NC} Generating database password"
    POSTGRES_PASSWORD=$(generate_password)
    
    echo -e "${GRAY}  ${ARROW}${NC} Generating JWT secrets"
    JWT_AUTH_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
    JWT_API_TOKENS_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)

    echo -e "${GRAY}  ${ARROW}${NC} Generating webhook secret"
    WEBHOOK_SECRET_HEADER=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64)
    
    echo -e "${GREEN}${CHECK}${NC} All configuration variables generated"
}

save_variables_to_file() {
    echo -e "${CYAN}${INFO}${NC} Saving configuration variables..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating variables file"
    cat > remnawave-vars.sh << EOF
# User provided domains and credentials
export PANEL_DOMAIN="$PANEL_DOMAIN"
export SUB_DOMAIN="$SUB_DOMAIN"
export SELFSTEAL_DOMAIN="$SELFSTEAL_DOMAIN"
export CLOUDFLARE_API_KEY="$CLOUDFLARE_API_KEY"
export CLOUDFLARE_EMAIL="$CLOUDFLARE_EMAIL"

# Auto-generated admin credentials
export SUPERADMIN_USERNAME="$SUPERADMIN_USERNAME"
export SUPERADMIN_PASSWORD="$SUPERADMIN_PASSWORD"
export cookies_random1="$cookies_random1"
export cookies_random2="$cookies_random2"
export METRICS_USER="$METRICS_USER"
export METRICS_PASS="$METRICS_PASS"

# JWT secrets
export JWT_AUTH_SECRET="$JWT_AUTH_SECRET"
export JWT_API_TOKENS_SECRET="$JWT_API_TOKENS_SECRET"

# Database password
export POSTGRES_PASSWORD="$POSTGRES_PASSWORD"

# Webhook secret
export WEBHOOK_SECRET_HEADER="$WEBHOOK_SECRET_HEADER"
EOF
    
    echo -e "${GRAY}  ${ARROW}${NC} Loading environment variables"
    source remnawave-vars.sh
    echo -e "${GREEN}${CHECK}${NC} Variables saved to remnawave-vars.sh"
}

save_node_variables_to_file() {
    echo -e "${CYAN}${INFO}${NC} Saving node configuration variables..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating variables file"
    cat > remnawave-node-vars.sh << EOF
# User provided node configuration
export SELFSTEAL_DOMAIN="$SELFSTEAL_DOMAIN"
export PANEL_IP="$PANEL_IP"
export CERTIFICATE="$CERTIFICATE"
EOF
    
    echo -e "${GRAY}  ${ARROW}${NC} Loading environment variables"
    source remnawave-node-vars.sh
    echo -e "${GREEN}${CHECK}${NC} Variables saved to remnawave-node-vars.sh"
}

move_variables_file() {
    echo -e "${CYAN}${INFO}${NC} Moving configuration files..."
    echo -e "${GRAY}  ${ARROW}${NC} Moving variables file to project directory"
    mkdir -p "$APP_DIR"
    if [ -f /root/remnawave-vars.sh ]; then
        mv /root/remnawave-vars.sh "$APP_DIR/"
    fi
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
    if ! dpkg -l | grep -q '^ii.*cron '; then
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
    if ! ping -c 1 download.docker.com >/dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Error: Unable to resolve download.docker.com. Check your DNS settings."
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

    echo -e "${GRAY}  ${ARROW}${NC} Configuring TCP optimizations (BBR)"
    if ! grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null

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
            echo -e "${YELLOW}WARNING:${NC}"
            echo -e "${RED}Failed to determine the domain or server IP address.${NC}"
            printf "${YELLOW}Ensure that the domain %s is correctly configured and points to this server (%s).${NC}\n" "$domain" "$server_ip"
            echo -ne "${CYAN}Enter 'y' to continue or 'n' to exit (y/n): ${NC}"
            read confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
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
                echo -e "${YELLOW}WARNING:${NC}"
                printf "${RED}The domain %s points to a Cloudflare IP (%s).${NC}\n" "$domain" "$domain_ip"
                echo -e "${YELLOW}Cloudflare proxying is not allowed for the selfsteal domain. Disable proxying (switch to 'DNS Only').${NC}"
                echo -ne "${CYAN}Enter 'y' to continue or 'n' to exit (y/n): ${NC}"
                read confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    return 1
                else
                    return 2
                fi
            fi
            return 1
        fi
    else
        if [ "$show_warning" = true ]; then
            echo -e "${YELLOW}WARNING:${NC}"
            printf "${RED}The domain %s points to IP address %s, which differs from this server's IP (%s).${NC}\n" "$domain" "$domain_ip" "$server_ip"
            echo -e "${YELLOW}For proper operation, the domain must point to the current server.${NC}"
            echo
            echo -ne "${CYAN}Enter 'y' to continue or 'n' to exit (y/n): ${NC}"
            read confirm
            echo
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                return 1
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
            echo -e "${GREEN}Wildcard certificate found in /etc/letsencrypt/live/$base_domain for $DOMAIN${NC}"
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
        echo -e "${YELLOW}WARNING: Cloudflare credentials not provided. Skipping SSL certificate generation.${NC}"
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

    local expected_hook="renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx && docker compose exec remnawave-nginx nginx -s reload'"
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
    local target_dir="/opt/remnawave"

    declare -A unique_domains
    local need_certificates=false
    local min_days_left=9999

    echo -e "${CYAN}${INFO}${NC} Checking certificates..."
    sleep 1

    for domain in "${!domains_to_check_ref[@]}"; do
        if ! check_certificates "$domain"; then
            need_certificates=true
        else
            days_left=$(check_cert_expiry "$domain")
            if [ $? -eq 0 ] && [ "$days_left" -lt "$min_days_left" ]; then
                min_days_left=$days_left
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
            desired_hook="renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'"
            if ! grep -q "renew_hook" "/etc/letsencrypt/renewal/$domain.conf"; then
                echo "$desired_hook" >> "/etc/letsencrypt/renewal/$domain.conf"
            elif ! grep -Fx "$desired_hook" "/etc/letsencrypt/renewal/$domain.conf"; then
                sed -i "/renew_hook/c\\$desired_hook" "/etc/letsencrypt/renewal/$domain.conf"
                echo -e "${YELLOW}Updating cron job to match certificate expiry.${NC}"
            fi
        fi
    done
}

#=======================
# API REQUEST FUNCTIONS
#=======================

make_api_request() {
    local method=$1
    local url=$2
    local token=$3
    local data=$4

    local headers=(
        -H "Authorization: Bearer $token"
        -H "Content-Type: application/json"
        -H "X-Forwarded-For: ${url#http://}"
        -H "X-Forwarded-Proto: https"
        -H "X-Remnawave-Client-Type: browser"
    )

    if [ -n "$data" ]; then
        curl -s -X "$method" "$url" "${headers[@]}" -d "$data"
    else
        curl -s -X "$method" "$url" "${headers[@]}"
    fi
}

register_remnawave() {
    local domain_url=$1
    local username=$2
    local password=$3
    local token=$4

    local register_data='{"username":"'"$username"'","password":"'"$password"'"}'
    local register_response=$(make_api_request "POST" "http://$domain_url/api/auth/register" "$token" "$register_data")

    if [ -z "$register_response" ]; then
        echo -e "${RED}Registration error - empty server response${NC}"
    elif [[ "$register_response" == *"accessToken"* ]]; then
        echo "$register_response" | jq -r '.response.accessToken'
    else
        echo -e "${RED}Registration error: $register_response${NC}"
    fi
}

get_panel_token() {
    TOKEN_FILE="${DIR_REMNAWAVE}/token"
    ENV_FILE="/opt/remnawave/.env"
    local domain_url="127.0.0.1:3000"
    
    local oauth_enabled=false
    if [ -f "$ENV_FILE" ]; then
        if grep -q "^TELEGRAM_OAUTH_ENABLED=true" "$ENV_FILE" || \
           grep -q "^OAUTH2_GITHUB_ENABLED=true" "$ENV_FILE" || \
           grep -q "^OAUTH2_POCKETID_ENABLED=true" "$ENV_FILE" || \
           grep -q "^OAUTH2_YANDEX_ENABLED=true" "$ENV_FILE"; then
            oauth_enabled=true
        fi
    fi
    
    if [ -f "$TOKEN_FILE" ]; then
        token=$(cat "$TOKEN_FILE")
        echo -e "${YELLOW}Using saved token...${NC}"
        local test_response=$(make_api_request "GET" "${domain_url}/api/config-profiles" "$token")
        
        if [ -z "$test_response" ] || ! echo "$test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
            if echo "$test_response" | grep -q '"statusCode":401' || \
               echo "$test_response" | jq -e '.message | test("Unauthorized")' > /dev/null 2>&1; then
                echo -e "${RED}Saved token is invalid. Requesting a new one...${NC}"
            else
                echo -e "${RED}Saved token is invalid. Requesting a new one...: $test_response${NC}"
            fi
            token=""
        fi
    fi
    
    if [ -z "$token" ]; then
        if [ "$oauth_enabled" = true ]; then
            echo -e "${YELLOW}=================================================${NC}"
            echo -e "${RED}WARNING:${NC}"
            echo -e "${YELLOW}OAuth is enabled. Manual token creation required.${NC}"
            printf "${YELLOW}Create API token in panel settings at https://%s and paste it below.${NC}\n" "$PANEL_DOMAIN"
            echo -ne "${CYAN}Enter API token: ${NC}"
            read token
            if [ -z "$token" ]; then
                echo -e "${RED}API token cannot be empty${NC}"
                return 1
            fi
            
            local test_response=$(make_api_request "GET" "${domain_url}/api/config-profiles" "$token")
            if [ -z "$test_response" ] || ! echo "$test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
                echo -e "${RED}Saved token is invalid. Requesting a new one...: $test_response${NC}"
                return 1
            fi
        else
            echo -ne "${CYAN}Enter panel username: ${NC}"
            read username
            echo -ne "${CYAN}Enter panel password: ${NC}"
            read password
            
            local login_response=$(make_api_request "POST" "${domain_url}/api/auth/login" "" "{\"username\":\"$username\",\"password\":\"$password\"}")
            token=$(echo "$login_response" | jq -r '.response.accessToken // .accessToken // ""')
            if [ -z "$token" ] || [ "$token" == "null" ]; then
                echo -e "${RED}Failed to get token.: $login_response${NC}"
                return 1
            fi
        fi
        
        echo "$token" > "$TOKEN_FILE"
        echo -e "${GREEN}Token successfully received and saved${NC}"
    else
        echo -e "${GREEN}Token successfully used${NC}"
    fi
    
    local final_test_response=$(make_api_request "GET" "${domain_url}/api/config-profiles" "$token")
    if [ -z "$final_test_response" ] || ! echo "$final_test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
        echo -e "${RED}Saved token is invalid. Requesting a new one...: $final_test_response${NC}"
        return 1
    fi
}

get_public_key() {
    local domain_url=$1
    local token=$2
    local target_dir=$3

    local api_response=$(make_api_request "GET" "http://$domain_url/api/keygen" "$token")

    if [ -z "$api_response" ]; then
        echo -e "${RED}Failed to get public key.${NC}"
    fi

    local pubkey=$(echo "$api_response" | jq -r '.response.pubKey')
    if [ -z "$pubkey" ]; then
        echo -e "${RED}Failed to extract public key from response.${NC}"
    fi

    local env_node_file="$target_dir/.env-node"
    cat > "$env_node_file" <<EOL
### APP ###
APP_PORT=2222

### XRAY ###
SSL_CERT="$pubkey"
EOL
    echo -e "${YELLOW}Public key successfully obtained${NC}"
    echo "$pubkey"
}

generate_xray_keys() {
    local domain_url=$1
    local token=$2

    local api_response=$(make_api_request "GET" "http://$domain_url/api/system/tools/x25519/generate" "$token")

    if [ -z "$api_response" ]; then
        echo -e "${RED}Failed to generate keys.${NC}"
        return 1
    fi

    if echo "$api_response" | jq -e '.errorCode' > /dev/null 2>&1; then
        local error_message=$(echo "$api_response" | jq -r '.message')
        echo -e "${RED}Failed to generate keys.: $error_message${NC}"
    fi

    local private_key=$(echo "$api_response" | jq -r '.response.keypairs[0].privateKey')

    if [ -z "$private_key" ] || [ "$private_key" = "null" ]; then
        echo -e "${RED}Failed to extract private key from response.${NC}"
    fi

    echo "$private_key"
}

create_node_api() {
    local domain_url=$1
    local token=$2
    local config_profile_uuid=$3
    local inbound_uuid=$4
    local node_address="${5:-172.30.0.1}"
    local node_name="${6:-Steal}"

    local node_data=$(cat <<EOF
{
    "name": "$node_name",
    "address": "$node_address",
    "port": 2222,
    "configProfile": {
        "activeConfigProfileUuid": "$config_profile_uuid",
        "activeInbounds": ["$inbound_uuid"]
    },
    "isTrafficTrackingActive": false,
    "trafficLimitBytes": 0,
    "notifyPercent": 0,
    "trafficResetDay": 31,
    "excludedInbounds": [],
    "countryCode": "XX",
    "consumptionMultiplier": 1.0
}
EOF
)

    local node_response=$(make_api_request "POST" "http://$domain_url/api/nodes" "$token" "$node_data")

    if [ -z "$node_response" ]; then
        echo -e "${RED}Empty response from server when creating node.${NC}"
    fi

    if ! echo "$node_response" | jq -e '.response.uuid' > /dev/null; then
        echo -e "${RED}Failed to create node.${NC}"
        return 1
    fi
}

get_config_profiles() {
    local domain_url="$1"
    local token="$2"

    local config_response=$(make_api_request "GET" "http://$domain_url/api/config-profiles" "$token")
    if [ -z "$config_response" ] || ! echo "$config_response" | jq -e '.' > /dev/null 2>&1; then
        echo -e "${RED}No config profiles found${NC}"
        return 1
    fi

    local profile_uuid=$(echo "$config_response" | jq -r '.response.configProfiles[] | select(.name == "Default-Profile") | .uuid' 2>/dev/null)
    if [ -z "$profile_uuid" ]; then
        echo -e "${YELLOW}Default-Profile not found${NC}"
        return 0
    fi

    echo "$profile_uuid"
    return 0
}

delete_config_profile() {
    local domain_url="$1"
    local token="$2"
    local profile_uuid="$3"

    if [ -z "$profile_uuid" ]; then
        profile_uuid=$(get_config_profiles "$domain_url" "$token")
        if [ $? -ne 0 ] || [ -z "$profile_uuid" ]; then
            return 0
        fi
    fi

    local delete_response=$(make_api_request "DELETE" "http://$domain_url/api/config-profiles/$profile_uuid" "$token")
    if [ -z "$delete_response" ] || ! echo "$delete_response" | jq -e '.' > /dev/null 2>&1; then
        echo -e "${RED}Failed to delete profile${NC}"
        return 1
    fi

    return 0
}

create_config_profile() {
    local domain_url=$1
    local token=$2
    local name=$3
    local domain=$4
    local private_key=$5
    local inbound_tag="${6:-Steal}"

    local short_id=$(openssl rand -hex 8)

    local request_body=$(jq -n --arg name "$name" --arg domain "$domain" --arg private_key "$private_key" --arg short_id "$short_id" --arg inbound_tag "$inbound_tag" '{
        name: $name,
        config: {
            log: { loglevel: "warning" },
            dns: {
                queryStrategy: "ForceIPv4",
                servers: [{ address: "https://dns.google/dns-query", skipFallback: false }]
            },
            inbounds: [{
                tag: $inbound_tag,
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
                { tag: "BLOCK", protocol: "blackhole" },
                { tag: "IPv4", protocol: "freedom", settings: { domainStrategy: "UseIPv4" } }
            ],
            routing: {
                domainStrategy: "IPIfNonMatch",
                rules: [
                    { ip: ["geoip:private"], type: "field", outboundTag: "BLOCK" },
                    { type: "field", domain: ["geosite:google"], outboundTag: "IPv4" },
                    { type: "field", protocol: ["bittorrent"], outboundTag: "DIRECT" },
                    { type: "field", domain: ["geosite:category-gov-ru"], outboundTag: "BLOCK" },
                    { type: "field", domain: ["geosite:category-ads-all"], outboundTag: "BLOCK" }
                ]
            }
        }
    }')

    local response=$(make_api_request "POST" "http://$domain_url/api/config-profiles" "$token" "$request_body")
    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.uuid' > /dev/null; then
        echo -e "${RED}Failed to create config profile: $response${NC}"
    fi

    local config_uuid=$(echo "$response" | jq -r '.response.uuid')
    local inbound_uuid=$(echo "$response" | jq -r '.response.inbounds[0].uuid')
    if [ -z "$config_uuid" ] || [ "$config_uuid" = "null" ] || [ -z "$inbound_uuid" ] || [ "$inbound_uuid" = "null" ]; then
        echo -e "${RED}Failed to create config profile: Invalid UUIDs in response: $response${NC}"
    fi

    echo "$config_uuid $inbound_uuid"
}

create_host() {
    local domain_url=$1
    local token=$2
    local inbound_uuid=$3
    local address=$4
    local config_uuid=$5
    local host_remark="${6:-Steal}"

    local request_body=$(jq -n --arg config_uuid "$config_uuid" --arg inbound_uuid "$inbound_uuid" --arg remark "$host_remark" --arg address "$address" '{
        inbound: {
            configProfileUuid: $config_uuid,
            configProfileInboundUuid: $inbound_uuid
        },
        remark: $remark,
        address: $address,
        port: 443,
        path: "",
        sni: $address,
        host: "",
        alpn: null,
        fingerprint: "chrome",
        allowInsecure: false,
        isDisabled: false,
        securityLayer: "DEFAULT"
    }')

    local response=$(make_api_request "POST" "http://$domain_url/api/hosts" "$token" "$request_body")

    if [ -z "$response" ]; then
        echo -e "${RED}Empty response from server when creating host.${NC}"
    fi

    if ! echo "$response" | jq -e '.response.uuid' > /dev/null; then
        echo -e "${RED}Failed to create host.${NC}"
        return 1
    fi
}

create_bot_token() {
    local domain_url=$1
    local token=$2
    
    local token_response=$(curl -s -X POST "http://$domain_url/api/tokens" \
        -H "Host: $PANEL_DOMAIN" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -H "X-Remnawave-Client-Type: browser" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Forwarded-Proto: https" \
        -H "X-Forwarded-Host: $PANEL_DOMAIN" \
        -d '{
            "tokenName": "Bot API Token",
            "tokenDescription": "API token for bot integration and webhook notifications"
        }')

    local bot_token=$(echo "$token_response" | jq -r '.response.token // empty')
    
    if [ -n "$bot_token" ] && [ "$bot_token" != "null" ]; then
        echo "$bot_token"
        return 0
    else
        return 1
    fi
}

get_default_squad() {
    local domain_url=$1
    local token=$2

    local response=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.internalSquads' > /dev/null 2>&1; then
        echo -e "${RED}Failed to get squad: $response${NC}"
        return 1
    fi

    local squad_uuids=$(echo "$response" | jq -r '.response.internalSquads[].uuid' 2>/dev/null)
    if [ -z "$squad_uuids" ]; then
        echo -e "${YELLOW}No squads found${NC}"
        return 0
    fi

    local valid_uuids=""
    while IFS= read -r uuid; do
        if [ -z "$uuid" ]; then
            continue
        fi
        if [[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            valid_uuids+="$uuid\n"
        else
            echo -e "${RED}Invalid UUID format: $uuid${NC}"
        fi
    done <<< "$squad_uuids"

    if [ -z "$valid_uuids" ]; then
        echo -e "${YELLOW}No valid squads found${NC}"
        return 0
    fi

    echo -e "$valid_uuids" | sed '/^$/d'
    return 0
}

update_squad() {
    local domain_url=$1
    local token=$2
    local squad_uuid=$3
    local inbound_uuid=$4

    if [[ ! $squad_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${RED}Invalid squad UUID: $squad_uuid${NC}"
        return 1
    fi

    if [[ ! $inbound_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${RED}Invalid inbound UUID: $inbound_uuid${NC}"
        return 1
    fi

    local squad_response=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$squad_response" ] || ! echo "$squad_response" | jq -e '.response.internalSquads' > /dev/null 2>&1; then
        echo -e "${RED}Failed to get squad: $squad_response${NC}"
        return 1
    fi

    local existing_inbounds=$(echo "$squad_response" | jq -r --arg uuid "$squad_uuid" '.response.internalSquads[] | select(.uuid == $uuid) | .inbounds[].uuid' 2>/dev/null)
    if [ -z "$existing_inbounds" ]; then
        existing_inbounds="[]"
    else
        existing_inbounds=$(echo "$existing_inbounds" | jq -R . | jq -s .)
    fi

    local inbounds_array=$(jq -n --argjson existing "$existing_inbounds" --arg new "$inbound_uuid" '$existing + [$new] | unique')

    local request_body=$(jq -n --arg uuid "$squad_uuid" --argjson inbounds "$inbounds_array" '{
        uuid: $uuid,
        inbounds: $inbounds
    }')

    local response=$(make_api_request "PATCH" "http://$domain_url/api/internal-squads" "$token" "$request_body")
    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}Failed to update squad: $response${NC}"
        return 1
    fi

    return 0
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

    unzip -o main.zip &>/dev/null || { echo "Error unpacking archive"; exit 0; }
    rm -f main.zip

    cd simple-web-templates-main/ || { echo "Error unpacking archive"; exit 0; }
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

#==============================
# PANEL INSTALLATION FUNCTIONS
#==============================

create_panel() {
    source /opt/remnawave/remnawave-vars.sh
    
    mkdir -p /opt/remnawave && cd /opt/remnawave

    check_domain "$PANEL_DOMAIN" true true
    local panel_check_result=$?
    if [ $panel_check_result -eq 2 ]; then
        echo -e "${RED}Installation aborted by user${NC}"
        exit 1
    fi

    check_domain "$SUB_DOMAIN" true true
    local sub_check_result=$?
    if [ $sub_check_result -eq 2 ]; then
        echo -e "${RED}Installation aborted by user${NC}"
        exit 1
    fi

    if [ "$PANEL_DOMAIN" = "$SUB_DOMAIN" ] || [ "$PANEL_DOMAIN" = "$SELFSTEAL_DOMAIN" ] || [ "$SUB_DOMAIN" = "$SELFSTEAL_DOMAIN" ]; then
        echo -e "${RED}Error: All domains (panel, subscription, and node) must be unique.${NC}"
        exit 1
    fi

    local PANEL_BASE_DOMAIN=$(extract_domain "$PANEL_DOMAIN")
    local SUB_BASE_DOMAIN=$(extract_domain "$SUB_DOMAIN")

    declare -A unique_domains
    unique_domains["$PANEL_BASE_DOMAIN"]=1
    unique_domains["$SUB_BASE_DOMAIN"]=1

    declare -A domains_to_check
    domains_to_check["$PANEL_DOMAIN"]=1
    domains_to_check["$SUB_DOMAIN"]=1
    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL"

    PANEL_CERT_DOMAIN=$(extract_domain "$PANEL_DOMAIN")
    SUB_CERT_DOMAIN=$(extract_domain "$SUB_DOMAIN")

    cat > .env <<EOL
### APP ###
APP_PORT=3000
METRICS_PORT=3001

### API ###
# Possible values: max (start instances on all cores), number (start instances on number of cores), -1 (start instances on all cores - 1)
# !!! Do not set this value more than physical cores count in your machine !!!
# Review documentation: https://remna.st/docs/install/environment-variables#scaling-api
API_INSTANCES=1

### DATABASE ###
# FORMAT: postgresql://{user}:{password}@{host}:{port}/{database}
DATABASE_URL="postgresql://remnawave:$POSTGRES_PASSWORD@remnawave-db:5432/remnawave"

### REDIS ###
REDIS_HOST=remnawave-redis
REDIS_PORT=6379

### JWT ###
JWT_AUTH_SECRET=$JWT_AUTH_SECRET
JWT_API_TOKENS_SECRET=$JWT_API_TOKENS_SECRET

# Set the session idle timeout in the panel to avoid daily logins.
# Value in hours: 12–168
JWT_AUTH_LIFETIME=168

### TELEGRAM NOTIFICATIONS ###
IS_TELEGRAM_NOTIFICATIONS_ENABLED=false
TELEGRAM_BOT_TOKEN=change_me
TELEGRAM_NOTIFY_USERS_CHAT_ID=change_me
TELEGRAM_NOTIFY_NODES_CHAT_ID=change_me

### Telegram Oauth (Login with Telegram)
### Docs https://remna.st/docs/features/telegram-oauth
### true/false
TELEGRAM_OAUTH_ENABLED=false
### Array of Admin Chat Ids. These ids will be allowed to login.
TELEGRAM_OAUTH_ADMIN_IDS=[123, 321]

# Optional
# Only set if you want to use topics
TELEGRAM_NOTIFY_USERS_THREAD_ID=
TELEGRAM_NOTIFY_NODES_THREAD_ID=
TELEGRAM_NOTIFY_CRM_THREAD_ID=

# Enable Github OAuth2, possible values: true, false
OAUTH2_GITHUB_ENABLED=false
# Github client ID, you can get it from Github application settings
OAUTH2_GITHUB_CLIENT_ID="REPLACE_WITH_YOUR_CLIENT_ID"
# Github client secret, you can get it from Github application settings
OAUTH2_GITHUB_CLIENT_SECRET="REPLACE_WITH_YOUR_CLIENT_SECRET"
# List of allowed emails, separated by commas
OAUTH2_GITHUB_ALLOWED_EMAILS=["admin@example.com", "user@example.com"]

# Enable PocketID OAuth2, possible values: true, false
OAUTH2_POCKETID_ENABLED=false
# PocketID Client ID, you can get it from OIDC Client settings
OAUTH2_POCKETID_CLIENT_ID="REPLACE_WITH_YOUR_CLIENT_ID"
# PocketID Client Secret, you can get it from OIDC Client settings
OAUTH2_POCKETID_CLIENT_SECRET="REPLACE_WITH_YOUR_CLIENT_SECRET"
# Plain domain where PocketID is hosted, do not place any paths here. Just plain domain.
OAUTH2_POCKETID_PLAIN_DOMAIN="pocketid.domain.com"
# List of allowed emails, separated by commas
OAUTH2_POCKETID_ALLOWED_EMAILS=["admin@example.com", "user@example.com"]

# Enable Yandex OAuth2, possible values: true, false
OAUTH2_YANDEX_ENABLED=false
# Yandex Client ID, you can get it from OIDC Client settings
OAUTH2_YANDEX_CLIENT_ID="REPLACE_WITH_YOUR_CLIENT_ID"
# Yandex Client Secret, you can get it from OIDC Client settings
OAUTH2_YANDEX_CLIENT_SECRET="REPLACE_WITH_YOUR_CLIENT_SECRET"
# List of allowed emails, separated by commas
OAUTH2_YANDEX_ALLOWED_EMAILS=["admin@example.com", "user@example.com"]

### FRONT_END ###
# Used by CORS, you can leave it as * or place your domain there
FRONT_END_DOMAIN=$PANEL_DOMAIN

### SUBSCRIPTION PUBLIC DOMAIN ###
### DOMAIN, WITHOUT HTTP/HTTPS, DO NOT ADD / AT THE END ###
### Used in "profile-web-page-url" response header and in UI/API ###
### Review documentation: https://remna.st/docs/install/environment-variables#domains
SUB_PUBLIC_DOMAIN=$SUB_DOMAIN

### If CUSTOM_SUB_PREFIX is set in @remnawave/subscription-page, append the same path to SUB_PUBLIC_DOMAIN. Example: SUB_PUBLIC_DOMAIN=sub-page.example.com/sub ###

### SWAGGER ###
SWAGGER_PATH=/docs
SCALAR_PATH=/scalar
IS_DOCS_ENABLED=true

### PROMETHEUS ###
### Metrics are available at /api/metrics
METRICS_USER=$METRICS_USER
METRICS_PASS=$METRICS_PASS

### WEBHOOK ###
WEBHOOK_ENABLED=true
### Only https:// is allowed
WEBHOOK_URL=https://bot.$PANEL_DOMAIN/notify_user
### This secret is used to sign the webhook payload, must be exact 64 characters. Only a-z, 0-9, A-Z are allowed.
WEBHOOK_SECRET_HEADER=$WEBHOOK_SECRET_HEADER

### HWID DEVICE DETECTION AND LIMITATION ###
# Don't enable this if you don't know what you are doing.
# Review documentation before enabling this feature.
# https://remna.st/docs/features/hwid-device-limit/
HWID_DEVICE_LIMIT_ENABLED=false
HWID_FALLBACK_DEVICE_LIMIT=5
HWID_MAX_DEVICES_ANNOUNCE="You have reached the maximum number of devices for your subscription."

### Bandwidth usage reached notifications
BANDWIDTH_USAGE_NOTIFICATIONS_ENABLED=false
# Only in ASC order (example: [60, 80]), must be valid array of integer(min: 25, max: 95) numbers. No more than 5 values.
BANDWIDTH_USAGE_NOTIFICATIONS_THRESHOLD=[60, 80]

### CLOUDFLARE ###
# USED ONLY FOR docker-compose-prod-with-cf.yml
# NOT USED BY THE APP ITSELF
CLOUDFLARE_TOKEN=ey...

### Database ###
### For Postgres Docker container ###
# NOT USED BY THE APP ITSELF
POSTGRES_USER=remnawave
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=remnawave
EOL

    cat > docker-compose.yml <<EOF
services:
  remnawave-db:
    image: postgres:17.6
    container_name: 'remnawave-db'
    hostname: remnawave-db
    restart: always
    env_file:
      - .env
    environment:
      - POSTGRES_USER=\${POSTGRES_USER}
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
      - POSTGRES_DB=\${POSTGRES_DB}
      - TZ=UTC
    ports:
      - '127.0.0.1:6767:5432'
    volumes:
      - remnawave-db-data:/var/lib/postgresql/data
    networks:
      - remnawave-network
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U \$\${POSTGRES_USER} -d \$\${POSTGRES_DB}']
      interval: 3s
      timeout: 10s
      retries: 3
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave:
    image: remnawave/backend:2.1.19
    container_name: remnawave
    hostname: remnawave
    restart: always
    env_file:
      - .env
    ports:
      - '127.0.0.1:3000:3000'
    networks:
      - remnawave-network
    healthcheck:
      test: ['CMD-SHELL', 'curl -f http://localhost:\${METRICS_PORT:-3001}/health']
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_healthy
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-redis:
    image: valkey/valkey:8.1.3-alpine
    container_name: remnawave-redis
    hostname: remnawave-redis
    restart: always
    networks:
      - remnawave-network
    volumes:
      - remnawave-redis-data:/data
    healthcheck:
      test: ['CMD', 'valkey-cli', 'ping']
      interval: 3s
      timeout: 10s
      retries: 3
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-nginx:
    image: nginx:1.28
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    restart: always
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt/live/${PANEL_CERT_DOMAIN}/fullchain.pem:/etc/nginx/ssl/${PANEL_CERT_DOMAIN}/fullchain.pem:ro
      - /etc/letsencrypt/live/${PANEL_CERT_DOMAIN}/privkey.pem:/etc/nginx/ssl/${PANEL_CERT_DOMAIN}/privkey.pem:ro
      - /etc/letsencrypt/live/${SUB_CERT_DOMAIN}/fullchain.pem:/etc/nginx/ssl/${SUB_CERT_DOMAIN}/fullchain.pem:ro
      - /etc/letsencrypt/live/${SUB_CERT_DOMAIN}/privkey.pem:/etc/nginx/ssl/${SUB_CERT_DOMAIN}/privkey.pem:ro
    network_mode: host
    depends_on:
      - remnawave
      - remnawave-subscription-page
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-subscription-page:
    image: remnawave/subscription-page:latest
    container_name: remnawave-subscription-page
    hostname: remnawave-subscription-page
    restart: always
    environment:
      - REMNAWAVE_PANEL_URL=http://remnawave:3000
      - APP_PORT=3010
      - META_TITLE=Remnawave Subscription
      - META_DESCRIPTION=page
    ports:
      - '127.0.0.1:3010:3010'
    networks:
      - remnawave-network
    volumes:
      - ./index.html:/opt/app/frontend/index.html
      - ./assets:/opt/app/frontend/assets
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
    external: false

volumes:
  remnawave-db-data:
    driver: local
    external: false
    name: remnawave-db-data
  remnawave-redis-data:
    driver: local
    external: false
    name: remnawave-redis-data
EOF
}

start_panel_services() {
    sleep 1

    echo -e "${CYAN}${INFO}${NC} Setting up Remnawave infrastructure..."

echo -e "${GRAY}  ${ARROW}${NC} Downloading custom sub page"
wget -P /opt/remnawave/ https://raw.githubusercontent.com/supermegaelf/rm-files/main/pages/sub/index.html > /dev/null 2>&1

    echo -e "${GRAY}  ${ARROW}${NC} Configuring SSL and proxy settings"
    cat > /opt/remnawave/nginx.conf <<EOL
upstream remnawave {
    server 127.0.0.1:3000;
}

upstream json {
    server 127.0.0.1:3010;
}

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

map \$http_cookie \$auth_cookie {
    default 0;
    "~*${cookies_random1}=${cookies_random2}" 1;
}

map \$arg_${cookies_random1} \$auth_query {
    default 0;
    "${cookies_random2}" 1;
}

map "\$auth_cookie\$auth_query" \$authorized {
    "~1" 1;
    default 0;
}

map \$arg_${cookies_random1} \$set_cookie_header {
    "${cookies_random2}" "${cookies_random1}=${cookies_random2}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000";
    default "";
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;

server {
    server_name $PANEL_DOMAIN;
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$PANEL_CERT_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$PANEL_CERT_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$PANEL_CERT_DOMAIN/fullchain.pem";

    add_header Set-Cookie \$set_cookie_header;

    location / {
        if (\$authorized = 0) {
            return 444;
        }
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

server {
    server_name $SUB_DOMAIN;
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$SUB_CERT_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$SUB_CERT_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$SUB_CERT_DOMAIN/fullchain.pem";

    location / {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_intercept_errors on;
        error_page 400 404 500 502 @redirect;
    }

    location @redirect {
        return 404;
    }
}

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOL

    echo -e "${GRAY}  ${ARROW}${NC} Starting Docker containers"
    cd /opt/remnawave
    docker compose up -d > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Infrastructure set up successfully"
    echo
    echo -e "${CYAN}${INFO}${NC} Setting up Remnawave panel..."
    echo -e "${GRAY}  ${ARROW}${NC} Waiting for containers to start"
    sleep 20

    local domain_url="127.0.0.1:3000"
    echo -e "${GRAY}  ${ARROW}${NC} Checking containers availability"
    until curl -s "http://$domain_url/api/auth/register" \
        --header 'X-Forwarded-For: 127.0.0.1' \
        --header 'X-Forwarded-Proto: https' \
        > /dev/null; do
        echo -e "${GRAY}  ${ARROW}${NC} Containers are not ready, waiting..."
        sleep 5
    done

    echo -e "${GRAY}  ${ARROW}${NC} Registering admin user"
    local token=$(register_remnawave "$domain_url" "$SUPERADMIN_USERNAME" "$SUPERADMIN_PASSWORD")

    echo -e "${GRAY}  ${ARROW}${NC} Generating x25519 keys"
    local private_key=$(generate_xray_keys "$domain_url" "$token")

    delete_config_profile "$domain_url" "$token"

    echo -e "${GRAY}  ${ARROW}${NC} Creating config profile"
    read config_profile_uuid inbound_uuid <<< $(create_config_profile "$domain_url" "$token" "StealConfig" "$SELFSTEAL_DOMAIN" "$private_key")

    echo -e "${GRAY}  ${ARROW}${NC} Creating node configuration"
    create_node_api "$domain_url" "$token" "$config_profile_uuid" "$inbound_uuid" "$SELFSTEAL_DOMAIN"

    echo -e "${GRAY}  ${ARROW}${NC} Setting up host configuration"
    create_host "$domain_url" "$token" "$inbound_uuid" "$SELFSTEAL_DOMAIN" "$config_profile_uuid"

    echo -e "${GRAY}  ${ARROW}${NC} Configuring default squad"
    local squad_uuid=$(get_default_squad "$domain_url" "$token")
    update_squad "$domain_url" "$token" "$squad_uuid" "$inbound_uuid"
    
    echo -e "${GRAY}  ${ARROW}${NC} Creating bot API token"
    local bot_token=$(create_bot_token "$domain_url" "$token")
    if [ -n "$bot_token" ]; then
        echo "" >> /opt/remnawave/remnawave-vars.sh
        echo "# API Token for Bot" >> /opt/remnawave/remnawave-vars.sh
        echo "export REMNAWAVE_TOKEN=\"$bot_token\"" >> /opt/remnawave/remnawave-vars.sh
        echo -e "${GREEN}${CHECK}${NC} Remnawave panel configured successfully"
    else
        echo -e "${RED}${CROSS}${NC} Remnawave panel configuration failed"
    fi
}

#=============================
# NODE INSTALLATION FUNCTIONS
#=============================

create_node() {
    mkdir -p /opt/remnawave && cd /opt/remnawave

    check_domain "$SELFSTEAL_DOMAIN" true false
    local domain_check_result=$?
    if [ $domain_check_result -eq 2 ]; then
        echo -e "${RED}Installation aborted by user${NC}"
        exit 1
    fi

    cat > .env-node <<EOL
### APP ###
APP_PORT=2222

### XRAY ###
$(echo -e "$CERTIFICATE" | sed 's/\\n$//')
EOL

    local SELFSTEAL_BASE_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")
    declare -A unique_domains
    unique_domains["$SELFSTEAL_BASE_DOMAIN"]=1

    declare -A domains_to_check
    domains_to_check["$SELFSTEAL_DOMAIN"]=1
    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL"

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
    image: remnawave/node:2.1.7
    container_name: remnanode
    hostname: remnanode
    restart: always
    network_mode: host
    env_file:
      - path: /opt/remnawave/.env-node
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
    cat > /opt/remnawave/nginx.conf <<EOL
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

    root /var/www/html;
    index index.html;
}

server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;
    ssl_reject_handshake on;
    return 444;
}
EOL

    echo -e "${GRAY}  ${ARROW}${NC} Allowing panel IP to node port"
    ufw allow from $PANEL_IP to any port 2222 > /dev/null 2>&1
    ufw reload > /dev/null 2>&1

    echo -e "${GRAY}  ${ARROW}${NC} Launching node services"
    sleep 3
    cd /opt/remnawave
    docker compose up -d > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Docker containers started successfully"
    echo
    echo -e "${CYAN}${INFO}${NC} Installing camouflage template..."
    echo -e "${GRAY}  ${ARROW}${NC} Selecting random template"
    randomhtml
    echo -e "${GREEN}${CHECK}${NC} Camouflage template installed successfully"
    echo
    echo -e "${CYAN}${INFO}${NC} Checking node connection..."
    local max_attempts=5
    local attempt=1
    local delay=15

    while [ $attempt -le $max_attempts ]; do
        echo -e "${GRAY}  ${ARROW}${NC} Attempt $attempt of $max_attempts"
        if curl -s --fail --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -q "html"; then
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
}

#======================
# MAIN ENTRY FUNCTIONS
#======================

install_panel() {
    set -e
    
    INSTALL_DIR="/opt"
    APP_NAME="remnawave"
    APP_DIR="$INSTALL_DIR/$APP_NAME"
    DATA_DIR="/var/lib/$APP_NAME"
    COMPOSE_FILE="$APP_DIR/docker-compose.yml"
    ENV_FILE="$APP_DIR/.env"

    echo
    echo -e "${GREEN}Installing packages${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    install_system_packages

    echo
    echo -e "${GREEN}Preparing installation${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    move_variables_file

    echo
    echo -e "${GREEN}Installing panel${NC}"
    echo -e "${GREEN}================${NC}"
    echo

    create_panel
    start_panel_services

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Panel URL:${NC}"
    echo -e "${WHITE}https://${PANEL_DOMAIN}/auth/login?${cookies_random1}=${cookies_random2}${NC}"
    echo
    echo -e "${CYAN}Admin Credentials (${YELLOW}SAVE THESE${CYAN}):${NC}"
    echo -e "${WHITE}Username: $SUPERADMIN_USERNAME${NC}"
    echo -e "${WHITE}Password: $SUPERADMIN_PASSWORD${NC}"
    echo
    echo -e "${CYAN}Configuration File:${NC}"
    echo -e "${WHITE}Variables saved to: $APP_DIR/remnawave-vars.sh${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check logs: cd /opt/remnawave && docker compose logs -f${NC}"
    echo -e "${WHITE}• Restart service: cd /opt/remnawave && docker compose restart${NC}"
    echo
}

install_node() {
    set -e
    
    INSTALL_DIR="/opt"
    APP_NAME="remnawave"
    APP_DIR="$INSTALL_DIR/$APP_NAME"
    DATA_DIR="/var/lib/$APP_NAME"
    COMPOSE_FILE="$APP_DIR/docker-compose.yml"

    echo
    echo -e "${GREEN}Installing packages${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    install_system_packages

    echo
    echo -e "${GREEN}Preparing installation${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    move_variables_file

    echo
    echo -e "${GREEN}Installing node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    create_node
    start_node_services

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check logs: cd /opt/remnawave && docker compose logs -f${NC}"
    echo -e "${WHITE}• Restart service: cd /opt/remnawave && docker compose restart${NC}"
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
    
    case $INSTALL_TYPE in
        1)
            echo
            echo -e "${PURPLE}===================${NC}"
            echo -e "${WHITE}Panel Installation${NC}"
            echo -e "${PURPLE}===================${NC}"
            echo
            input_panel_domain
            input_sub_domain
            input_selfsteal_domain
            input_cloudflare_email
            input_cloudflare_api_key
            
            echo
            echo -e "${GREEN}Environment variables${NC}"
            echo -e "${GREEN}=====================${NC}"
            echo
            generate_configuration
            echo
            save_variables_to_file
            ;;
        2)
            echo
            echo -e "${PURPLE}==================${NC}"
            echo -e "${WHITE}Node Installation${NC}"
            echo -e "${PURPLE}==================${NC}"
            echo
            input_node_selfsteal_domain
            input_panel_ip
            input_cloudflare_email
            input_cloudflare_api_key
            input_ssl_certificate
            
            echo
            echo -e "${GREEN}Environment variables${NC}"
            echo -e "${GREEN}=====================${NC}"
            echo
            save_node_variables_to_file
            ;;
        3)
            echo
            echo -e "${YELLOW}${WARNING}${NC} Exiting installation..."
            exit 0
            ;;
        *)
            echo
            echo -e "${RED}${CROSS}${NC} Invalid choice. Please select 1, 2, or 3."
            exit 1
            ;;
    esac

    case $INSTALL_TYPE in
        1)
            install_panel
            ;;
        2)
            install_node
            ;;
    esac
}

main
exit 0
