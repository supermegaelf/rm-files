#!/bin/bash

#=========================
# REMNAWAVE BESZEL MANAGER
#=========================

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

PANEL_IP=""
MONITOR_DOMAIN=""
BASE_DOMAIN=""
HUB_DOMAIN=""
INSTALL_STEP=""
HUB_STARTED=false
AGENT_STARTED=false
FIREWALL_CONFIGURED=false
NGINX_BACKUPED=false
NGINX_MODIFIED=false

#======================
# VALIDATION FUNCTIONS
#======================

check_root_privileges() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}${CROSS}${NC} This script must be run as root"
        echo
        exit 1
    fi
}

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$domain" =~ [[:space:]] ]]; then
        return 0
    fi
    return 1
}

#================================
# INSTALLATION STATUS FUNCTIONS
#================================

check_panel_installed() {
    if [ -d "/opt/beszel" ] && [ -f "/opt/beszel/docker-compose.yml" ]; then
        if docker ps -a | grep -q "beszel "; then
            echo "true"
            return
        fi
    fi
    echo "false"
}

check_node_installed() {
    if [ -d "/opt/beszel-agent" ] && [ -f "/opt/beszel-agent/docker-compose.yml" ]; then
        if docker ps -a | grep -q "beszel-agent" && ! docker ps -a | grep -q "beszel "; then
            echo "true"
            return
        fi
    fi
    echo "false"
}

#============================
# INPUT VALIDATION FUNCTIONS
#============================

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

input_monitor_domain() {
    echo -ne "${CYAN}Panel monitoring domain (e.g., monitoring.example.com): ${NC}"
    read MONITOR_DOMAIN
    while [[ -z "$MONITOR_DOMAIN" ]] || ! validate_domain "$MONITOR_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain (e.g., monitoring.example.com)."
        echo
        echo -ne "${CYAN}Panel monitoring domain: ${NC}"
        read MONITOR_DOMAIN
    done
}

input_hub_domain() {
    echo -ne "${CYAN}Panel monitoring domain (e.g., monitoring.example.com): ${NC}"
    read HUB_DOMAIN
    while [[ -z "$HUB_DOMAIN" ]] || ! validate_domain "$HUB_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain (e.g., monitoring.example.com)."
        echo
        echo -ne "${CYAN}Panel monitoring domain: ${NC}"
        read HUB_DOMAIN
    done
}

extract_base_domain() {
    echo -e "${CYAN}${INFO}${NC} Extracting base domain..."
    echo -e "${GRAY}  ${ARROW}${NC} Processing monitoring domain"
    BASE_DOMAIN=$(echo "$MONITOR_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
    echo -e "${GREEN}${CHECK}${NC} Base domain extracted: ${WHITE}$BASE_DOMAIN${NC}"
}

#========================
# PANEL SETUP FUNCTIONS
#========================

create_hub_structure() {
    echo
    echo -e "${GREEN}Beszel Hub Setup${NC}"
    echo -e "${GREEN}================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating Beszel Hub directory structure..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating /opt/beszel directory"
    mkdir -p /opt/beszel
    echo -e "${GRAY}  ${ARROW}${NC} Creating data directory"
    mkdir -p /opt/beszel/data
    echo -e "${GREEN}${CHECK}${NC} Directory structure created!"
}

create_hub_docker_compose() {
    echo
    echo -e "${CYAN}${INFO}${NC} Creating Docker Compose configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Generating docker-compose.yml"

    cat > /opt/beszel/docker-compose.yml << 'EOF'
services:
  beszel:
    image: henrygd/beszel:latest
    container_name: beszel
    restart: unless-stopped
    ports:
      - "8090:8090"
      - "45876:45876"
    volumes:
      - ./data:/beszel_data
EOF

    echo -e "${GREEN}${CHECK}${NC} Docker Compose configuration created!"
}

start_hub_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Hub container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"

    if [ ! -d "/opt/beszel" ]; then
        echo -e "${RED}${CROSS}${NC} Directory /opt/beszel does not exist"
        return 1
    fi

    (cd /opt/beszel && docker compose up -d > /dev/null 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Hub started successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to start Beszel Hub"
        return 1
    fi
}

create_panel_agent_structure() {
    echo
    echo -e "${GREEN}Beszel Agent Setup${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating Beszel Agent directory structure..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating /opt/beszel-agent directory"
    mkdir -p /opt/beszel-agent
    echo -e "${GRAY}  ${ARROW}${NC} Creating data directory"
    mkdir -p /opt/beszel-agent/beszel_agent_data
    echo -e "${GREEN}${CHECK}${NC} Directory structure created!"
}

create_panel_agent_docker_compose() {
    echo
    echo -e "${CYAN}${INFO}${NC} Creating Agent Docker Compose configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Generating docker-compose.yml"

    cat > /opt/beszel-agent/docker-compose.yml << EOF
services:
  beszel-agent:
    image: henrygd/beszel-agent
    container_name: beszel-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./beszel_agent_data:/var/lib/beszel-agent
    environment:
      LISTEN: 45877
      KEY: 'PUBLIC_KEY'
      TOKEN: 'TOKEN'
      HUB_URL: https://$MONITOR_DOMAIN
EOF

    echo -e "${GREEN}${CHECK}${NC} Agent Docker Compose configuration created!"
}

start_panel_agent_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Agent container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"

    if [ ! -d "/opt/beszel-agent" ]; then
        echo -e "${RED}${CROSS}${NC} Directory /opt/beszel-agent does not exist"
        return 1
    fi

    (cd /opt/beszel-agent && docker compose up -d > /dev/null 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Agent started successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to start Beszel Agent"
        return 1
    fi
}

configure_panel_firewall() {
    echo
    echo -e "${GREEN}Firewall Configuration${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Configuring UFW firewall rules..."
    echo -e "${GRAY}  ${ARROW}${NC} Adding rule for Beszel Web UI (8090)"
    ufw allow 8090/tcp comment 'Beszel Web UI' > /dev/null 2>&1
    echo -e "${GRAY}  ${ARROW}${NC} Adding rule for Beszel Agents (45876)"
    ufw allow 45876/tcp comment 'Beszel Agents' > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Firewall rules configured!"
}

backup_nginx_config() {
    echo
    echo -e "${GREEN}Nginx Configuration Backup${NC}"
    echo -e "${GREEN}===========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating backup of nginx configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Checking nginx config file"

    if [ -f "/opt/remnawave/nginx.conf" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Creating backup copy"
        cp /opt/remnawave/nginx.conf /opt/remnawave/nginx.conf.backup
        echo -e "${GREEN}${CHECK}${NC} Nginx configuration backed up!"
    else
        echo -e "${RED}${CROSS}${NC} Nginx config not found at /opt/remnawave/nginx.conf"
        return 1
    fi
}

add_beszel_to_nginx() {
    echo
    echo -e "${GREEN}Nginx Configuration Update${NC}"
    echo -e "${GREEN}==========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Adding Beszel configuration to Nginx..."
    echo -e "${GRAY}  ${ARROW}${NC} Preparing configuration"

    local total_lines=$(wc -l < /opt/remnawave/nginx.conf)
    if [ "$total_lines" -lt 6 ]; then
        echo -e "${RED}${CROSS}${NC} Nginx config file is too small ($total_lines lines), cannot safely remove last 5 lines"
        return 1
    fi

    head -n -5 /opt/remnawave/nginx.conf > /opt/remnawave/nginx.conf.tmp || {
        echo -e "${RED}${CROSS}${NC} Failed to process nginx config"
        return 1
    }
    mv /opt/remnawave/nginx.conf.tmp /opt/remnawave/nginx.conf || {
        echo -e "${RED}${CROSS}${NC} Failed to update nginx config"
        return 1
    }

    echo -e "${GRAY}  ${ARROW}${NC} Inserting Beszel server block"
    cat >> /opt/remnawave/nginx.conf << EOF

server {
    server_name  $MONITOR_DOMAIN;

    listen       443 ssl;
    http2        on;

    location / {
        proxy_redirect          off;
        proxy_http_version      1.1;
        proxy_pass              http://127.0.0.1:8090;
        proxy_set_header        Upgrade \$http_upgrade;
        proxy_set_header        Connection "upgrade";
        proxy_set_header        Host \$host;
        proxy_set_header        X-Real-IP \$remote_addr;
        proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto \$scheme;
    }

    ssl_certificate "/etc/nginx/ssl/$BASE_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$BASE_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$BASE_DOMAIN/fullchain.pem";

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
}

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOF

    echo -e "${GREEN}${CHECK}${NC} Beszel configuration added!"
}

restart_nginx_container() {
    echo
    echo -e "${GREEN}Nginx Container Restart${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restarting Nginx container..."
    echo -e "${GRAY}  ${ARROW}${NC} Validating nginx configuration"

    if docker ps --format '{{.Names}}' | grep -q "^remnawave-nginx$"; then
        if ! docker exec remnawave-nginx nginx -t 2>&1 | grep -q "syntax is ok"; then
            echo -e "${RED}${CROSS}${NC} Nginx config syntax error"
            docker exec remnawave-nginx nginx -t 2>&1 | tail -5
            echo -e "${YELLOW}${WARNING}${NC} Restoring backup configuration"
            if [ -f "/opt/remnawave/nginx.conf.backup" ]; then
                mv /opt/remnawave/nginx.conf.backup /opt/remnawave/nginx.conf
                echo -e "${GREEN}${CHECK}${NC} Backup configuration restored"
            fi
            return 1
        fi
    fi

    if [ ! -d "/opt/remnawave" ]; then
        echo -e "${RED}${CROSS}${NC} Directory /opt/remnawave does not exist"
        return 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Restarting remnawave-nginx service"
    (cd /opt/remnawave && docker compose restart remnawave-nginx > /dev/null 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Nginx restarted successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to restart Nginx"
        return 1
    fi
}

restore_nginx_config() {
    echo -e "${GREEN}Nginx Configuration Restoration${NC}"
    echo -e "${GREEN}================================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restoring nginx configuration from backup..."
    echo -e "${GRAY}  ${ARROW}${NC} Checking for backup file"

    if [ -f "/opt/remnawave/nginx.conf.backup" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Restoring configuration file"
        mv /opt/remnawave/nginx.conf.backup /opt/remnawave/nginx.conf

        echo -e "${GRAY}  ${ARROW}${NC} Restarting Nginx container"
        if [ -d "/opt/remnawave" ]; then
            (cd /opt/remnawave && docker compose restart remnawave-nginx > /dev/null 2>&1 || true)
        fi

        echo -e "${GREEN}${CHECK}${NC} Nginx configuration restored!"
    else
        echo -e "${YELLOW}${WARNING}${NC} No backup found, skipping"
    fi
}

verify_panel_installation() {
    echo
    echo -e "${GREEN}Installation Verification${NC}"
    echo -e "${GREEN}=========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Verifying Beszel installation..."
    echo -e "${GRAY}  ${ARROW}${NC} Waiting for services to initialize"

    sleep 10

    echo -e "${GRAY}  ${ARROW}${NC} Checking Beszel Hub container"
    if docker ps | grep -q "beszel "; then
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Hub: ${GREEN}Running${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Hub: ${RED}Not running${NC}"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Checking Beszel Agent container"
    if docker ps | grep -q "beszel-agent"; then
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${GREEN}Running${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${RED}Not running${NC}"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Checking port availability"
    if ss -tlnp | grep -q 8090; then
        echo -e "${GRAY}  ${ARROW}${NC} Port 8090: ${GREEN}Listening${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Port 8090: ${YELLOW}Not listening${NC}"
    fi

    if ss -tlnp | grep -q 45876; then
        echo -e "${GRAY}  ${ARROW}${NC} Port 45876: ${GREEN}Listening${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Port 45876: ${YELLOW}Not listening${NC}"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Testing HTTP endpoint"
    if curl -s http://localhost:8090 > /dev/null 2>&1; then
        echo -e "${GRAY}  ${ARROW}${NC} HTTP endpoint: ${GREEN}Accessible${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} HTTP endpoint: ${YELLOW}Not responding${NC}"
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation verification completed!"
}

display_panel_completion() {
    echo

    echo -e "${PURPLE}=========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete!"
    echo -e "${PURPLE}=========================${NC}"
    echo

    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}1. Follow the link and create admin account:${NC}"
    echo -e "${WHITE}https://$MONITOR_DOMAIN${NC}"
    echo
    echo -e "${WHITE}2. Click \"Add System\" and fill in the fields:${NC}"
    echo -e "${WHITE}Name: Panel${NC}"
    echo -e "${WHITE}Host/IP: 127.0.0.1${NC}"
    echo
    echo -e "${WHITE}3. Click \"Copy docker compose\", open \"docker-compose\" using the command below, and replace the content:${NC}"
    echo -e "${WHITE}nano /opt/beszel-agent/docker-compose.yml${NC}"
    echo
    echo -e "${WHITE}4. Run:${NC}"
    echo -e "${WHITE}cd /opt/beszel-agent && docker compose down && docker compose up -d${NC}"
}

rollback_panel_installation() {
    echo
    echo -e "${RED}${CROSS}${NC} Installation failed at step: $INSTALL_STEP"
    echo -e "${YELLOW}${WARNING}${NC} Starting rollback..."
    echo

    if [ "$NGINX_MODIFIED" = "true" ] || [ "$NGINX_BACKUPED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Restoring nginx configuration"
        if [ -f "/opt/remnawave/nginx.conf.backup" ]; then
            mv /opt/remnawave/nginx.conf.backup /opt/remnawave/nginx.conf
            if [ -d "/opt/remnawave" ]; then
                (cd /opt/remnawave && docker compose restart remnawave-nginx > /dev/null 2>&1 || true)
            fi
        fi
    fi

    if [ "$FIREWALL_CONFIGURED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Removing firewall rules"
        ufw delete allow 8090/tcp > /dev/null 2>&1 || true
        ufw delete allow 45876/tcp > /dev/null 2>&1 || true
    fi

    if [ "$AGENT_STARTED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        if [ -d "/opt/beszel-agent" ]; then
            (cd /opt/beszel-agent && docker compose down > /dev/null 2>&1 || true)
        fi
        rm -rf /opt/beszel-agent || true
    fi

    if [ "$HUB_STARTED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Hub"
        if [ -d "/opt/beszel" ]; then
            (cd /opt/beszel && docker compose down > /dev/null 2>&1 || true)
        fi
        rm -rf /opt/beszel || true
    fi

    echo -e "${GREEN}${CHECK}${NC} Rollback completed"
    echo
}

install_panel_beszel() {
    echo
    echo -e "${PURPLE}===============================${NC}"
    echo -e "${WHITE}Beszel Monitoring Installation${NC}"
    echo -e "${PURPLE}===============================${NC}"
    echo

    input_monitor_domain

    echo
    echo -e "${GREEN}Configuration Summary${NC}"
    echo -e "${GREEN}=====================${NC}"
    echo

    extract_base_domain

    echo
    echo -e "${CYAN}${INFO}${NC} Checking installation requirements..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying existing Beszel installation"

    local panel_installed=$(check_panel_installed)

    if [ "$panel_installed" = "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel is already installed on panel!"
        echo -e "${RED}Please uninstall it first if you want to reinstall.${NC}"
        return 1
    fi

    echo -e "${GREEN}${CHECK}${NC} System requirements validated!"

    trap rollback_panel_installation ERR
    set -e

    INSTALL_STEP="Creating Hub structure"
    create_hub_structure

    INSTALL_STEP="Creating Hub docker-compose"
    create_hub_docker_compose

    INSTALL_STEP="Starting Hub container"
    start_hub_container
    HUB_STARTED=true

    INSTALL_STEP="Creating Agent structure"
    create_panel_agent_structure

    INSTALL_STEP="Creating Agent docker-compose"
    create_panel_agent_docker_compose

    INSTALL_STEP="Starting Agent container"
    start_panel_agent_container
    AGENT_STARTED=true

    INSTALL_STEP="Configuring firewall"
    configure_panel_firewall
    FIREWALL_CONFIGURED=true

    INSTALL_STEP="Backing up nginx config"
    backup_nginx_config
    NGINX_BACKUPED=true

    INSTALL_STEP="Adding Beszel to nginx"
    add_beszel_to_nginx
    NGINX_MODIFIED=true

    INSTALL_STEP="Restarting nginx"
    restart_nginx_container

    INSTALL_STEP="Verification"
    verify_panel_installation

    trap - ERR
    set +e

    display_panel_completion
}

uninstall_panel_beszel() {
    echo
    echo -ne "${YELLOW}Are you sure you want to uninstall Beszel from panel? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        return 0
    fi

    echo
    echo -e "${PURPLE}=================================${NC}"
    echo -e "${WHITE}Beszel Monitoring Uninstallation${NC}"
    echo -e "${PURPLE}=================================${NC}"
    echo

    echo -e "${GREEN}Docker Services Removal${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Docker containers..."

    if [ -d "/opt/beszel" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Hub"
        (cd /opt/beszel && docker compose down > /dev/null 2>&1 || true)
    fi

    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        (cd /opt/beszel-agent && docker compose down > /dev/null 2>&1 || true)
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Removing container images"
    docker rmi henrygd/beszel:latest > /dev/null 2>&1 || true
    docker rmi henrygd/beszel-agent:latest > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Docker services removal completed!"
    echo

    echo -e "${GREEN}File System Cleanup${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Beszel files and directories..."

    if [ -d "/opt/beszel" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Removing /opt/beszel"
        rm -rf /opt/beszel
    fi

    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Removing /opt/beszel-agent"
        rm -rf /opt/beszel-agent
    fi

    echo -e "${GREEN}${CHECK}${NC} File system cleanup completed!"
    echo

    restore_nginx_config

    echo
    echo -e "${GREEN}Firewall Configuration${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing firewall rules..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing UFW rules"
    ufw delete allow 8090/tcp > /dev/null 2>&1 || true
    ufw delete allow 45876/tcp > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Firewall configuration cleanup completed!"
    echo

    echo -e "${PURPLE}===========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Uninstallation complete!"
    echo -e "${PURPLE}===========================${NC}"
    echo
    echo -e "${CYAN}All Beszel components have been successfully removed.${NC}"
}

#======================
# NODE SETUP FUNCTIONS
#======================

create_node_agent_structure() {
    echo
    echo -e "${GREEN}Beszel Agent Setup${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating Beszel Agent directory structure..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating /opt/beszel-agent directory"
    mkdir -p /opt/beszel-agent
    echo -e "${GRAY}  ${ARROW}${NC} Creating data directory"
    mkdir -p /opt/beszel-agent/beszel_agent_data
    echo -e "${GREEN}${CHECK}${NC} Directory structure created!"
}

create_node_agent_docker_compose() {
    echo
    echo -e "${CYAN}${INFO}${NC} Creating Agent Docker Compose configuration..."
    echo -e "${GRAY}  ${ARROW}${NC} Generating docker-compose.yml"

    cat > /opt/beszel-agent/docker-compose.yml << EOF
services:
  beszel-agent:
    image: henrygd/beszel-agent
    container_name: beszel-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./beszel_agent_data:/var/lib/beszel-agent
    environment:
      LISTEN: 45876
      KEY: 'PUBLIC_KEY'
      TOKEN: 'TOKEN'
      HUB_URL: https://$HUB_DOMAIN
EOF

    echo -e "${GREEN}${CHECK}${NC} Agent Docker Compose configuration created!"
}

start_node_agent_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Agent container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"

    if [ ! -d "/opt/beszel-agent" ]; then
        echo -e "${RED}${CROSS}${NC} Directory /opt/beszel-agent does not exist"
        return 1
    fi

    (cd /opt/beszel-agent && docker compose up -d > /dev/null 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Agent started successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to start Beszel Agent"
        return 1
    fi
}

configure_node_firewall() {
    echo
    echo -e "${GREEN}Firewall Configuration${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Configuring UFW firewall rules..."
    echo -e "${GRAY}  ${ARROW}${NC} Adding rule for Beszel Agent (45876)"
    ufw allow from "$PANEL_IP" to any port 45876 proto tcp comment 'Beszel Agent' > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Firewall rules configured!"
}

verify_node_installation() {
    echo
    echo -e "${GREEN}Installation Verification${NC}"
    echo -e "${GREEN}=========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Verifying Beszel installation..."
    echo -e "${GRAY}  ${ARROW}${NC} Waiting for services to initialize"

    sleep 15

    echo -e "${GRAY}  ${ARROW}${NC} Checking Beszel Agent container"
    if docker ps | grep -q "beszel-agent"; then
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${GREEN}Running${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${RED}Not running${NC}"
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation verification completed!"
}

display_node_completion() {
    echo

    echo -e "${PURPLE}=========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete!"
    echo -e "${PURPLE}=========================${NC}"
    echo

    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${WHITE}1. Follow the link and login your panel account:${NC}"
    echo -e "${WHITE}https://$HUB_DOMAIN${NC}"
    echo
    echo -e "${WHITE}2. Click \"Add System\" and fill in the fields:${NC}"
    echo -e "${WHITE}Name: Node${NC}"
    echo -e "${WHITE}Host/IP: $(hostname -I | awk '{print $1}')${NC}"
    echo
    echo -e "${WHITE}3. Click \"Copy docker compose\", open \"docker-compose\" using the command below, and replace the content:${NC}"
    echo -e "${WHITE}nano /opt/beszel-agent/docker-compose.yml${NC}"
    echo
    echo -e "${WHITE}4. Run:${NC}"
    echo -e "${WHITE}cd /opt/beszel-agent && docker compose down && docker compose up -d${NC}"
}

rollback_node_installation() {
    echo
    echo -e "${RED}${CROSS}${NC} Installation failed at step: $INSTALL_STEP"
    echo -e "${YELLOW}${WARNING}${NC} Starting rollback..."
    echo

    if [ "$FIREWALL_CONFIGURED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Removing firewall rules"
        ufw status numbered | grep "Beszel Agent" | awk '{print $1}' | sed 's/\[//' | sed 's/\]//' | tac | while read num; do
            yes | ufw delete $num > /dev/null 2>&1 || true
        done
    fi

    if [ "$AGENT_STARTED" = "true" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        if [ -d "/opt/beszel-agent" ]; then
            (cd /opt/beszel-agent && docker compose down > /dev/null 2>&1 || true)
        fi
        rm -rf /opt/beszel-agent || true
    fi

    echo -e "${GREEN}${CHECK}${NC} Rollback completed"
    echo
}

install_node_beszel() {
    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${WHITE}Beszel Agent Installation${NC}"
    echo -e "${PURPLE}==========================${NC}"
    echo

    input_panel_ip
    input_hub_domain

    echo
    echo -e "${GREEN}Configuration Summary${NC}"
    echo -e "${GREEN}=====================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking installation requirements..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying existing Beszel installation"

    local node_installed=$(check_node_installed)

    if [ "$node_installed" = "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel Agent is already installed!"
        echo -e "${RED}Please uninstall it first if you want to reinstall.${NC}"
        return 1
    fi

    echo -e "${GREEN}${CHECK}${NC} System requirements validated!"

    trap rollback_node_installation ERR
    set -e

    INSTALL_STEP="Creating Agent structure"
    create_node_agent_structure

    INSTALL_STEP="Creating Agent docker-compose"
    create_node_agent_docker_compose

    INSTALL_STEP="Starting Agent container"
    start_node_agent_container
    AGENT_STARTED=true

    INSTALL_STEP="Configuring firewall"
    configure_node_firewall
    FIREWALL_CONFIGURED=true

    INSTALL_STEP="Verification"
    verify_node_installation

    trap - ERR
    set +e

    display_node_completion
}

uninstall_node_beszel() {
    echo
    echo -ne "${YELLOW}Are you sure you want to uninstall Beszel Agent? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        return 0
    fi

    echo
    echo -e "${PURPLE}============================${NC}"
    echo -e "${WHITE}Beszel Agent Uninstallation${NC}"
    echo -e "${PURPLE}============================${NC}"
    echo

    echo -e "${GREEN}Docker Services Removal${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Docker containers..."

    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        (cd /opt/beszel-agent && docker compose down > /dev/null 2>&1 || true)
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Removing container images"
    docker rmi henrygd/beszel-agent:latest > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Docker services removal completed!"
    echo

    echo -e "${GREEN}File System Cleanup${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Beszel files and directories..."

    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Removing /opt/beszel-agent"
        rm -rf /opt/beszel-agent
    fi

    echo -e "${GREEN}${CHECK}${NC} File system cleanup completed!"
    echo

    echo -e "${GREEN}Firewall Configuration${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing firewall rules..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing UFW rules"
    ufw status numbered | grep "Beszel Agent" | awk '{print $1}' | sed 's/\[//' | sed 's/\]//' | tac | while read num; do
        yes | ufw delete $num > /dev/null 2>&1
    done

    echo -e "${GREEN}${CHECK}${NC} Firewall configuration cleanup completed!"
    echo

    echo -e "${PURPLE}===========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Uninstallation complete!"
    echo -e "${PURPLE}===========================${NC}"
    echo
    echo -e "${CYAN}All Beszel components have been successfully removed.${NC}"
}

#================
# MENU FUNCTIONS
#================

show_main_menu() {
    local panel_installed=$(check_panel_installed)
    local node_installed=$(check_node_installed)

    echo -e "${CYAN}Please select an action:${NC}"
    echo

    if [ "$panel_installed" = "true" ]; then
        echo -e "${RED}1.${NC} Uninstall from Panel"
    else
        echo -e "${GREEN}1.${NC} Install on Panel"
    fi

    if [ "$node_installed" = "true" ]; then
        echo -e "${RED}2.${NC} Uninstall from Node"
    else
        echo -e "${GREEN}2.${NC} Install on Node"
    fi

    echo -e "${RED}3.${NC} Exit"
    echo
}

handle_user_choice() {
    local panel_installed=$(check_panel_installed)
    local node_installed=$(check_node_installed)

    while true; do
        echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
        read CHOICE

        case $CHOICE in
            1)
                if [ "$panel_installed" = "true" ]; then
                    uninstall_panel_beszel
                else
                    install_panel_beszel
                fi
                break
                ;;
            2)
                if [ "$node_installed" = "true" ]; then
                    uninstall_node_beszel
                else
                    install_node_beszel
                fi
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
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    check_root_privileges

    echo
    echo -e "${PURPLE}=========================${NC}"
    echo -e "${WHITE}REMNAWAVE BESZEL MANAGER${NC}"
    echo -e "${PURPLE}=========================${NC}"
    echo

    show_main_menu
    handle_user_choice
    echo
}

main
