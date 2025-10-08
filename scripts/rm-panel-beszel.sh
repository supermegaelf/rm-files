#!/bin/bash

#================================
# REMNAWAVE PANEL BESZEL MANAGER
#================================

# Color constants
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

# Status symbols
readonly CHECK="✓"
readonly CROSS="✗"
readonly WARNING="!"
readonly INFO="*"
readonly ARROW="→"

# Global variables
PANEL_DOMAIN=""
BASE_DOMAIN=""
MONITOR_DOMAIN=""

#======================
# VALIDATION FUNCTIONS
#======================

# Check root privileges
check_root_privileges() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}${CROSS}${NC} This script must be run as root"
        echo
        exit 1
    fi
}

# Check Beszel installation status
check_beszel_status() {
    local hub_installed=false
    local agent_installed=false
    
    if [ -d "/opt/beszel" ] && [ -f "/opt/beszel/docker-compose.yml" ]; then
        if docker ps -a | grep -q "beszel "; then
            hub_installed=true
        fi
    fi
    
    if [ -d "/opt/beszel-agent" ] && [ -f "/opt/beszel-agent/docker-compose.yml" ]; then
        if docker ps -a | grep -q "beszel-agent"; then
            agent_installed=true
        fi
    fi
    
    echo "$hub_installed,$agent_installed"
}

#==================
# STATUS FUNCTIONS
#==================

# Show current status
show_status() {
    echo
    echo -e "${PURPLE}==============${NC}"
    echo -e "${NC}Beszel Status${NC}"
    echo -e "${PURPLE}==============${NC}"
    echo
    echo -e "${GREEN}Service Status${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking Beszel installation status..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying directory structure"
    echo -e "${GRAY}  ${ARROW}${NC} Checking Docker containers"
    
    local status=$(check_beszel_status)
    local hub_installed=$(echo $status | cut -d',' -f1)
    local agent_installed=$(echo $status | cut -d',' -f2)
    
    if [ "$hub_installed" != "true" ] && [ "$agent_installed" != "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel is not installed"
        echo
        return
    fi

    # Check Beszel Hub
    if [ "$hub_installed" = "true" ]; then
        if docker ps | grep -q "beszel "; then
            echo -e "${GREEN}${CHECK}${NC} Beszel Hub is running"
        else
            echo -e "${RED}${CROSS}${NC} Beszel Hub is not running"
        fi
    fi
    
    # Check Beszel Agent
    if [ "$agent_installed" = "true" ]; then
        if docker ps | grep -q "beszel-agent"; then
            echo -e "${GREEN}${CHECK}${NC} Beszel Agent is running"
        else
            echo -e "${RED}${CROSS}${NC} Beszel Agent is not running"
        fi
    fi
}

#============================
# INPUT VALIDATION FUNCTIONS
#============================

# Validate domain
validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$domain" =~ [[:space:]] ]]; then
        return 0
    fi
    return 1
}

# Input panel domain
input_panel_domain() {
    echo -ne "${CYAN}Panel monitoring domain (e.g., monitoring.example.com): ${NC}"
    read PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]] || ! validate_domain "$PANEL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain (e.g., monitoring.example.com)."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read PANEL_DOMAIN
    done
}

# Extract base domain
extract_base_domain() {
    echo -e "${CYAN}${INFO}${NC} Extracting base domain..."
    echo -e "${GRAY}  ${ARROW}${NC} Processing panel domain"
    BASE_DOMAIN=$(echo "$PANEL_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
    MONITOR_DOMAIN="$PANEL_DOMAIN"
    echo -e "${GREEN}${CHECK}${NC} Base domain extracted: ${WHITE}$BASE_DOMAIN${NC}"
}

#============================
# BESZEL HUB SETUP FUNCTIONS
#============================

# Create Beszel Hub structure
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

# Create Hub docker-compose
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

# Start Hub container
start_hub_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Hub container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"
    
    cd /opt/beszel
    docker compose up -d > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Hub started successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to start Beszel Hub"
        exit 1
    fi
}

#==============================
# BESZEL AGENT SETUP FUNCTIONS
#==============================

# Create Beszel Agent structure
create_agent_structure() {
    echo
    echo -e "${GREEN}Beszel Agent Setup${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating Beszel Agent directory structure..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating /opt/beszel-agent directory"
    mkdir -p /opt/beszel-agent
    echo -e "${GREEN}${CHECK}${NC} Directory structure created!"
}

# Create Agent docker-compose
create_agent_docker_compose() {
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

# Start Agent container
start_agent_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Agent container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"
    
    cd /opt/beszel-agent
    docker compose up -d > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Agent started successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to start Beszel Agent"
        exit 1
    fi
}

#========================
# FIREWALL CONFIGURATION
#========================

# Configure UFW firewall
configure_firewall() {
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

#================================
# NGINX CONFIGURATION MANAGEMENT
#================================

# Backup existing nginx config
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
        exit 1
    fi
}

# Add Beszel section to nginx config
add_beszel_to_nginx() {
    echo
    echo -e "${GREEN}Nginx Configuration Update${NC}"
    echo -e "${GREEN}==========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Adding Beszel configuration to Nginx..."
    echo -e "${GRAY}  ${ARROW}${NC} Extracting base domain"
    
    local BASE_DOMAIN=$(echo "$MONITOR_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
    
    echo -e "${GRAY}  ${ARROW}${NC} Preparing configuration"

    head -n -5 /opt/remnawave/nginx.conf > /opt/remnawave/nginx.conf.tmp
    mv /opt/remnawave/nginx.conf.tmp /opt/remnawave/nginx.conf
    
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

# Restart nginx container
restart_nginx_container() {
    echo
    echo -e "${GREEN}Nginx Container Restart${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restarting Nginx container..."
    echo -e "${GRAY}  ${ARROW}${NC} Navigating to Remnawave directory"
    
    cd /opt/remnawave
    
    echo -e "${GRAY}  ${ARROW}${NC} Restarting remnawave-nginx service"
    docker compose restart remnawave-nginx > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${CHECK}${NC} Nginx restarted successfully!"
    else
        echo -e "${RED}${CROSS}${NC} Failed to restart Nginx"
        exit 1
    fi
}

# Restore nginx config from backup
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
        cd /opt/remnawave
        docker compose restart remnawave-nginx > /dev/null 2>&1
        
        echo -e "${GREEN}${CHECK}${NC} Nginx configuration restored!"
    else
        echo -e "${YELLOW}${WARNING}${NC} No backup found, skipping"
    fi
}

#========================
# VERIFICATION FUNCTIONS
#========================

# Verify installation
verify_installation() {
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

# Display completion info
display_installation_completion() {
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
    echo -e "${WHITE}3. Click \"Copy docker compose\", open \"docker-compose\" and insert \"PUBLIC_KEY\" and \"TOKEN\":${NC}"
    echo -e "${WHITE}nano /opt/beszel-agent/docker-compose.yml${NC}"
    echo
    echo -e "${WHITE}4. Run:${NC}"
    echo -e "${WHITE}cd /opt/beszel-agent && docker compose down && docker compose up -d${NC}"
}

#============================
# MAIN INSTALLATION FUNCTION
#============================

# Install Beszel
install_beszel() {
    echo
    echo -e "${PURPLE}===============================${NC}"
    echo -e "${NC}Beszel Monitoring Installation${NC}"
    echo -e "${PURPLE}===============================${NC}"
    echo

    # Get panel domain
    input_panel_domain

    echo
    echo -e "${GREEN}Configuration Summary${NC}"
    echo -e "${GREEN}=====================${NC}"
    echo

    extract_base_domain

    echo
    echo -e "${CYAN}${INFO}${NC} Checking installation requirements..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying existing Beszel installation"

    # Check if Beszel is already installed
    local status=$(check_beszel_status)
    local hub_installed=$(echo $status | cut -d',' -f1)
    local agent_installed=$(echo $status | cut -d',' -f2)
    
    if [ "$hub_installed" = "true" ] || [ "$agent_installed" = "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel is already installed!"
        echo -e "${RED}Please uninstall it first if you want to reinstall.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}${CHECK}${NC} System requirements validated!"

    set -e

    # Execute installation steps
    create_hub_structure
    create_hub_docker_compose
    start_hub_container
    
    create_agent_structure
    create_agent_docker_compose
    start_agent_container
    
    configure_firewall
    backup_nginx_config
    add_beszel_to_nginx
    restart_nginx_container
    verify_installation
    display_installation_completion
}

#==========================
# UNINSTALLATION FUNCTIONS
#==========================

# Uninstall Beszel
uninstall_beszel() {
    echo
    # Confirmation
    echo -ne "${YELLOW}Are you sure you want to uninstall Beszel? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        return 0
    fi

    echo
    echo -e "${PURPLE}=================================${NC}"
    echo -e "${NC}Beszel Monitoring Uninstallation${NC}"
    echo -e "${PURPLE}=================================${NC}"
    echo
    echo -e "${GREEN}Status Verification${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking current installation status..."
    echo -e "${GRAY}  ${ARROW}${NC} Scanning for Beszel components"
    echo -e "${GRAY}  ${ARROW}${NC} Identifying services to remove"

    # Check if Beszel is installed
    local status=$(check_beszel_status)
    local hub_installed=$(echo $status | cut -d',' -f1)
    local agent_installed=$(echo $status | cut -d',' -f2)
    
    if [ "$hub_installed" != "true" ] && [ "$agent_installed" != "true" ]; then
        echo -e "${YELLOW}Beszel is not installed on this system.${NC}"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation status check completed!"
    echo

    echo -e "${GREEN}Docker Services Removal${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Docker containers..."
    
    # Stop and remove Beszel Hub
    if [ -d "/opt/beszel" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Hub"
        cd /opt/beszel
        docker compose down > /dev/null 2>&1 || true
    fi

    # Stop and remove Beszel Agent
    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        cd /opt/beszel-agent
        docker compose down > /dev/null 2>&1 || true
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
    
    # Remove directories
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
    
    # Remove UFW rules
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

#================
# MENU FUNCTIONS
#================

# Show main menu
show_main_menu() {
    local status=$(check_beszel_status)
    local hub_installed=$(echo $status | cut -d',' -f1)
    local agent_installed=$(echo $status | cut -d',' -f2)
    local beszel_installed=false
    
    if [ "$hub_installed" = "true" ] || [ "$agent_installed" = "true" ]; then
        beszel_installed=true
    fi
    
    echo -e "${CYAN}Please select an action:${NC}"
    echo
    if [ "$beszel_installed" = "true" ]; then
        echo -e "${BLUE}1.${NC} Show Status"
        echo -e "${YELLOW}2.${NC} Uninstall"
        echo -e "${RED}3.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Install"
        echo -e "${YELLOW}2.${NC} Uninstall"
        echo -e "${RED}3.${NC} Exit"
    fi
    echo
}

# Handle user choice
handle_user_choice() {
    local status=$(check_beszel_status)
    local hub_installed=$(echo $status | cut -d',' -f1)
    local agent_installed=$(echo $status | cut -d',' -f2)
    local beszel_installed=false
    
    if [ "$hub_installed" = "true" ] || [ "$agent_installed" = "true" ]; then
        beszel_installed=true
    fi
    
    while true; do
        if [ "$beszel_installed" = "true" ]; then
            echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
            read CHOICE
        else
            echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
            read CHOICE
        fi
        
        case $CHOICE in
            1)
                if [ "$beszel_installed" = "true" ]; then
                    show_status
                else
                    install_beszel
                fi
                break
                ;;
            2)
                uninstall_beszel
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

# Main function
main() {
    # Check root privileges first
    check_root_privileges

    # Display script header
    echo
    echo -e "${PURPLE}===============================${NC}"
    echo -e "${NC}REMNAWAVE PANEL BESZEL MANAGER${NC}"
    echo -e "${PURPLE}===============================${NC}"
    echo

    # Show menu and handle user choice
    show_main_menu
    handle_user_choice
    echo
}

# Execute main function
main
