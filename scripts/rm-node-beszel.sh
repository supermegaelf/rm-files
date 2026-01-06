#!/bin/bash

#===============================
# REMNAWAVE NODE BESZEL MANAGER
#===============================

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
PANEL_IP=""
HUB_DOMAIN=""
INSTALL_STEP=""
AGENT_STARTED=false
FIREWALL_CONFIGURED=false

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

# Validate IP
validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# Validate domain
validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$domain" =~ [[:space:]] ]]; then
        return 0
    fi
    return 1
}

# Check Beszel installation status
check_beszel_status() {
    local agent_installed=false
    
    if [ -d "/opt/beszel-agent" ] && [ -f "/opt/beszel-agent/docker-compose.yml" ]; then
        if docker ps -a | grep -q "beszel-agent"; then
            agent_installed=true
        fi
    fi
    
    echo "$agent_installed"
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
    
    local agent_installed=$(check_beszel_status)
    
    if [ "$agent_installed" != "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel Agent is not installed"
        echo
        return
    fi

    # Check Beszel Agent
    if docker ps | grep -q "beszel-agent"; then
        echo -e "${GREEN}${CHECK}${NC} Beszel Agent is running"
    else
        echo -e "${RED}${CROSS}${NC} Beszel Agent container exists but not running"
    fi
}

#============================
# INPUT VALIDATION FUNCTIONS
#============================

# Input panel IP
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

# Input panel monitoring domain
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
    echo -e "${GRAY}  ${ARROW}${NC} Creating data directory"
    mkdir -p /opt/beszel-agent/beszel_agent_data
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
      LISTEN: 45876
      KEY: 'PUBLIC_KEY'
      TOKEN: 'TOKEN'
      HUB_URL: https://$HUB_DOMAIN
EOF

    echo -e "${GREEN}${CHECK}${NC} Agent Docker Compose configuration created!"
}

# Start Agent container
start_agent_container() {
    echo
    echo -e "${CYAN}${INFO}${NC} Starting Beszel Agent container..."
    echo -e "${GRAY}  ${ARROW}${NC} Pulling latest image"
    echo -e "${GRAY}  ${ARROW}${NC} Starting service"
    
    if [ ! -d "/opt/beszel-agent" ]; then
        echo -e "${RED}${CROSS}${NC} Directory /opt/beszel-agent does not exist"
        exit 1
    fi
    
    cd /opt/beszel-agent || {
        echo -e "${RED}${CROSS}${NC} Failed to change directory to /opt/beszel-agent"
        exit 1
    }
    
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
    echo -e "${GRAY}  ${ARROW}${NC} Adding rule for Beszel Agent (45876)"
    ufw allow from "$PANEL_IP" to any port 45876 proto tcp comment 'Beszel Agent' > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Firewall rules configured!"
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
    
    sleep 15

    echo -e "${GRAY}  ${ARROW}${NC} Checking Beszel Agent container"
    if docker ps | grep -q "beszel-agent"; then
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${GREEN}Running${NC}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Beszel Agent: ${RED}Not running${NC}"
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

#============================
# ROLLBACK FUNCTION
#============================

# Rollback installation on error
rollback_installation() {
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
            cd /opt/beszel-agent || {
                echo -e "${YELLOW}${WARNING}${NC} Failed to change directory, continuing..."
            }
            docker compose down > /dev/null 2>&1 || true
        fi
        rm -rf /opt/beszel-agent || true
    fi
    
    echo -e "${GREEN}${CHECK}${NC} Rollback completed"
    echo
}

#============================
# MAIN INSTALLATION FUNCTION
#============================

# Install Beszel
install_beszel() {
    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${NC}Beszel Agent Installation${NC}"
    echo -e "${PURPLE}==========================${NC}"
    echo

    # Get panel IP and panel monitoring domain
    input_panel_ip
    input_hub_domain

    echo
    echo -e "${GREEN}Configuration Summary${NC}"
    echo -e "${GREEN}=====================${NC}"
    echo
    echo -e "${CYAN}${INFO}${NC} Checking installation requirements..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying existing Beszel installation"

    # Check if Beszel is already installed
    local agent_installed=$(check_beszel_status)
    
    if [ "$agent_installed" = "true" ]; then
        echo -e "${RED}${CROSS}${NC} Beszel Agent is already installed!"
        echo -e "${RED}Please uninstall it first if you want to reinstall.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}${CHECK}${NC} System requirements validated!"

    trap rollback_installation ERR
    set -e

    INSTALL_STEP="Creating Agent structure"
    create_agent_structure
    
    INSTALL_STEP="Creating Agent docker-compose"
    create_agent_docker_compose
    
    INSTALL_STEP="Starting Agent container"
    start_agent_container
    AGENT_STARTED=true
    
    INSTALL_STEP="Configuring firewall"
    configure_firewall
    FIREWALL_CONFIGURED=true
    
    INSTALL_STEP="Verification"
    verify_installation
    
    trap - ERR
    set +e
    
    display_installation_completion
}

#==========================
# UNINSTALLATION FUNCTIONS
#==========================

# Uninstall Beszel
uninstall_beszel() {
    echo
    # Confirmation
    echo -ne "${YELLOW}Are you sure you want to uninstall Beszel Agent? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        return 0
    fi

    echo
    echo -e "${PURPLE}============================${NC}"
    echo -e "${NC}Beszel Agent Uninstallation${NC}"
    echo -e "${PURPLE}============================${NC}"
    echo
    echo -e "${GREEN}Status Verification${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking current installation status..."
    echo -e "${GRAY}  ${ARROW}${NC} Scanning for Beszel components"
    echo -e "${GRAY}  ${ARROW}${NC} Identifying services to remove"

    # Check if Beszel is installed
    local agent_installed=$(check_beszel_status)
    
    if [ "$agent_installed" != "true" ]; then
        echo -e "${YELLOW}Beszel Agent is not installed on this system.${NC}"
        return 0
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation status check completed!"
    echo

    echo -e "${GREEN}Docker Services Removal${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Docker containers..."
    
    # Stop and remove Beszel Agent
    if [ -d "/opt/beszel-agent" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Stopping Beszel Agent"
        cd /opt/beszel-agent || {
            echo -e "${YELLOW}${WARNING}${NC} Failed to change directory, continuing..."
        }
        docker compose down > /dev/null 2>&1 || true
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Removing container images"
    docker rmi henrygd/beszel-agent:latest > /dev/null 2>&1 || true

    echo -e "${GREEN}${CHECK}${NC} Docker services removal completed!"
    echo

    echo -e "${GREEN}File System Cleanup${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing Beszel files and directories..."
    
    # Remove directory
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
    
    # Remove UFW rules - need to find and delete by comment
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

# Show main menu
show_main_menu() {
    local agent_installed=$(check_beszel_status)
    
    echo -e "${CYAN}Please select an action:${NC}"
    echo
    if [ "$agent_installed" = "true" ]; then
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
    local agent_installed=$(check_beszel_status)
    
    while true; do
        if [ "$agent_installed" = "true" ]; then
            echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
            read CHOICE
        else
            echo -ne "${CYAN}Enter your choice (1-3): ${NC}"
            read CHOICE
        fi
        
        case $CHOICE in
            1)
                if [ "$agent_installed" = "true" ]; then
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
    echo -e "${PURPLE}==============================${NC}"
    echo -e "${NC}REMNAWAVE NODE BESZEL MANAGER${NC}"
    echo -e "${PURPLE}==============================${NC}"
    echo

    # Show menu and handle user choice
    show_main_menu
    handle_user_choice
    echo
}

# Execute main function
main
