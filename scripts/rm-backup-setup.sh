#!/bin/bash

#===================================
# REMNAWAVE TELEGRAM BACKUP MANAGER
#===================================

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
SCRIPT_URL="https://raw.githubusercontent.com/supermegaelf/rm-files/main/scripts/rm-backup.sh"
SCRIPT_DIR="/root/scripts"
SCRIPT_PATH="$SCRIPT_DIR/rm-backup.sh"

#================
# MAIN FUNCTIONS
#================

prepare_environment() {
    echo -e "${GREEN}Environment Preparation${NC}"
    echo -e "${GREEN}=======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Setting up backup environment..."
    echo -e "${GRAY}  ${ARROW}${NC} Checking directory structure"
    echo -e "${GRAY}  ${ARROW}${NC} Creating scripts directory"
    echo -e "${GRAY}  ${ARROW}${NC} Validating permissions"

    if [ ! -d "$SCRIPT_DIR" ]; then
        mkdir -p "$SCRIPT_DIR" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}${CROSS}${NC} Failed to create directory $SCRIPT_DIR"
            exit 1
        fi
        echo -e "${CYAN}${INFO}${NC} Directory created successfully"
    else
        echo -e "${YELLOW}${WARNING}${NC} Directory $SCRIPT_DIR already exists"
    fi

    echo -e "${GREEN}${CHECK}${NC} Environment preparation completed!"
}

download_backup_script() {
    echo
    echo -e "${GREEN}Script Download${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Downloading backup script..."
    echo -e "${GRAY}  ${ARROW}${NC} Connecting to GitHub repository"
    echo -e "${GRAY}  ${ARROW}${NC} Downloading rm-backup.sh file"
    echo -e "${GRAY}  ${ARROW}${NC} Setting executable permissions"

    wget -q -O "$SCRIPT_PATH" "$SCRIPT_URL" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Failed to download mb-backup.sh"
        exit 1
    fi

    chmod 700 "$SCRIPT_PATH" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Failed to set permissions on $SCRIPT_PATH"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Script download completed!"
}

configure_backup_script() {
    /bin/bash "$SCRIPT_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} rm-backup.sh failed to execute"
        exit 1
    fi
}

verify_installation() {
    echo -e "${GREEN}Installation Verification${NC}"
    echo -e "${GREEN}=========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Verifying installation status..."
    echo -e "${GRAY}  ${ARROW}${NC} Checking cron job setup"
    echo -e "${GRAY}  ${ARROW}${NC} Restarting cron service"
    echo -e "${GRAY}  ${ARROW}${NC} Validating system integration"

    if grep -q "$SCRIPT_PATH" /etc/crontab; then
        :  # Cron job found, continue silently
    else
        echo -e "${RED}${CROSS}${NC} Cron job was not added to /etc/crontab"
        exit 1
    fi

    systemctl restart cron > /dev/null 2>&1 || service cron restart > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}${WARNING}${NC} Failed to restart cron service, changes may not apply until next reboot"
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation verification completed!"
}

show_completion_summary() {
    echo
    echo -e "${PURPLE}=========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete!"
    echo -e "${PURPLE}=========================${NC}"
    echo
    echo -e "${CYAN}Installation Summary:${NC}"
    echo -e "${WHITE}• Backup script location: $SCRIPT_PATH${NC}"
    echo -e "${WHITE}• Backup schedule: Hourly execution${NC}"
    echo -e "${WHITE}• Service status: Active and configured${NC}"
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    echo
    echo -e "${PURPLE}==================================${NC}"
    echo -e "${NC}REMNAWAVE TELEGRAM BACKUP MANAGER${NC}"
    echo -e "${PURPLE}==================================${NC}"
    echo

    set -e

    prepare_environment
    download_backup_script
    configure_backup_script
    verify_installation
    show_completion_summary
    echo
}

# Execute main function
main
