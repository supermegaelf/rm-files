#!/bin/bash

#=============================
# REMNAWAVE TG BACKUP MANAGER
#=============================

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

SCRIPT_URL="https://raw.githubusercontent.com/supermegaelf/rm-files/main/scripts/backup.sh"
SCRIPT_DIR="/root/scripts"
SCRIPT_PATH="$SCRIPT_DIR/backup.sh"
BACKUP_LOG="/root/backup-output.txt"

#========
# HELPER
#========

is_installed() {
    [ -f "$SCRIPT_PATH" ] || grep -q "$SCRIPT_PATH" /etc/crontab 2>/dev/null
}

#===================
# INSTALL FUNCTIONS
#===================

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
        echo -e "${GRAY}  ${ARROW}${NC} Creating directory"
    else
        echo -e "${YELLOW}${WARNING}${NC} Directory $SCRIPT_DIR already exists"
    fi

    echo -e "${GREEN}${CHECK}${NC} Environment preparation complete"
}

download_backup_script() {
    echo
    echo -e "${GREEN}Script Download${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Downloading backup script..."
    echo -e "${GRAY}  ${ARROW}${NC} Connecting to GitHub repository"
    echo -e "${GRAY}  ${ARROW}${NC} Downloading backup.sh file"
    echo -e "${GRAY}  ${ARROW}${NC} Setting executable permissions"

    if ! curl -fsSL -o "$SCRIPT_PATH" "$SCRIPT_URL"; then
        echo -e "${RED}${CROSS}${NC} Failed to download backup.sh"
        exit 1
    fi

    if ! chmod 700 "$SCRIPT_PATH" > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to set permissions on $SCRIPT_PATH"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Script download complete"
}

configure_backup_script() {
    if ! /bin/bash "$SCRIPT_PATH"; then
        echo -e "${RED}${CROSS}${NC} backup.sh failed to execute"
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
        :
    else
        echo -e "${RED}${CROSS}${NC} Cron job was not added to /etc/crontab"
        exit 1
    fi

    if ! { systemctl restart cron || service cron restart; } > /dev/null 2>&1; then
        echo -e "${YELLOW}${WARNING}${NC} Failed to restart cron service, changes may not apply until next reboot"
    fi

    echo -e "${GREEN}${CHECK}${NC} Installation verification complete"
}

show_completion_summary() {
    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Installation Summary:${NC}"
    echo -e "${WHITE}• Backup script location: $SCRIPT_PATH${NC}"
    echo -e "${WHITE}• Backup schedule: Hourly execution${NC}"
    echo -e "${WHITE}• Service status: Active and configured${NC}"
}

perform_installation() {
    echo
    echo -e "${PURPLE}====================${NC}"
    echo -e "${WHITE}Backup Installation${NC}"
    echo -e "${PURPLE}====================${NC}"
    echo

    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${CROSS}${NC} This script must be run as root"
        exit 1
    fi

    if is_installed; then
        echo -e "${YELLOW}${WARNING}${NC} Backup appears to be already installed."
        echo
        echo -ne "${YELLOW}Do you want to reinstall? (y/N): ${NC}"
        read -r REINSTALL

        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}Installation cancelled.${NC}"
            exit 0
        fi
        echo
    fi

    set -e

    prepare_environment
    download_backup_script
    configure_backup_script
    verify_installation
    show_completion_summary
    echo
}

#====================
# UNINSTALL FUNCTION
#====================

perform_uninstall() {
    echo
    echo -e "${PURPLE}======================${NC}"
    echo -e "${WHITE}Backup Uninstallation${NC}"
    echo -e "${PURPLE}======================${NC}"
    echo

    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${CROSS}${NC} This script must be run as root"
        exit 1
    fi

    if ! is_installed; then
        echo -e "${YELLOW}${WARNING}${NC} Backup is not installed on this system."
        echo
        exit 0
    fi

    echo -ne "${YELLOW}Are you sure you want to continue? (y/N): ${NC}"
    read -r CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Uninstallation cancelled.${NC}"
        exit 0
    fi

    echo
    echo -e "${GREEN}Removing Cron Job${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing scheduled backup..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing entry from /etc/crontab"
    sed -i "\|$SCRIPT_PATH|d" /etc/crontab

    echo -e "${GRAY}  ${ARROW}${NC} Restarting cron service"
    if ! { systemctl restart cron || service cron restart; } > /dev/null 2>&1; then
        echo -e "${YELLOW}${WARNING}${NC} Failed to restart cron service, changes may not apply until next reboot"
    fi
    echo -e "${GREEN}${CHECK}${NC} Cron job removed"

    echo
    echo -e "${GREEN}Removing Files${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Removing backup files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing backup script"
    rm -f "$SCRIPT_PATH"
    echo -e "${GRAY}  ${ARROW}${NC} Removing log file"
    rm -f "$BACKUP_LOG"
    echo -e "${GRAY}  ${ARROW}${NC} Removing scripts directory if empty"
    rmdir "$SCRIPT_DIR" > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Backup files removed"

    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Uninstallation complete"
    echo -e "${PURPLE}==========================${NC}"
    echo
    exit 0
}

#================
# MENU FUNCTIONS
#================

show_main_menu() {
    echo
    echo -e "${PURPLE}============================${NC}"
    echo -e "${NC}Remnawave TG Backup Manager${NC}"
    echo -e "${PURPLE}============================${NC}"
    echo
    echo -e "${CYAN}Please select an action:${NC}"
    echo

    if is_installed; then
        echo -e "${GREEN}1.${NC} Uninstall"
        echo -e "${RED}2.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Install"
        echo -e "${RED}2.${NC} Exit"
    fi
    echo
}

handle_user_choice() {
    while true; do
        echo -ne "${CYAN}Enter your choice (1-2): ${NC}"
        read CHOICE
        case $CHOICE in
            1)
                if is_installed; then
                    ACTION="uninstall"
                else
                    ACTION="install"
                fi
                break
                ;;
            2)
                echo -e "${CYAN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}${CROSS}${NC} Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    if [ "$1" = "uninstall" ] || [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
        ACTION="uninstall"
    elif [ "$1" = "install" ] || [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
        ACTION="install"
    else
        show_main_menu
        handle_user_choice
    fi

    if [ "$ACTION" = "uninstall" ]; then
        perform_uninstall
    else
        perform_installation
    fi
}

main "$@"
exit 0
