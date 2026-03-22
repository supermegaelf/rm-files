#!/bin/bash

#===========================
# REMNAWAVE TELEGRAM BACKUP
#===========================

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
POSTGRES_USER=""
POSTGRES_PASSWORD=""
SHOP_MYSQL_USER=""
SHOP_MYSQL_PASSWORD=""
TG_BOT_TOKEN=""
TG_CHAT_ID=""
TIMESTAMP=""
WORK_DIR=""
MAIN_BACKUP_FILE=""
SHOP_SQL_FILE=""

#=====================
# CONFIGURATION SETUP
#=====================

read_env_var() {
    local file="$1"
    local var="$2"
    grep "^${var}=" "$file" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'"
}

load_credentials() {
    echo -e "${CYAN}${INFO}${NC} Loading credentials..."

    # Remnawave PostgreSQL — read from /opt/remnawave/.env
    if [ ! -f /opt/remnawave/.env ]; then
        echo -e "${RED}${CROSS}${NC} /opt/remnawave/.env not found"
        exit 1
    fi
    POSTGRES_USER=$(read_env_var /opt/remnawave/.env POSTGRES_USER)
    POSTGRES_PASSWORD=$(read_env_var /opt/remnawave/.env POSTGRES_PASSWORD)
    echo -e "${GRAY}  ${ARROW}${NC} Remnawave DB: ${POSTGRES_USER}"

    # Shop Bot MySQL — read from /root/shop-bot/.env (optional)
    if [ -f /root/shop-bot/.env ]; then
        SHOP_MYSQL_USER=$(read_env_var /root/shop-bot/.env DB_USER)
        SHOP_MYSQL_PASSWORD=$(read_env_var /root/shop-bot/.env DB_PASS)
        echo -e "${GRAY}  ${ARROW}${NC} Shop Bot DB: ${SHOP_MYSQL_USER}"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Shop Bot: not found, skipping"
    fi

    echo -e "${GREEN}${CHECK}${NC} Credentials loaded."
    echo
}

configure_backup() {
    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${NC}REMNAWAVE TELEGRAM BACKUP${NC}"
    echo -e "${PURPLE}==========================${NC}"
    echo

    load_credentials

    if [ -t 0 ] && ([ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ]); then

        echo -ne "${CYAN}Telegram Bot Token: ${NC}"
        read TG_BOT_TOKEN

        echo -ne "${CYAN}Telegram Chat ID: ${NC}"
        read TG_CHAT_ID
        echo

        if [[ ! "$TG_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
            echo -e "${RED}${CROSS}${NC} Invalid Telegram Bot Token format"
            exit 1
        fi
        if [[ ! "$TG_CHAT_ID" =~ ^-?[0-9]+$ ]]; then
            echo -e "${RED}${CROSS}${NC} Invalid Telegram Chat ID format"
            exit 1
        fi

        echo -e "${CYAN}${INFO}${NC} Saving configuration..."
        echo -e "${GRAY}  ${ARROW}${NC} Setting Telegram parameters"
        echo -e "${GRAY}  ${ARROW}${NC} Creating cron schedule"

        sed -i "s|TG_BOT_TOKEN=\"[^\"]*\"|TG_BOT_TOKEN=\"$TG_BOT_TOKEN\"|" "$0"
        sed -i "s|TG_CHAT_ID=\"[^\"]*\"|TG_CHAT_ID=\"$TG_CHAT_ID\"|" "$0"

        if ! grep -q "/root/scripts/rm-backup.sh" /etc/crontab; then
            echo "0 */1 * * * root /bin/bash /root/scripts/rm-backup.sh >/dev/null 2>&1" | tee -a /etc/crontab > /dev/null 2>&1
        fi

        echo -e "${GREEN}${CHECK}${NC} Configuration saved successfully!"
        echo
    fi
}

#======================
# VALIDATION FUNCTIONS
#======================

validate_configuration() {
    if [ -z "$POSTGRES_USER" ]; then
        echo -e "${RED}${CROSS}${NC} POSTGRES_USER not found in /opt/remnawave/.env"
        exit 1
    fi

    if [ -z "$POSTGRES_PASSWORD" ]; then
        echo -e "${RED}${CROSS}${NC} POSTGRES_PASSWORD not found in /opt/remnawave/.env"
        exit 1
    fi

    if [[ ! "$TG_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        echo -e "${RED}${CROSS}${NC} Invalid Telegram Bot Token format"
        exit 1
    fi

    if [[ ! "$TG_CHAT_ID" =~ ^-?[0-9]+$ ]]; then
        echo -e "${RED}${CROSS}${NC} Invalid Telegram Chat ID format"
        exit 1
    fi
}

#================
# MAIN FUNCTIONS
#================

prepare_system() {
    echo -e "${GREEN}System Preparation${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Setting up backup environment..."
    echo -e "${GRAY}  ${ARROW}${NC} Creating temporary directory"
    echo -e "${GRAY}  ${ARROW}${NC} Initializing backup variables"
    echo -e "${GRAY}  ${ARROW}${NC} Validating permissions"

    TEMP_DIR=$(mktemp -d)
    if [ ! -d "$TEMP_DIR" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create temporary directory"
        exit 1
    fi

    TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
    WORK_DIR="$TEMP_DIR/work"
    mkdir -p "$WORK_DIR"
    MAIN_BACKUP_FILE="$TEMP_DIR/remnawave_backup_${TIMESTAMP}.tar.gz"
    SHOP_SQL_FILE="$TEMP_DIR/shop_${TIMESTAMP}.sql"

    echo -e "${GREEN}${CHECK}${NC} System preparation completed!"
}

check_containers() {
    echo
    echo -e "${GREEN}Docker Container Check${NC}"
    echo -e "${GREEN}======================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Checking Docker containers status..."
    echo -e "${GRAY}  ${ARROW}${NC} Verifying Remnawave PostgreSQL container"
    echo -e "${GRAY}  ${ARROW}${NC} Checking Shop database containers"
    echo -e "${GRAY}  ${ARROW}${NC} Validating container health"

    POSTGRES_CONTAINER_NAME="remnawave-db"
    if ! docker ps -q -f name="$POSTGRES_CONTAINER_NAME" | grep -q .; then
        echo -e "${RED}${CROSS}${NC} Container $POSTGRES_CONTAINER_NAME is not running"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    # Check for shop database container
    SHOP_CONTAINER_NAME=""
    
    if docker ps -q -f name="shop-bot-db-1" | grep -q .; then
        SHOP_CONTAINER_NAME="shop-bot-db-1"
        echo -e "${GRAY}  ${ARROW}${NC} Shop bot database container detected"
    else
        echo -e "${GRAY}  ${ARROW}${NC} No shop database container found"
    fi

    echo -e "${GREEN}${CHECK}${NC} Docker containers validated!"
}

create_database_backup() {
    echo
    echo -e "${GREEN}Database Backup Creation${NC}"
    echo -e "${GREEN}========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Creating database backups..."
    echo -e "${GRAY}  ${ARROW}${NC} User: ${POSTGRES_USER}"

    # Backup PostgreSQL — full dump compatible with db-migrate.sh restore
    local error_log
    error_log=$(mktemp)
    docker exec "$POSTGRES_CONTAINER_NAME" pg_dumpall -c -U "$POSTGRES_USER" 2>"$error_log" | gzip -9 > "$WORK_DIR/dump_${TIMESTAMP}.sql.gz"
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        cat "$error_log" >&2
        rm -f "$error_log"
        echo -e "${RED}${CROSS}${NC} Failed to backup remnawave database"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    rm -f "$error_log"
    echo -e "${GRAY}  ${ARROW}${NC} Remnawave database backed up"

    # Backup shop database (plain SQL, sent as separate file)
    if [ -n "$SHOP_CONTAINER_NAME" ] && [ -n "$SHOP_MYSQL_PASSWORD" ]; then
        databases_shop=$(docker exec "$SHOP_CONTAINER_NAME" mariadb -h 127.0.0.1 --user="$SHOP_MYSQL_USER" --password="$SHOP_MYSQL_PASSWORD" -e "SHOW DATABASES;" 2>/dev/null | tr -d "| " | grep -v Database)
        if [ $? -eq 0 ]; then
            for db in $databases_shop; do
                if [[ "$db" == "shop" ]]; then
                    docker exec "$SHOP_CONTAINER_NAME" mariadb-dump -h 127.0.0.1 --force --opt --user="$SHOP_MYSQL_USER" --password="$SHOP_MYSQL_PASSWORD" --databases "$db" > "$SHOP_SQL_FILE" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        echo -e "${GRAY}  ${ARROW}${NC} Shop database backed up"
                    else
                        echo -e "${GRAY}  ${ARROW}${NC} Failed to backup shop database"
                        rm -f "$SHOP_SQL_FILE"
                    fi
                fi
            done
        else
            echo -e "${GRAY}  ${ARROW}${NC} Could not access shop database"
        fi
    else
        echo -e "${GRAY}  ${ARROW}${NC} Skipping shop database (no container)"
    fi

    echo -e "${GREEN}${CHECK}${NC} Database backup creation completed!"
}

create_archive() {
    echo
    echo -e "${GREEN}Archive Creation${NC}"
    echo -e "${GREEN}================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Building backup archive..."
    echo -e "${GRAY}  ${ARROW}${NC} Archiving /opt/remnawave"

    # Archive /opt/remnawave directory
    tar -czf "$WORK_DIR/remnawave_dir_${TIMESTAMP}.tar.gz" \
        --exclude="*.log" --exclude="*.tmp" --exclude=".git" \
        -C /opt remnawave > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Failed to archive /opt/remnawave"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    echo -e "${GRAY}  ${ARROW}${NC} Packing final archive"

    # Pack dump + dir archive into final backup (compatible with db-migrate.sh)
    tar -czf "$MAIN_BACKUP_FILE" \
        -C "$WORK_DIR" \
        "dump_${TIMESTAMP}.sql.gz" \
        "remnawave_dir_${TIMESTAMP}.tar.gz" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create backup archive"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Backup archive created successfully!"
}

send_file_to_telegram() {
    local file="$1"
    local filename
    filename=$(basename "$file")

    echo -e "${GRAY}  ${ARROW}${NC} ${filename}"
    local response
    response=$(curl -s -F chat_id="$TG_CHAT_ID" \
        -F document=@"$file" \
        "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument")

    if ! echo "$response" | grep -q '"ok":true'; then
        local error_desc
        error_desc=$(echo "$response" | grep -o '"description":"[^"]*"' | cut -d'"' -f4)
        echo -e "${RED}${CROSS}${NC} Failed to send ${filename}"
        [ -n "$error_desc" ] && echo -e "${YELLOW}${WARNING}${NC} Error: ${error_desc}"
    fi
}

send_to_telegram() {
    echo
    echo -e "${GREEN}Telegram Upload${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Sending backups to Telegram..."

    send_file_to_telegram "$MAIN_BACKUP_FILE"

    if [ -f "$SHOP_SQL_FILE" ]; then
        send_file_to_telegram "$SHOP_SQL_FILE"
    fi

    echo -e "${GREEN}${CHECK}${NC} Upload complete!"
}

cleanup_files() {
    echo
    echo -e "${GREEN}Cleanup Process${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Cleaning up temporary files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing temporary directories"
    echo -e "${GRAY}  ${ARROW}${NC} Clearing backup cache"
    echo -e "${GRAY}  ${ARROW}${NC} Finalizing cleanup"

    rm -rf "$TEMP_DIR" > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} Cleanup process completed!"
}

show_completion_summary() {
    echo
    echo -e "${PURPLE}===================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Backup complete!"
    echo -e "${PURPLE}===================${NC}"
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    configure_backup
    validate_configuration
    prepare_system
    check_containers
    create_database_backup
    create_archive
    send_to_telegram
    cleanup_files
    show_completion_summary
    echo
}

# Execute main function
main
