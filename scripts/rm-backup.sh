#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"
POSTGRES_DB="postgres"
TG_BOT_TOKEN=""
TG_CHAT_ID=""

echo
echo -e "${PURPLE}=================${NC}"
echo -e "${NC}REMNAWAVE BACKUP${NC}"
echo -e "${PURPLE}=================${NC}"
echo

if [ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ]; then
    echo -e "${CYAN}Please enter the required information:${NC}"
    echo
    
    read -p "$(echo "PostgreSQL username: ")" POSTGRES_USER
    read -p "$(echo "PostgreSQL password: ")" POSTGRES_PASSWORD
    read -p "$(echo "PostgreSQL database (default is remnawave, press Enter to use it): ")" POSTGRES_DB_INPUT
    POSTGRES_DB=${POSTGRES_DB_INPUT:-remnawave}
    read -p "$(echo "Telegram Bot Token: ")" TG_BOT_TOKEN
    read -p "$(echo "Telegram Chat ID: ")" TG_CHAT_ID

    if [[ ! "$TG_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        echo -e "${RED}Error: Invalid Telegram Bot Token format${NC}"
        exit 1
    fi
    if [[ ! "$TG_CHAT_ID" =~ ^-?[0-9]+$ ]]; then
        echo -e "${RED}Error: Invalid Telegram Chat ID format${NC}"
        exit 1
    fi

    sed -i "s/TG_BOT_TOKEN=\"\"/TG_BOT_TOKEN=\"$TG_BOT_TOKEN\"/" "$0"
    sed -i "s/TG_CHAT_ID=\"\"/TG_CHAT_ID=\"$TG_CHAT_ID\"/" "$0"

    if ! grep -q "/root/scripts/rm-backup.sh" /etc/crontab; then
        echo "0 */1 * * * root /bin/bash /root/scripts/rm-backup.sh >/dev/null 2>&1" | tee -a /etc/crontab
    fi
    
    echo
    echo -e "${GREEN}✓${NC} Configuration saved successfully!"
    echo
fi

if [[ ! "$TG_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
    echo -e "${RED}Error: Invalid Telegram Bot Token format${NC}"
    exit 1
fi

if [[ ! "$TG_CHAT_ID" =~ ^-?[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid Telegram Chat ID format${NC}"
    exit 1
fi

echo -e "${GREEN}======================${NC}"
echo -e "${NC}1. System preparation${NC}"
echo -e "${GREEN}======================${NC}"
echo

TEMP_DIR=$(mktemp -d)
if [ ! -d "$TEMP_DIR" ]; then
    echo -e "${RED}Error: Failed to create temporary directory${NC}"
    exit 1
fi
BACKUP_FILE="$TEMP_DIR/rm-backup-$(date +%d.%m.%Y_%H.%M).tar.gz"

echo -e "${GREEN}✓${NC} Temporary directory created: $TEMP_DIR"

echo
echo -e "${GREEN}--------------------------------${NC}"
echo -e "${GREEN}✓${NC} System preparation completed!"
echo -e "${GREEN}--------------------------------${NC}"
echo

echo -e "${GREEN}=============================${NC}"
echo -e "${NC}2. Checking Docker container${NC}"
echo -e "${GREEN}=============================${NC}"
echo

POSTGRES_CONTAINER_NAME="remnawave-db"
if ! docker ps -q -f name="$POSTGRES_CONTAINER_NAME" | grep -q .; then
    echo -e "${RED}Error: Container $POSTGRES_CONTAINER_NAME is not running${NC}"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo -e "${GREEN}✓${NC} Container $POSTGRES_CONTAINER_NAME is running"

echo
echo -e "${GREEN}------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Docker container check completed!"
echo -e "${GREEN}------------------------------------${NC}"
echo

echo -e "${GREEN}============================${NC}"
echo -e "${NC}3. Creating database backup${NC}"
echo -e "${GREEN}============================${NC}"
echo

# Create database backup directory
mkdir -p /opt/remnawave/db-backup/
echo -e "${GREEN}✓${NC} Database backup directory created"

# Create PostgreSQL database backup
echo "Creating PostgreSQL database backup..."
docker exec $POSTGRES_CONTAINER_NAME pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /opt/remnawave/db-backup/remnawave.sql 2>/tmp/remnawave_error.log
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to create database backup${NC}"
    cat /tmp/remnawave_error.log
    rm -rf "$TEMP_DIR" /tmp/remnawave_error.log
    exit 1
fi
rm -f /tmp/remnawave_error.log

echo -e "${GREEN}✓${NC} PostgreSQL database backup created"

echo
echo -e "${GREEN}--------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Database backup creation completed!"
echo -e "${GREEN}--------------------------------------${NC}"
echo

echo -e "${GREEN}===========================${NC}"
echo -e "${NC}4. Creating backup archive${NC}"
echo -e "${GREEN}===========================${NC}"
echo

# Create compressed backup archive
echo "Creating backup archive..."
tar --exclude='/opt/remnawave/db-backup' \
    -cf "$TEMP_DIR/backup-remnawave.tar" \
    -C / \
    /opt/remnawave/.env \
    /opt/remnawave/docker-compose.yml \
    /opt/remnawave/nginx.conf \
    /opt/remnawave/remnawave-vars.sh \
    /etc/letsencrypt/live/ \
    /etc/letsencrypt/renewal/

echo -e "${GREEN}✓${NC} Configuration files archived"

# Add database backup to archive
tar -rf "$TEMP_DIR/backup-remnawave.tar" -C / /opt/remnawave/db-backup/remnawave.sql
echo -e "${GREEN}✓${NC} Database backup added to archive"

# Compress the archive
gzip "$TEMP_DIR/backup-remnawave.tar"
mv "$TEMP_DIR/backup-remnawave.tar.gz" "$BACKUP_FILE"
echo -e "${GREEN}✓${NC} Archive compressed successfully"

echo
echo -e "${GREEN}-------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Backup archive creation completed!"
echo -e "${GREEN}-------------------------------------${NC}"
echo

echo -e "${GREEN}=======================${NC}"
echo -e "${NC}5. Sending to Telegram${NC}"
echo -e "${GREEN}=======================${NC}"
echo

# Send to Telegram
echo "Sending backup to Telegram..."
curl -F chat_id="$TG_CHAT_ID" \
     -F document=@"$BACKUP_FILE" \
     https://api.telegram.org/bot$TG_BOT_TOKEN/sendDocument

# Check if upload was successful
if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}✓${NC} Backup successfully sent to Telegram"
    # Clean up database backup directory
    rm -rf /opt/remnawave/db-backup/remnawave.sql
    echo -e "${GREEN}✓${NC} Database backup file cleaned up"
else
    echo
    echo -e "${RED}✗${NC} Failed to send backup to Telegram"
fi

echo
echo -e "${GREEN}-----------------------------${NC}"
echo -e "${GREEN}✓${NC} Telegram upload completed!"
echo -e "${GREEN}-----------------------------${NC}"
echo

echo -e "${GREEN}===================${NC}"
echo -e "${NC}6. Cleanup process${NC}"
echo -e "${GREEN}===================${NC}"
echo

# Clean up temporary files
rm -rf "$TEMP_DIR"
echo -e "${GREEN}✓${NC} Temporary files cleaned up"

echo
echo -e "${GREEN}-----------------------------${NC}"
echo -e "${GREEN}✓${NC} Cleanup process completed!"
echo -e "${GREEN}-----------------------------${NC}"
echo

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}✓${NC} Backup process completed successfully!"
echo -e "${GREEN}=========================================${NC}"
echo
echo -e "${CYAN}Backup Information:${NC}"
echo -e "Archive name: ${WHITE}rm-backup-$(date +%d.%m.%Y_%H.%M).tar.gz${NC}"
echo -e "Database: ${WHITE}$POSTGRES_DB${NC}"
echo -e "Telegram Chat ID: ${WHITE}$TG_CHAT_ID${NC}"
