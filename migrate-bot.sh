#!/bin/bash

set -euo pipefail

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

ENV_FILE="/root/shop-bot/.env"
if [ -f "$ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]]; then
            continue
        fi
        if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | sed 's/^["'\'']//; s/["'\'']$//')
            if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                export "$key=$value" 2>/dev/null || true
            fi
        fi
    done < "$ENV_FILE"
fi

show_main_menu() {
    echo
    echo -e "${PURPLE}=================${NC}"
    echo -e "${WHITE}BOT DB MIGRATION${NC}"
    echo -e "${PURPLE}=================${NC}"
    echo
    echo -e "${CYAN}Please select an action:${NC}"
    echo
    echo -e "${GREEN}1.${NC} Export Database"
    echo -e "${GREEN}2.${NC} Import Database"
    echo -e "${RED}3.${NC} Exit"
    echo
    echo -ne "${CYAN}Enter your choice (1, 2, or 3): ${NC}"
}

input_source_db_host() {
    echo -ne "${CYAN}Database host (default: ${DB_ADDRESS:-localhost}, press ENTER to use it): ${NC}"
    read input_host
    SOURCE_DB_HOST="${input_host:-${DB_ADDRESS:-localhost}}"
}

input_source_db_port() {
    echo -ne "${CYAN}Database port (default: ${DB_PORT:-3306}, press ENTER to use it): ${NC}"
    read input_port
    SOURCE_DB_PORT="${input_port:-${DB_PORT:-3306}}"
    if ! [[ "$SOURCE_DB_PORT" =~ ^[0-9]+$ ]] || [ "$SOURCE_DB_PORT" -lt 1 ] || [ "$SOURCE_DB_PORT" -gt 65535 ]; then
        echo -e "${RED}${CROSS}${NC} Invalid port number! Port must be between 1 and 65535."
        return 1
    fi
}

input_source_db_user() {
    echo -ne "${CYAN}Database user (default: ${DB_USER:-}, press ENTER to use it): ${NC}"
    read input_user
    SOURCE_DB_USER="${input_user:-${DB_USER:-}}"
    while [[ -z "$SOURCE_DB_USER" ]]; do
        echo -e "${RED}${CROSS}${NC} Database user cannot be empty!"
        echo -ne "${CYAN}Database user: ${NC}"
        read SOURCE_DB_USER
    done
}

input_source_db_pass() {
    if [ -n "${DB_PASS:-}" ]; then
        echo -ne "${CYAN}Database password (current: ${DB_PASS}, press ENTER to use it): ${NC}"
    else
        echo -ne "${CYAN}Database password: ${NC}"
    fi
    read -r SOURCE_DB_PASS
    if [ -z "$SOURCE_DB_PASS" ] && [ -n "${DB_PASS:-}" ]; then
        SOURCE_DB_PASS="$DB_PASS"
    fi
}

input_source_db_name() {
    echo -ne "${CYAN}Database name (default: ${DB_NAME:-shop}, press ENTER to use it): ${NC}"
    read input_name
    SOURCE_DB_NAME="${input_name:-${DB_NAME:-shop}}"
    while [[ -z "$SOURCE_DB_NAME" ]]; do
        echo -e "${RED}${CROSS}${NC} Database name cannot be empty!"
        echo -ne "${CYAN}Database name: ${NC}"
        read SOURCE_DB_NAME
    done
}

export_database() {
    echo -e "${CYAN}${INFO}${NC} Enter source database connection details:"
    echo
    
    input_source_db_host
    if ! input_source_db_port; then
        return 1
    fi
    input_source_db_user
    input_source_db_pass
    input_source_db_name
    
    OUTPUT_FILE="${OUTPUT_FILE:-/root/shop.sql}"

    echo
    echo -e "${CYAN}${INFO}${NC} Checking database connection..."
    
    USE_DOCKER=false
    DB_CONTAINER=""
    TEST_HOST="$SOURCE_DB_HOST"
    
    if command -v docker >/dev/null 2>&1; then
        DB_CONTAINER=$(docker ps --format "{{.Names}}" | grep -E "shop-bot.*db|shop.*db" | grep -v "beszel" | head -n 1)
        if [ -n "$DB_CONTAINER" ]; then
            if [ "$SOURCE_DB_HOST" = "db" ] || [ "$SOURCE_DB_HOST" = "127.0.0.1" ] || [ "$SOURCE_DB_HOST" = "localhost" ]; then
                TEST_HOST="127.0.0.1"
                echo -e "${GRAY}  ${ARROW}${NC} Found database container: ${WHITE}$DB_CONTAINER${NC}"
                echo -e "${GRAY}  ${ARROW}${NC} Using docker exec for connection"
                USE_DOCKER=true
            fi
        fi
    fi
    
    if [ "$USE_DOCKER" = false ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Testing port connectivity..."
        if ! timeout 3 bash -c "echo > /dev/tcp/$SOURCE_DB_HOST/$SOURCE_DB_PORT" 2>/dev/null; then
            echo -e "${RED}${CROSS}${NC} Cannot connect to ${WHITE}$SOURCE_DB_HOST:$SOURCE_DB_PORT${NC}"
            echo -e "${GRAY}  ${ARROW}${NC} Check if database container is running: ${WHITE}docker ps | grep db${NC}"
            return 1
        fi
        echo -e "${GRAY}  ${ARROW}${NC} Port is accessible"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Testing port connectivity..."
        if ! timeout 3 bash -c "echo > /dev/tcp/$TEST_HOST/$SOURCE_DB_PORT" 2>/dev/null; then
            echo -e "${RED}${CROSS}${NC} Cannot connect to ${WHITE}$TEST_HOST:$SOURCE_DB_PORT${NC}"
            echo -e "${GRAY}  ${ARROW}${NC} Check if database container is running: ${WHITE}docker ps | grep db${NC}"
            return 1
        fi
        echo -e "${GRAY}  ${ARROW}${NC} Port is accessible"
    fi
    
    if [ "$USE_DOCKER" = false ]; then
        MYSQL_CMD="mariadb"
        if ! command -v mariadb >/dev/null 2>&1; then
            MYSQL_CMD="mysql"
            if ! command -v mysql >/dev/null 2>&1; then
                echo -e "${RED}${CROSS}${NC} Neither mariadb nor mysql client is installed"
                echo -e "${GRAY}  ${ARROW}${NC} Install with: ${WHITE}apt-get install mariadb-client${NC}"
                return 1
            fi
        fi
    fi
    
    echo -e "${GRAY}  ${ARROW}${NC} Testing database connection..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$SOURCE_DB_PASS" ]; then
            CONNECTION_OUTPUT=$(timeout 5 docker exec "$DB_CONTAINER" mariadb -u "$SOURCE_DB_USER" -e "SELECT 1" "$SOURCE_DB_NAME" 2>&1)
        else
            export MYSQL_PWD="$SOURCE_DB_PASS"
            CONNECTION_OUTPUT=$(timeout 5 docker exec -e MYSQL_PWD="$SOURCE_DB_PASS" "$DB_CONTAINER" mariadb -u "$SOURCE_DB_USER" -e "SELECT 1" "$SOURCE_DB_NAME" 2>&1)
            unset MYSQL_PWD
        fi
    else
        if [ -z "$SOURCE_DB_PASS" ]; then
            echo -e "${YELLOW}${WARNING}${NC} Password is empty! Trying to connect without password..."
            CONNECTION_OUTPUT=$(timeout 5 $MYSQL_CMD -h "$SOURCE_DB_HOST" -P "$SOURCE_DB_PORT" -u "$SOURCE_DB_USER" --connect-timeout=5 -e "SELECT 1" "$SOURCE_DB_NAME" 2>&1)
        else
            export MYSQL_PWD="$SOURCE_DB_PASS"
            CONNECTION_OUTPUT=$(timeout 5 $MYSQL_CMD -h "$SOURCE_DB_HOST" -P "$SOURCE_DB_PORT" -u "$SOURCE_DB_USER" --connect-timeout=5 -e "SELECT 1" "$SOURCE_DB_NAME" 2>&1)
            unset MYSQL_PWD
        fi
    fi
    CONNECTION_EXIT_CODE=$?
    if [ $CONNECTION_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Database connection error"
        echo -e "${GRAY}  ${ARROW}${NC} Error: ${WHITE}${CONNECTION_OUTPUT}${NC}"
        echo
        echo -e "${CYAN}Troubleshooting:${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Check if database is running: ${WHITE}docker ps | grep db${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Verify credentials in ${WHITE}/root/shop-bot/.env${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Check DB_ADDRESS and DB_PORT values"
        if [ -z "$SOURCE_DB_PASS" ]; then
            echo -e "${YELLOW}${WARNING}${NC} Password (DB_PASS) is empty or not loaded from .env"
            echo -e "${GRAY}  ${ARROW}${NC} Make sure DB_PASS is set in ${WHITE}/root/shop-bot/.env${NC}"
        fi
        return 1
    fi
    echo -e "${GREEN}${CHECK}${NC} Connection successful"
    echo

    MYSQL_CMD="mariadb"
    if ! command -v mariadb >/dev/null 2>&1; then
        MYSQL_CMD="mysql"
    fi
    
    echo -e "${CYAN}${INFO}${NC} Counting users in source database..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$SOURCE_DB_PASS" ]; then
            USER_COUNT=$(timeout 5 docker exec "$DB_CONTAINER" mariadb -u "$SOURCE_DB_USER" -sN -e "SELECT COUNT(*) FROM vpnusers" "$SOURCE_DB_NAME" 2>/dev/null || echo "0")
        else
            USER_COUNT=$(timeout 5 docker exec -e MYSQL_PWD="$SOURCE_DB_PASS" "$DB_CONTAINER" mariadb -u "$SOURCE_DB_USER" -sN -e "SELECT COUNT(*) FROM vpnusers" "$SOURCE_DB_NAME" 2>/dev/null || echo "0")
        fi
    else
        if [ -z "$SOURCE_DB_PASS" ]; then
            USER_COUNT=$(timeout 5 $MYSQL_CMD -h "$SOURCE_DB_HOST" -P "$SOURCE_DB_PORT" -u "$SOURCE_DB_USER" --connect-timeout=5 -sN -e "SELECT COUNT(*) FROM vpnusers" "$SOURCE_DB_NAME" 2>/dev/null || echo "0")
        else
            export MYSQL_PWD="$SOURCE_DB_PASS"
            USER_COUNT=$(timeout 5 $MYSQL_CMD -h "$SOURCE_DB_HOST" -P "$SOURCE_DB_PORT" -u "$SOURCE_DB_USER" --connect-timeout=5 -sN -e "SELECT COUNT(*) FROM vpnusers" "$SOURCE_DB_NAME" 2>/dev/null || echo "0")
            unset MYSQL_PWD
        fi
    fi
    if [ -z "$USER_COUNT" ] || [ "$USER_COUNT" = "" ]; then
        USER_COUNT="0"
    fi
    echo -e "${GRAY}  ${ARROW}${NC} Found ${WHITE}$USER_COUNT${NC} users in database"
    echo -e "${GREEN}${CHECK}${NC} Counting completed"
    echo
    echo -e "${CYAN}${INFO}${NC} Creating database dump..."
    echo -e "${GRAY}  ${ARROW}${NC} Exporting data..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$SOURCE_DB_PASS" ]; then
            docker exec "$DB_CONTAINER" mariadb-dump \
                -u "$SOURCE_DB_USER" \
                --single-transaction \
                --routines \
                --triggers \
                --events \
                --add-drop-table \
                "$SOURCE_DB_NAME" > "$OUTPUT_FILE"
        else
            docker exec -e MYSQL_PWD="$SOURCE_DB_PASS" "$DB_CONTAINER" mariadb-dump \
                -u "$SOURCE_DB_USER" \
                --single-transaction \
                --routines \
                --triggers \
                --events \
                --add-drop-table \
                "$SOURCE_DB_NAME" > "$OUTPUT_FILE"
        fi
    else
        DUMP_CMD="mariadb-dump"
        if ! command -v mariadb-dump >/dev/null 2>&1; then
            DUMP_CMD="mysqldump"
            if ! command -v mysqldump >/dev/null 2>&1; then
                echo -e "${RED}${CROSS}${NC} Neither mariadb-dump nor mysqldump is installed"
                echo -e "${GRAY}  ${ARROW}${NC} Install with: ${WHITE}apt-get install mariadb-client${NC}"
                return 1
            fi
        fi
        
        if [ -z "$SOURCE_DB_PASS" ]; then
            $DUMP_CMD \
                -h "$SOURCE_DB_HOST" \
                -P "$SOURCE_DB_PORT" \
                -u "$SOURCE_DB_USER" \
                --single-transaction \
                --routines \
                --triggers \
                --events \
                --add-drop-table \
                "$SOURCE_DB_NAME" > "$OUTPUT_FILE"
        else
            export MYSQL_PWD="$SOURCE_DB_PASS"
            $DUMP_CMD \
                -h "$SOURCE_DB_HOST" \
                -P "$SOURCE_DB_PORT" \
                -u "$SOURCE_DB_USER" \
                --single-transaction \
                --routines \
                --triggers \
                --events \
                --add-drop-table \
                "$SOURCE_DB_NAME" > "$OUTPUT_FILE"
            unset MYSQL_PWD
        fi
    fi

    DUMP_EXIT_CODE=$?
    if [ $DUMP_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Error creating dump"
        rm -f "$OUTPUT_FILE"
        return 1
    fi

    DUMP_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    DUMP_LINES=$(wc -l < "$OUTPUT_FILE")
    echo -e "${GREEN}${CHECK}${NC} Export completed"
    echo
    echo -e "${PURPLE}============================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Dump created successfully"
    echo -e "${PURPLE}============================${NC}"
    echo
    echo -e "${CYAN}Dump Information:${NC}"
    echo
    echo -e "${GRAY}•${NC} File: ${WHITE}$OUTPUT_FILE${NC}"
    echo -e "${GRAY}•${NC} Size: ${WHITE}$DUMP_SIZE${NC}"
    echo -e "${GRAY}•${NC} Lines: ${WHITE}$DUMP_LINES${NC}"
    echo -e "${GRAY}•${NC} Users exported: ${WHITE}$USER_COUNT${NC}"
    echo
    echo -e "${CYAN}Next Steps:${NC}"
    echo
    echo -e "${GRAY}1.${NC} Transfer file ${WHITE}$OUTPUT_FILE${NC} to Remnawave server."
    echo -e "${GRAY}2.${NC} Run ${WHITE}migrate_bot.sh${NC} and select option 2."
    echo
}

input_target_db_host() {
    echo -ne "${CYAN}Database host (default: ${DB_ADDRESS:-localhost}): ${NC}"
    read input_host
    TARGET_DB_HOST="${input_host:-${DB_ADDRESS:-localhost}}"
}

input_target_db_port() {
    echo -ne "${CYAN}Database port (default: ${DB_PORT:-3306}): ${NC}"
    read input_port
    TARGET_DB_PORT="${input_port:-${DB_PORT:-3306}}"
    if ! [[ "$TARGET_DB_PORT" =~ ^[0-9]+$ ]] || [ "$TARGET_DB_PORT" -lt 1 ] || [ "$TARGET_DB_PORT" -gt 65535 ]; then
        echo -e "${RED}${CROSS}${NC} Invalid port number! Port must be between 1 and 65535."
        return 1
    fi
}

input_target_db_user() {
    echo -ne "${CYAN}Database user (default: ${DB_USER:-}): ${NC}"
    read input_user
    TARGET_DB_USER="${input_user:-${DB_USER:-}}"
    while [[ -z "$TARGET_DB_USER" ]]; do
        echo -e "${RED}${CROSS}${NC} Database user cannot be empty!"
        echo -ne "${CYAN}Database user: ${NC}"
        read TARGET_DB_USER
    done
}

input_target_db_pass() {
    if [ -n "${DB_PASS:-}" ]; then
        echo -ne "${CYAN}Database password (current: ${DB_PASS}): ${NC}"
    else
        echo -ne "${CYAN}Database password: ${NC}"
    fi
    read -r TARGET_DB_PASS
    if [ -z "$TARGET_DB_PASS" ] && [ -n "${DB_PASS:-}" ]; then
        TARGET_DB_PASS="$DB_PASS"
    fi
}

input_target_db_name() {
    echo -ne "${CYAN}Database name (default: ${DB_NAME:-shop}): ${NC}"
    read input_name
    TARGET_DB_NAME="${input_name:-${DB_NAME:-shop}}"
    while [[ -z "$TARGET_DB_NAME" ]]; do
        echo -e "${RED}${CROSS}${NC} Database name cannot be empty!"
        echo -ne "${CYAN}Database name: ${NC}"
        read TARGET_DB_NAME
    done
}

input_dump_file() {
    echo -ne "${CYAN}Dump file path (default: /root/shop.sql): ${NC}"
    read input_file
    INPUT_FILE="${input_file:-/root/shop.sql}"
    while [[ -z "$INPUT_FILE" ]]; do
        echo -e "${RED}${CROSS}${NC} Dump file path cannot be empty!"
        echo -ne "${CYAN}Dump file path: ${NC}"
        read INPUT_FILE
    done
    if [ ! -f "$INPUT_FILE" ]; then
        echo -e "${RED}${CROSS}${NC} Dump file not found: ${WHITE}$INPUT_FILE${NC}"
        return 1
    fi
    return 0
}

import_database() {
    echo -e "${CYAN}${INFO}${NC} Enter target database connection details:"
    echo
    
    input_target_db_host
    if ! input_target_db_port; then
        return 1
    fi
    input_target_db_user
    input_target_db_pass
    input_target_db_name
    
    INPUT_FILE="/root/shop.sql"
    
    if [ ! -f "$INPUT_FILE" ]; then
        echo -e "${RED}${CROSS}${NC} Dump file not found: ${WHITE}$INPUT_FILE${NC}"
        return 1
    fi

    DUMP_SIZE=$(du -h "$INPUT_FILE" | cut -f1)
    DUMP_LINES=$(wc -l < "$INPUT_FILE")

    echo
    echo -e "${CYAN}${INFO}${NC} Checking database connection..."
    
    USE_DOCKER=false
    DB_CONTAINER=""
    TEST_HOST="$TARGET_DB_HOST"
    
    if command -v docker >/dev/null 2>&1; then
        DB_CONTAINER=$(docker ps --format "{{.Names}}" | grep -E "shop-bot.*db|shop.*db" | grep -v "beszel" | head -n 1)
        if [ -n "$DB_CONTAINER" ]; then
            if [ "$TARGET_DB_HOST" = "db" ] || [ "$TARGET_DB_HOST" = "127.0.0.1" ] || [ "$TARGET_DB_HOST" = "localhost" ]; then
                TEST_HOST="127.0.0.1"
                echo -e "${GRAY}  ${ARROW}${NC} Found database container: ${WHITE}$DB_CONTAINER${NC}"
                echo -e "${GRAY}  ${ARROW}${NC} Using docker exec for connection"
                USE_DOCKER=true
            fi
        fi
    fi
    
    if [ "$USE_DOCKER" = false ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Testing port connectivity..."
        if ! timeout 3 bash -c "echo > /dev/tcp/$TARGET_DB_HOST/$TARGET_DB_PORT" 2>/dev/null; then
            echo -e "${RED}${CROSS}${NC} Cannot connect to ${WHITE}$TARGET_DB_HOST:$TARGET_DB_PORT${NC}"
            echo -e "${GRAY}  ${ARROW}${NC} Check if database container is running: ${WHITE}docker ps | grep db${NC}"
            return 1
        fi
        echo -e "${GRAY}  ${ARROW}${NC} Port is accessible"
    else
        echo -e "${GRAY}  ${ARROW}${NC} Testing port connectivity..."
        if ! timeout 3 bash -c "echo > /dev/tcp/$TEST_HOST/$TARGET_DB_PORT" 2>/dev/null; then
            echo -e "${RED}${CROSS}${NC} Cannot connect to ${WHITE}$TEST_HOST:$TARGET_DB_PORT${NC}"
            echo -e "${GRAY}  ${ARROW}${NC} Check if database container is running: ${WHITE}docker ps | grep db${NC}"
            return 1
        fi
        echo -e "${GRAY}  ${ARROW}${NC} Port is accessible"
    fi
    
    if [ "$USE_DOCKER" = false ]; then
        MYSQL_CMD="mariadb"
        if ! command -v mariadb >/dev/null 2>&1; then
            MYSQL_CMD="mysql"
            if ! command -v mysql >/dev/null 2>&1; then
                echo -e "${RED}${CROSS}${NC} Neither mariadb nor mysql client is installed"
                echo -e "${GRAY}  ${ARROW}${NC} Install with: ${WHITE}apt-get install mariadb-client${NC}"
                return 1
            fi
        fi
    fi
    
    echo -e "${GRAY}  ${ARROW}${NC} Testing database connection..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$TARGET_DB_PASS" ]; then
            CONNECTION_OUTPUT=$(timeout 5 docker exec "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" -e "SELECT 1" "$TARGET_DB_NAME" 2>&1)
        else
            CONNECTION_OUTPUT=$(timeout 5 docker exec -e MYSQL_PWD="$TARGET_DB_PASS" "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" -e "SELECT 1" "$TARGET_DB_NAME" 2>&1)
        fi
    else
        if [ -z "$TARGET_DB_PASS" ]; then
            echo -e "${YELLOW}${WARNING}${NC} Password is empty! Trying to connect without password..."
            CONNECTION_OUTPUT=$(timeout 5 $MYSQL_CMD -h "$TARGET_DB_HOST" -P "$TARGET_DB_PORT" -u "$TARGET_DB_USER" --connect-timeout=5 -e "SELECT 1" "$TARGET_DB_NAME" 2>&1)
        else
            export MYSQL_PWD="$TARGET_DB_PASS"
            CONNECTION_OUTPUT=$(timeout 5 $MYSQL_CMD -h "$TARGET_DB_HOST" -P "$TARGET_DB_PORT" -u "$TARGET_DB_USER" --connect-timeout=5 -e "SELECT 1" "$TARGET_DB_NAME" 2>&1)
            unset MYSQL_PWD
        fi
    fi
    CONNECTION_EXIT_CODE=$?
    if [ $CONNECTION_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Database connection error"
        echo -e "${GRAY}  ${ARROW}${NC} Error: ${WHITE}${CONNECTION_OUTPUT}${NC}"
        echo
        echo -e "${CYAN}Troubleshooting:${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Make sure the target database exists"
        echo -e "${GRAY}  ${ARROW}${NC} Check if database is running: ${WHITE}docker ps | grep db${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Verify credentials in ${WHITE}/root/shop-bot/.env${NC}"
        echo -e "${GRAY}  ${ARROW}${NC} Check DB_ADDRESS and DB_PORT values"
        if [ -z "$TARGET_DB_PASS" ]; then
            echo -e "${YELLOW}${WARNING}${NC} Password (DB_PASS) is empty or not loaded from .env"
            echo -e "${GRAY}  ${ARROW}${NC} Make sure DB_PASS is set in ${WHITE}/root/shop-bot/.env${NC}"
        fi
        return 1
    fi
    echo -e "${GREEN}${CHECK}${NC} Connection successful"
    echo

    echo -e "${CYAN}${INFO}${NC} Importing data into database..."
    echo -e "${GRAY}  ${ARROW}${NC} Importing data..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$TARGET_DB_PASS" ]; then
            docker exec -i "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" "$TARGET_DB_NAME" < "$INPUT_FILE"
        else
            docker exec -i -e MYSQL_PWD="$TARGET_DB_PASS" "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" "$TARGET_DB_NAME" < "$INPUT_FILE"
        fi
    else
        MYSQL_CMD="mariadb"
        if ! command -v mariadb >/dev/null 2>&1; then
            MYSQL_CMD="mysql"
        fi
        
        if [ -z "$TARGET_DB_PASS" ]; then
            $MYSQL_CMD \
                -h "$TARGET_DB_HOST" \
                -P "$TARGET_DB_PORT" \
                -u "$TARGET_DB_USER" \
                "$TARGET_DB_NAME" < "$INPUT_FILE"
        else
            export MYSQL_PWD="$TARGET_DB_PASS"
            $MYSQL_CMD \
                -h "$TARGET_DB_HOST" \
                -P "$TARGET_DB_PORT" \
                -u "$TARGET_DB_USER" \
                "$TARGET_DB_NAME" < "$INPUT_FILE"
            unset MYSQL_PWD
        fi
    fi

    IMPORT_EXIT_CODE=$?
    if [ $IMPORT_EXIT_CODE -ne 0 ]; then
        echo -e "${RED}${CROSS}${NC} Error importing data"
        return 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Import completed"
    echo
    echo -e "${CYAN}${INFO}${NC} Counting imported users..."
    if [ "$USE_DOCKER" = true ]; then
        if [ -z "$TARGET_DB_PASS" ]; then
            IMPORTED_COUNT=$(timeout 5 docker exec "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" -sN -e "SELECT COUNT(*) FROM vpnusers" "$TARGET_DB_NAME" 2>/dev/null || echo "0")
        else
            IMPORTED_COUNT=$(timeout 5 docker exec -e MYSQL_PWD="$TARGET_DB_PASS" "$DB_CONTAINER" mariadb -u "$TARGET_DB_USER" -sN -e "SELECT COUNT(*) FROM vpnusers" "$TARGET_DB_NAME" 2>/dev/null || echo "0")
        fi
    else
        MYSQL_CMD="mariadb"
        if ! command -v mariadb >/dev/null 2>&1; then
            MYSQL_CMD="mysql"
        fi
        
        if [ -z "$TARGET_DB_PASS" ]; then
            IMPORTED_COUNT=$(timeout 5 $MYSQL_CMD -h "$TARGET_DB_HOST" -P "$TARGET_DB_PORT" -u "$TARGET_DB_USER" --connect-timeout=5 -sN -e "SELECT COUNT(*) FROM vpnusers" "$TARGET_DB_NAME" 2>/dev/null || echo "0")
        else
            export MYSQL_PWD="$TARGET_DB_PASS"
            IMPORTED_COUNT=$(timeout 5 $MYSQL_CMD -h "$TARGET_DB_HOST" -P "$TARGET_DB_PORT" -u "$TARGET_DB_USER" --connect-timeout=5 -sN -e "SELECT COUNT(*) FROM vpnusers" "$TARGET_DB_NAME" 2>/dev/null || echo "0")
            unset MYSQL_PWD
        fi
    fi
    if [ -z "$IMPORTED_COUNT" ] || [ "$IMPORTED_COUNT" = "" ]; then
        IMPORTED_COUNT="0"
    fi
    echo -e "${GRAY}  ${ARROW}${NC} Users imported: ${WHITE}$IMPORTED_COUNT${NC}"
    echo -e "${GREEN}${CHECK}${NC} Counting completed"
    echo
    echo -e "${PURPLE}================================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Import completed successfully"
    echo -e "${PURPLE}================================${NC}"
    echo
    echo -e "${CYAN}Next Steps:${NC}"
    echo
    echo -e "${GRAY}1.${NC} If needed, run vpn_id synchronization: ${WHITE}python bot/migration/sync_vpn_ids.py${NC}"
    echo -e "${GRAY}2.${NC} Restart the bot: ${WHITE}cd /root/shop-bot && docker compose restart${NC}"
    echo
}

main() {
    show_main_menu
    read CHOICE
    
    case $CHOICE in
        1)
            echo
            echo -e "${PURPLE}================${NC}"
            echo -e "${WHITE}Export Database${NC}"
            echo -e "${PURPLE}================${NC}"
            echo
            export_database
            ;;
        2)
            echo
            echo -e "${PURPLE}================${NC}"
            echo -e "${WHITE}Import Database${NC}"
            echo -e "${PURPLE}================${NC}"
            echo
            import_database
            ;;
        3)
            echo
            echo -e "${YELLOW}${WARNING}${NC} Exiting..."
            exit 0
            ;;
        *)
            echo
            echo -e "${RED}${CROSS}${NC} Invalid choice. Please select 1, 2, or 3."
            exit 1
            ;;
    esac
}

main
exit 0
