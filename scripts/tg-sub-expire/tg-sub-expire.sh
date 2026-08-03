#!/bin/bash

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

REMNAWAVE_DIR="/opt/remnawave"
SHIM_DIR="${REMNAWAVE_DIR}/tg-sub-expire"
STATE_FILE="${SHIM_DIR}/tg-sub-expire.state"
NGINX_CONF="${REMNAWAVE_DIR}/nginx.conf"
COMPOSE_OVERRIDE="${REMNAWAVE_DIR}/docker-compose.override.yml"
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/supermegaelf/rm-files/main/scripts/tg-sub-expire}"

SUB_PREFIX="sub"

error() {
    echo -e "${RED}${CROSS}${NC} $1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script must be run as root"
    fi
}

check_prerequisites() {
    [ -f "${REMNAWAVE_DIR}/docker-compose.yml" ] || error "Remnawave not found at ${REMNAWAVE_DIR}"
    [ -f "$NGINX_CONF" ] || error "nginx.conf not found at ${NGINX_CONF}"
    command -v docker > /dev/null 2>&1 || error "Docker is not installed"
}

input_service_shortuuid() {
    echo -e "${GRAY}${INFO}${NC} Create the telegram-only user in the panel first, then paste its shortUuid."
    echo
    echo -ne "${CYAN}tg-service shortUuid: ${NC}"
    read -r SERVICE_SHORT_UUID
    while ! [[ "$SERVICE_SHORT_UUID" =~ ^[A-Za-z0-9_-]{4,64}$ ]]; do
        echo -e "${RED}${CROSS}${NC} Invalid shortUuid!"
        echo
        echo -ne "${CYAN}tg-service shortUuid: ${NC}"
        read -r SERVICE_SHORT_UUID
    done
}

input_swap_statuses() {
    echo -ne "${CYAN}Also swap DISABLED users to telegram-only? (y/n): ${NC}"
    read -r ans
    ans=$(printf '%s' "$ans" | tr -cd 'a-zA-Z')
    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
        SWAP_STATUSES="expired,limited,disabled"
    else
        SWAP_STATUSES="expired,limited"
    fi
}

deploy_shim() {
    echo -e "${CYAN}${INFO}${NC} Deploying subscription shim..."

    mkdir -p "$SHIM_DIR"

    echo -e "${GRAY}  ${ARROW}${NC} Fetching router.php"
    if ! curl -fsSL "${RAW_BASE}/router.php" -o "${SHIM_DIR}/router.php"; then
        error "Failed to download router.php from ${RAW_BASE}"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Writing docker-compose.override.yml"
    cat > "$COMPOSE_OVERRIDE" <<EOF
services:
  remnawave-tg-shim:
    image: php:8.3-cli-alpine
    container_name: remnawave-tg-shim
    hostname: remnawave-tg-shim
    restart: always
    environment:
      - PANEL_URL=http://remnawave:3000
      - SUBPAGE_URL=http://remnawave-subscription-page:3010
      - SERVICE_SHORT_UUID=${SERVICE_SHORT_UUID}
      - SWAP_STATUSES=${SWAP_STATUSES}
      - SUB_PREFIX=${SUB_PREFIX}
      - PHP_CLI_SERVER_WORKERS=4
    command: php -S 0.0.0.0:3011 /app/router.php
    working_dir: /app
    volumes:
      - ./tg-sub-expire/router.php:/app/router.php:ro
    ports:
      - '127.0.0.1:3011:3011'
    networks:
      - remnawave-network
    depends_on:
      - remnawave
      - remnawave-subscription-page
    logging:
      driver: json-file
      options:
        max-size: '30m'
        max-file: '5'
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Starting shim container"
    cd "$REMNAWAVE_DIR"
    if ! docker compose up -d remnawave-tg-shim > /tmp/.tgshim.log 2>&1; then
        cat /tmp/.tgshim.log
        error "Failed to start shim container"
    fi

    echo -e "${GREEN}${CHECK}${NC} Shim deployed"
}

patch_nginx() {
    echo -e "${CYAN}${INFO}${NC} Updating nginx..."

    if grep -q "127.0.0.1:3011" "$NGINX_CONF"; then
        echo -e "${GRAY}  ${ARROW}${NC} nginx already points at shim"
    else
        cp "$NGINX_CONF" "${NGINX_CONF}.tg-sub-expire.bak"
        sed -i 's#proxy_pass http://127.0.0.1:3010;#proxy_pass http://127.0.0.1:3011;#g' "$NGINX_CONF"
        echo -e "${GRAY}  ${ARROW}${NC} Backup at ${NGINX_CONF}.tg-sub-expire.bak"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Reloading nginx"
    if docker exec remnawave-nginx nginx -t > /dev/null 2>&1; then
        docker exec remnawave-nginx nginx -s reload > /dev/null 2>&1
    else
        error "nginx config test failed, not reloading"
    fi

    echo -e "${GREEN}${CHECK}${NC} nginx updated"
}

save_state() {
    cat > "$STATE_FILE" <<EOF
SERVICE_SHORT_UUID="${SERVICE_SHORT_UUID}"
SWAP_STATUSES="${SWAP_STATUSES}"
EOF
    chmod 600 "$STATE_FILE"
}

install_tg() {
    echo
    echo -e "${GREEN}Deploying telegram fallback${NC}"
    echo -e "${GREEN}===========================${NC}"
    echo

    deploy_shim
    patch_nginx
    save_state

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Summary:${NC}"
    echo -e "${WHITE}• tg-service shortUuid: ${SERVICE_SHORT_UUID}${NC}"
    echo -e "${WHITE}• Swap statuses: ${SWAP_STATUSES}${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Shim logs: docker logs -f remnawave-tg-shim${NC}"
    echo -e "${WHITE}• Restart shim: docker compose -f ${REMNAWAVE_DIR}/docker-compose.yml up -d remnawave-tg-shim${NC}"
    echo
}

remove_tg() {
    echo
    echo -e "${GREEN}Removing telegram fallback${NC}"
    echo -e "${GREEN}==========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restoring nginx..."
    if [ -f "${NGINX_CONF}.tg-sub-expire.bak" ]; then
        mv "${NGINX_CONF}.tg-sub-expire.bak" "$NGINX_CONF"
    else
        sed -i 's#proxy_pass http://127.0.0.1:3011;#proxy_pass http://127.0.0.1:3010;#g' "$NGINX_CONF"
    fi
    docker exec remnawave-nginx nginx -t > /dev/null 2>&1 && \
        docker exec remnawave-nginx nginx -s reload > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} nginx restored"

    echo
    echo -e "${CYAN}${INFO}${NC} Removing shim container..."
    cd "$REMNAWAVE_DIR"
    docker compose -f docker-compose.yml -f docker-compose.override.yml rm -sf remnawave-tg-shim > /dev/null 2>&1 || true
    rm -f "$COMPOSE_OVERRIDE"
    echo -e "${GREEN}${CHECK}${NC} Shim removed"

    echo
    echo -e "${CYAN}${INFO}${NC} Cleaning up files..."
    rm -f "$STATE_FILE" "${SHIM_DIR}/router.php"
    rmdir "$SHIM_DIR" 2>/dev/null || true
    echo -e "${GREEN}${CHECK}${NC} Files removed"

    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Removal complete"
    echo -e "${PURPLE}==================${NC}"
    echo
}

show_main_menu() {
    SHIM_INSTALLED=false
    [ -f "$COMPOSE_OVERRIDE" ] && SHIM_INSTALLED=true

    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${WHITE}REMNAWAVE TELEGRAM FALLBACK${NC}"
    echo -e "${PURPLE}==========================${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    if [ "$SHIM_INSTALLED" = true ]; then
        echo -e "${RED}1.${NC} Remove telegram fallback"
        echo -e "${YELLOW}2.${NC} Exit"
    else
        echo -e "${GREEN}1.${NC} Setup telegram fallback"
        echo -e "${YELLOW}2.${NC} Exit"
    fi
    echo
    echo -ne "${CYAN}Enter your choice: ${NC}"
}

main() {
    exec < /dev/tty
    check_root
    check_prerequisites

    show_main_menu
    read -r CHOICE

    if [ "$SHIM_INSTALLED" = true ]; then
        case $CHOICE in
            1) remove_tg ;;
            2) echo; echo -e "${YELLOW}${WARNING}${NC} Exiting..."; exit 0 ;;
            *) echo; error "Invalid option. Please enter 1-2." ;;
        esac
    else
        case $CHOICE in
            1)
                echo
                echo -e "${PURPLE}==============${NC}"
                echo -e "${WHITE}Fallback Setup${NC}"
                echo -e "${PURPLE}==============${NC}"
                echo
                input_service_shortuuid
                input_swap_statuses
                install_tg
                ;;
            2) echo; echo -e "${YELLOW}${WARNING}${NC} Exiting..."; exit 0 ;;
            *) echo; error "Invalid option. Please enter 1-2." ;;
        esac
    fi
}

main
