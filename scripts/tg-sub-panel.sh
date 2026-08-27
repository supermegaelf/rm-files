#!/bin/bash

#==============
# TG-SUB PANEL
#==============

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

SUB_PREFIX="sub"
SWAP_STATUSES="expired,limited"

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
    echo -ne "${CYAN}TG service shortUuid: ${NC}"
    read -r SERVICE_SHORT_UUID
    while ! [[ "$SERVICE_SHORT_UUID" =~ ^[A-Za-z0-9_-]{4,64}$ ]]; do
        echo -e "${RED}${CROSS}${NC} Invalid shortUuid!"
        echo
        echo -ne "${CYAN}TG service shortUuid: ${NC}"
        read -r SERVICE_SHORT_UUID
    done
}

input_grace_days() {
    echo -ne "${CYAN}Grace days (default 1, 0 = unlimited): ${NC}"
    read -r GRACE_DAYS
    GRACE_DAYS="${GRACE_DAYS:-1}"
    while ! [[ "$GRACE_DAYS" =~ ^[0-9]+$ ]]; do
        echo -e "${RED}${CROSS}${NC} Enter a whole number (0 or more)!"
        echo
        echo -ne "${CYAN}Grace days (default 1, 0 = unlimited): ${NC}"
        read -r GRACE_DAYS
        GRACE_DAYS="${GRACE_DAYS:-1}"
    done
}

input_panel_domain() {
    echo -ne "${CYAN}Panel domain (e.g., panel.example.com): ${NC}"
    read -r PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]] || [[ "$PANEL_DOMAIN" =~ [[:space:]] ]] || ! [[ "$PANEL_DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
        echo -e "${RED}${CROSS}${NC} Invalid domain!"
        echo
        echo -ne "${CYAN}Panel domain (e.g., panel.example.com): ${NC}"
        read -r PANEL_DOMAIN
    done
    PANEL_URL="https://${PANEL_DOMAIN}"
}

load_panel_vars() {
    local vars="${REMNAWAVE_DIR}/remnawave-vars.sh"
    if [ -f "$vars" ]; then
        source "$vars"
    fi
    if [ -n "$PANEL_DOMAIN" ]; then
        PANEL_URL="https://${PANEL_DOMAIN}"
    else
        input_panel_domain
    fi
}

deploy_shim() {
    echo -e "${CYAN}${INFO}${NC} Deploying subscription shim..."

    mkdir -p "$SHIM_DIR"

    echo -e "${GRAY}  ${ARROW}${NC} Writing router.php"
    cat > "${SHIM_DIR}/router.php" <<'PHP_EOF'
<?php
declare(strict_types=1);

$PANEL   = rtrim((string) (getenv('PANEL_URL')   ?: 'http://remnawave:3000'), '/');
$SUBPAGE = rtrim((string) (getenv('SUBPAGE_URL') ?: 'http://remnawave-subscription-page:3010'), '/');
$SERVICE = trim((string) getenv('SERVICE_SHORT_UUID'));
$SWAP    = array_values(array_filter(array_map('trim',
    explode(',', strtolower((string) (getenv('SWAP_STATUSES') ?: 'expired,limited'))))));
$PREFIX  = trim((string) (getenv('SUB_PREFIX') ?: 'sub'), '/');
$GRACE   = (int) (getenv('GRACE_DAYS') ?: 0);
$GRACE_ANNOUNCE = trim((string) @file_get_contents('/app/grace-announce.txt'));

$method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri      = $_SERVER['REQUEST_URI'] ?? '/';
$path     = parse_url($uri, PHP_URL_PATH) ?: '/';
$query    = parse_url($uri, PHP_URL_QUERY);
$qs       = $query ? ('?' . $query) : '';

$host     = $_SERVER['HTTP_HOST'] ?? '';
$ua       = $_SERVER['HTTP_USER_AGENT'] ?? '';
$accept   = $_SERVER['HTTP_ACCEPT'] ?? '';
$lang     = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');

function fwdHeaders(): array
{
    global $host, $ua, $accept, $lang, $clientIp;
    $h = [];
    if ($host)     $h[] = 'Host: ' . $host;
    if ($ua)       $h[] = 'User-Agent: ' . $ua;
    if ($accept)   $h[] = 'Accept: ' . $accept;
    if ($lang)     $h[] = 'Accept-Language: ' . $lang;
    if ($clientIp) {
        $h[] = 'X-Forwarded-For: ' . $clientIp;
        $h[] = 'X-Real-IP: ' . $clientIp;
    }
    $h[] = 'X-Forwarded-Proto: https';
    return $h;
}

function httpReq(string $method, string $url, array $headers, ?string $body = null): array
{
    $opts = ['http' => [
        'method'          => $method,
        'header'          => implode("\r\n", $headers),
        'ignore_errors'   => true,
        'timeout'         => 15,
        'follow_location' => 0,
    ], 'ssl' => [
        'verify_peer'      => false,
        'verify_peer_name' => false,
    ]];
    if ($body !== null) {
        $opts['http']['content'] = $body;
    }
    $out = @file_get_contents($url, false, stream_context_create($opts));

    $code        = 0;
    $respHeaders = [];
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $mm)) {
            $code        = (int) $mm[1];
            $respHeaders = [];
            continue;
        }
        $p = explode(':', $line, 2);
        if (count($p) === 2) {
            $respHeaders[strtolower(trim($p[0]))] = trim($p[1]);
        }
    }

    return ['code' => $code, 'headers' => $respHeaders, 'body' => $out === false ? '' : $out];
}

function emitHeaders(array $headers): void
{
    $drop = ['transfer-encoding', 'connection', 'content-length', 'content-encoding'];
    foreach ($headers as $k => $v) {
        if (in_array($k, $drop, true)) {
            continue;
        }
        header($k . ': ' . $v);
    }
}

function passthrough(): void
{
    global $SUBPAGE, $uri, $method;
    $reqBody = ($method === 'GET' || $method === 'HEAD') ? null : file_get_contents('php://input');
    $r = httpReq($method, $SUBPAGE . $uri, fwdHeaders(), $reqBody);
    http_response_code($r['code'] ?: 502);
    emitHeaders($r['headers']);
    echo $r['body'];
}

if (!preg_match('#^/' . preg_quote($PREFIX, '#') . '/([A-Za-z0-9_-]{4,64})#', $path, $m)) {
    passthrough();
    exit;
}
$shortUuid = $m[1];

if ($SERVICE === '') {
    passthrough();
    exit;
}

if (stripos($accept, 'text/html') !== false) {
    passthrough();
    exit;
}

$infoHeaders = ['Accept: application/json', 'X-Forwarded-For: ' . $clientIp];
$info   = httpReq('GET', $PANEL . '/api/sub/' . rawurlencode($shortUuid) . '/info', $infoHeaders);
$status    = 'active';
$expiresAt = '';
if ($info['code'] === 200) {
    $data      = json_decode($info['body'], true);
    $status    = strtolower((string) ($data['response']['user']['userStatus'] ?? 'active'));
    $expiresAt = (string) ($data['response']['user']['expiresAt'] ?? '');
}

if (!in_array($status, $SWAP, true)) {
    passthrough();
    exit;
}

// Grace period: give telegram-only access for GRACE_DAYS after expiry, then stop.
if ($GRACE > 0 && $expiresAt !== '') {
    $expTs = strtotime($expiresAt);
    if ($expTs !== false && time() > $expTs + $GRACE * 86400) {
        passthrough();
        exit;
    }
}

$rest = substr($path, strlen('/' . $PREFIX . '/' . $shortUuid));
$orig = httpReq('GET', $SUBPAGE . '/' . $PREFIX . '/' . rawurlencode($shortUuid) . $rest . $qs, fwdHeaders());
$svc  = httpReq('GET', $SUBPAGE . '/' . $PREFIX . '/' . rawurlencode($SERVICE)   . $rest . $qs, fwdHeaders());

if ($svc['code'] !== 200 || $svc['body'] === '') {
    passthrough();
    exit;
}

http_response_code(200);
header('Cache-Control: no-store');

$keep = [
    'subscription-userinfo', 'profile-title', 'profile-update-interval', 'support-url',
    'content-disposition', 'profile-web-page-url', 'subscription-refill-date',
];
foreach ($keep as $k) {
    if (isset($orig['headers'][$k])) {
        header($k . ': ' . $orig['headers'][$k]);
    }
}
if ($status === 'expired' && $GRACE_ANNOUNCE !== '') {
    header('announce: base64:' . base64_encode($GRACE_ANNOUNCE));
} elseif (isset($orig['headers']['announce'])) {
    header('announce: ' . $orig['headers']['announce']);
}
header('Content-Type: ' . ($svc['headers']['content-type'] ?? 'text/plain; charset=utf-8'));
echo $svc['body'];
PHP_EOF

    echo -e "${GRAY}  ${ARROW}${NC} Writing docker-compose.override.yml"
    cat > "$COMPOSE_OVERRIDE" <<EOF
services:
  remnawave-tg-shim:
    image: php:8.3-cli-alpine
    container_name: remnawave-tg-shim
    hostname: remnawave-tg-shim
    restart: always
    environment:
      - PANEL_URL=${PANEL_URL}
      - SUBPAGE_URL=http://remnawave-subscription-page:3010
      - SERVICE_SHORT_UUID=${SERVICE_SHORT_UUID}
      - SWAP_STATUSES=${SWAP_STATUSES}
      - GRACE_DAYS=${GRACE_DAYS}
      - SUB_PREFIX=${SUB_PREFIX}
      - PHP_CLI_SERVER_WORKERS=4
    command: php -S 0.0.0.0:3011 /app/router.php
    working_dir: /app
    volumes:
      - ./tg-sub-expire/router.php:/app/router.php:ro
      - ./tg-sub-expire/grace-announce.txt:/app/grace-announce.txt:ro
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

    if [ ! -f "${SHIM_DIR}/grace-announce.txt" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Writing grace-announce.txt"
        cat > "${SHIM_DIR}/grace-announce.txt" <<'GRACE_EOF'
⚠️ Подписка истекла ⏳
1. Выключите VPN ➔ нажмите 🔄 ➔ включите VPN
2. Откройте Telegram ➔ @surf_v_bot ➔ Подписка ⭐️ ➔ Продлить 💳
GRACE_EOF
    fi

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
        sed 's#proxy_pass http://127.0.0.1:3010;#proxy_pass http://127.0.0.1:3011;#g' "$NGINX_CONF" > "${NGINX_CONF}.tmp"
        cat "${NGINX_CONF}.tmp" > "$NGINX_CONF"
        rm -f "${NGINX_CONF}.tmp"
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
PANEL_URL="${PANEL_URL}"
SERVICE_SHORT_UUID="${SERVICE_SHORT_UUID}"
SWAP_STATUSES="${SWAP_STATUSES}"
GRACE_DAYS="${GRACE_DAYS}"
EOF
    chmod 600 "$STATE_FILE"
}

install_tg() {
    echo
    echo -e "${GREEN}Deploying telegram fallback${NC}"
    echo -e "${GREEN}===========================${NC}"
    echo

    deploy_shim
    echo
    patch_nginx
    save_state

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Summary:${NC}"
    echo -e "${WHITE}• TG service shortUuid: ${SERVICE_SHORT_UUID}${NC}"
    echo -e "${WHITE}• Grace days: ${GRACE_DAYS} $([ "$GRACE_DAYS" = "0" ] && echo '(unlimited)')${NC}"
    echo
}

remove_tg() {
    echo
    echo -e "${GREEN}Removing telegram fallback${NC}"
    echo -e "${GREEN}==========================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restoring nginx..."
    echo -e "${GRAY}  ${ARROW}${NC} Reverting proxy_pass to 3010"
    if [ -f "${NGINX_CONF}.tg-sub-expire.bak" ]; then
        cat "${NGINX_CONF}.tg-sub-expire.bak" > "$NGINX_CONF"
        rm -f "${NGINX_CONF}.tg-sub-expire.bak"
    else
        sed 's#proxy_pass http://127.0.0.1:3011;#proxy_pass http://127.0.0.1:3010;#g' "$NGINX_CONF" > "${NGINX_CONF}.tmp"
        cat "${NGINX_CONF}.tmp" > "$NGINX_CONF"
        rm -f "${NGINX_CONF}.tmp"
    fi
    echo -e "${GRAY}  ${ARROW}${NC} Reloading nginx"
    docker exec remnawave-nginx nginx -t > /dev/null 2>&1 && \
        docker exec remnawave-nginx nginx -s reload > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} nginx restored"

    echo
    echo -e "${CYAN}${INFO}${NC} Removing shim container..."
    echo -e "${GRAY}  ${ARROW}${NC} Stopping and removing container"
    cd "$REMNAWAVE_DIR"
    docker compose -f docker-compose.yml -f docker-compose.override.yml rm -sf remnawave-tg-shim > /dev/null 2>&1 || true
    rm -f "$COMPOSE_OVERRIDE"
    echo -e "${GREEN}${CHECK}${NC} Shim removed"

    echo
    echo -e "${CYAN}${INFO}${NC} Cleaning up files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing state file and router.php"
    rm -f "$STATE_FILE" "${SHIM_DIR}/router.php" "${SHIM_DIR}/grace-announce.txt"
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
    echo -e "${PURPLE}=============${NC}"
    echo -e "${WHITE}TG-SUB PANEL${NC}"
    echo -e "${PURPLE}=============${NC}"
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
                load_panel_vars
                input_service_shortuuid
                input_grace_days
                install_tg
                ;;
            2) echo; echo -e "${YELLOW}${WARNING}${NC} Exiting..."; exit 0 ;;
            *) echo; error "Invalid option. Please enter 1-2." ;;
        esac
    fi
}

main
