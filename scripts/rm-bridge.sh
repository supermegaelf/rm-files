#!/bin/bash

#=======================
# REMNAWAVE BRIDGE SETUP
#=======================

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

DIR_BRIDGE="/usr/local/remnawave_bridge/"

#======================
# VALIDATION FUNCTIONS
#======================

validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$domain" =~ [[:space:]] ]]; then
        return 0
    fi
    return 1
}

validate_url() {
    local url=$1
    if [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        return 0
    fi
    return 1
}

#========================
# SYSTEM CHECK FUNCTIONS
#========================

error() {
    echo -e "${RED}${CROSS}${NC} $1"
    exit 1
}

log_entry() {
    mkdir -p ${DIR_BRIDGE}
    LOGFILE="${DIR_BRIDGE}rm-bridge-setup.log"
    exec > >(tee -a "$LOGFILE") 2>&1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script must be run as root"
    fi
}

install_deps() {
    echo -e "${CYAN}${INFO}${NC} Installing dependencies..."

    echo -e "${GRAY}  ${ARROW}${NC} Updating package lists"
    if ! apt-get update -y > /dev/null 2>&1; then
        error "Failed to update package list"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing curl and jq"
    if ! apt-get install -y curl jq > /dev/null 2>&1; then
        error "Failed to install required packages"
    fi

    echo -e "${GREEN}${CHECK}${NC} Dependencies installed"
}

check_deps() {
    local missing=()
    for dep in curl jq; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        install_deps
    fi
}

#===================
# INPUT FUNCTIONS
#===================

input_panel_url() {
    echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
    read PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]] || ! validate_domain "$PANEL_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain (e.g., example.com)."
        echo
        echo -ne "${CYAN}Panel domain: ${NC}"
        read PANEL_DOMAIN
    done
    PANEL_URL="https://${PANEL_DOMAIN}"
}

input_api_token() {
    echo -ne "${CYAN}API token (from panel settings): ${NC}"
    read API_TOKEN
    while [[ -z "$API_TOKEN" ]]; do
        echo -e "${RED}${CROSS}${NC} API token cannot be empty!"
        echo
        echo -ne "${CYAN}API token: ${NC}"
        read API_TOKEN
    done
}

input_sub_url() {
    echo -ne "${CYAN}Subscription URL (e.g., https://example.com/sub/...): ${NC}"
    read SUB_URL
    while [[ -z "$SUB_URL" ]] || ! validate_url "$SUB_URL"; do
        echo -e "${RED}${CROSS}${NC} Invalid URL! Please enter a valid subscription URL."
        echo
        echo -ne "${CYAN}Subscription URL: ${NC}"
        read SUB_URL
    done
}

input_bridge_domain() {
    echo -ne "${CYAN}Bridge domain (e.g., bridge.example.com): ${NC}"
    read BRIDGE_DOMAIN
    while [[ -z "$BRIDGE_DOMAIN" ]] || ! validate_domain "$BRIDGE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Bridge domain: ${NC}"
        read BRIDGE_DOMAIN
    done
}

input_foreign_domain() {
    echo -ne "${CYAN}Foreign node selfsteal domain (e.g., example.com): ${NC}"
    read FOREIGN_DOMAIN
    while [[ -z "$FOREIGN_DOMAIN" ]] || ! validate_domain "$FOREIGN_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Foreign node domain: ${NC}"
        read FOREIGN_DOMAIN
    done
}

#=================
# API FUNCTIONS
#=================

make_api_request() {
    local method=$1
    local path=$2
    local data=${3:-}

    if [ -n "$data" ]; then
        curl -s -X "$method" "${PANEL_URL}${path}" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser" \
            -d "$data"
    else
        curl -s -X "$method" "${PANEL_URL}${path}" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -H "X-Remnawave-Client-Type: browser"
    fi
}

fetch_foreign_node_data() {
    echo -e "${CYAN}${INFO}${NC} Fetching foreign node data from subscription..."

    echo -e "${GRAY}  ${ARROW}${NC} Downloading subscription"
    local sub_data
    sub_data=$(curl -s "$SUB_URL" | base64 -d)

    echo -e "${GRAY}  ${ARROW}${NC} Parsing foreign node entry"
    local foreign_line
    foreign_line=$(echo "$sub_data" | grep "@${FOREIGN_DOMAIN}:" || true)

    if [ -z "$foreign_line" ]; then
        echo -e "${RED}${CROSS}${NC} Domain $FOREIGN_DOMAIN not found in subscription"
        exit 1
    fi

    VLESS_UUID=$(echo "$foreign_line" | grep -oP 'vless://\K[^@]+' || echo "")
    FOREIGN_PBK=$(echo "$foreign_line" | grep -oP '(?<=pbk=)[^&]+' || echo "")
    FOREIGN_SID=$(echo "$foreign_line" | grep -oP '(?<=sid=)[^&#]+' || echo "")

    if [ -z "$VLESS_UUID" ] || [ -z "$FOREIGN_PBK" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to extract required data from subscription"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Foreign node data fetched"
}

generate_bridge_keys() {
    echo -e "${CYAN}${INFO}${NC} Generating Reality keys for Bridge node..."

    echo -e "${GRAY}  ${ARROW}${NC} Requesting x25519 key pair"
    local keys_response
    keys_response=$(make_api_request GET "/api/system/tools/x25519/generate")

    BRIDGE_PRIVATE_KEY=$(echo "$keys_response" | jq -r '.response.keypairs[0].privateKey')

    if [ -z "$BRIDGE_PRIVATE_KEY" ] || [ "$BRIDGE_PRIVATE_KEY" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to generate keys"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Keys generated"
}

create_bridge_profile() {
    echo -e "${CYAN}${INFO}${NC} Creating Bridge config profile..."

    echo -e "${GRAY}  ${ARROW}${NC} Building config"
    local profile_data
    profile_data=$(jq -n \
        --arg bridge_private_key "$BRIDGE_PRIVATE_KEY" \
        --arg foreign_domain "$FOREIGN_DOMAIN" \
        --arg vless_uuid "$VLESS_UUID" \
        --arg foreign_pbk "$FOREIGN_PBK" \
        --arg foreign_sid "$FOREIGN_SID" \
        '{
            name: "Bridge",
            config: {
                log: { loglevel: "warning" },
                inbounds: [{
                    tag: "VLESS_PUBLIC_INBOUND",
                    port: 443,
                    listen: "0.0.0.0",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
                    streamSettings: {
                        network: "raw",
                        security: "reality",
                        realitySettings: {
                            target: "max.ru:443",
                            shortIds: [""],
                            privateKey: $bridge_private_key,
                            serverNames: ["max.ru"]
                        }
                    }
                }],
                outbounds: [
                    { tag: "DIRECT", protocol: "freedom" },
                    { tag: "BLOCK", protocol: "blackhole" },
                    {
                        tag: "VLESS_OUTBOUND_TO_FREEDOM",
                        protocol: "vless",
                        settings: {
                            vnext: [{
                                address: $foreign_domain,
                                port: 443,
                                users: [{
                                    id: $vless_uuid,
                                    encryption: "none",
                                    flow: "xtls-rprx-vision"
                                }]
                            }]
                        },
                        streamSettings: {
                            network: "tcp",
                            security: "reality",
                            realitySettings: {
                                serverName: $foreign_domain,
                                publicKey: $foreign_pbk,
                                shortId: $foreign_sid
                            }
                        }
                    }
                ],
                routing: {
                    rules: [
                        { ip: ["geoip:private"], outboundTag: "BLOCK" },
                        { domain: ["geosite:private"], outboundTag: "BLOCK" },
                        { protocol: ["bittorrent"], outboundTag: "BLOCK" },
                        { inboundTag: ["VLESS_PUBLIC_INBOUND"], outboundTag: "VLESS_OUTBOUND_TO_FREEDOM" }
                    ]
                }
            }
        }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local profile_response
    profile_response=$(make_api_request POST "/api/config-profiles" "$profile_data")

    BRIDGE_PROFILE_UUID=$(echo "$profile_response" | jq -r '.response.uuid')
    BRIDGE_INBOUND_UUID=$(echo "$profile_response" | jq -r '.response.inbounds[0].uuid')

    if [ -z "$BRIDGE_PROFILE_UUID" ] || [ "$BRIDGE_PROFILE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create config profile: $profile_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Config profile created"
}

create_bridge_node() {
    echo -e "${CYAN}${INFO}${NC} Creating Bridge node in panel..."

    local node_data
    node_data=$(jq -n \
        --arg bridge_domain "$BRIDGE_DOMAIN" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$BRIDGE_INBOUND_UUID" \
        '{
            name: "Bridge",
            address: $bridge_domain,
            port: 2222,
            configProfile: {
                activeConfigProfileUuid: $profile_uuid,
                activeInbounds: [$inbound_uuid]
            },
            isTrafficTrackingActive: false,
            trafficLimitBytes: 0,
            notifyPercent: 0,
            trafficResetDay: 1,
            excludedInbounds: [],
            countryCode: "XX",
            consumptionMultiplier: 1.0
        }')

    local node_response
    node_response=$(make_api_request POST "/api/nodes" "$node_data")

    BRIDGE_NODE_UUID=$(echo "$node_response" | jq -r '.response.uuid')
    BRIDGE_SECRET_KEY=$(echo "$node_response" | jq -r '.response.secretKey // ""')

    if [ -z "$BRIDGE_NODE_UUID" ] || [ "$BRIDGE_NODE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create node: $node_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Node created"
}

update_bridge_host() {
    echo -e "${CYAN}${INFO}${NC} Updating host..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching existing hosts"
    local hosts_response
    hosts_response=$(make_api_request GET "/api/hosts")

    local host_uuid
    host_uuid=$(echo "$hosts_response" | jq -r '.response[0].uuid')

    if [ -z "$host_uuid" ] || [ "$host_uuid" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} No hosts found"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating host configuration"
    local host_update
    host_update=$(jq -n \
        --arg host_uuid "$host_uuid" \
        --arg bridge_domain "$BRIDGE_DOMAIN" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$BRIDGE_INBOUND_UUID" \
        '{
            uuid: $host_uuid,
            address: $bridge_domain,
            sni: "max.ru",
            fingerprint: "chrome",
            inbound: {
                configProfileUuid: $profile_uuid,
                configProfileInboundUuid: $inbound_uuid
            }
        }')

    local host_response
    host_response=$(make_api_request PATCH "/api/hosts" "$host_update")

    if ! echo "$host_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update host: $host_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Host updated"
}

update_bridge_squad() {
    echo -e "${CYAN}${INFO}${NC} Adding inbound to squad..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching squad configuration"
    local squad_response
    squad_response=$(make_api_request GET "/api/internal-squads")

    local squad_uuid
    squad_uuid=$(echo "$squad_response" | jq -r '.response.internalSquads[0].uuid')

    local existing_inbounds
    existing_inbounds=$(echo "$squad_response" | jq -r \
        --arg uuid "$squad_uuid" \
        '.response.internalSquads[] | select(.uuid == $uuid) | .inbounds[].uuid' 2>/dev/null \
        | jq -R . | jq -s .)

    if [ "$existing_inbounds" = "null" ] || [ -z "$existing_inbounds" ]; then
        existing_inbounds="[]"
    fi

    local inbounds_array
    inbounds_array=$(jq -n \
        --argjson existing "$existing_inbounds" \
        --arg new "$BRIDGE_INBOUND_UUID" \
        '$existing + [$new] | unique')

    echo -e "${GRAY}  ${ARROW}${NC} Updating squad"
    local squad_update
    squad_update=$(jq -n \
        --arg squad_uuid "$squad_uuid" \
        --argjson inbounds "$inbounds_array" \
        '{
            uuid: $squad_uuid,
            inbounds: $inbounds
        }')

    local squad_patch_response
    squad_patch_response=$(make_api_request PATCH "/api/internal-squads" "$squad_update")

    if ! echo "$squad_patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update squad: $squad_patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Inbound added to squad"
}

#======================
# MAIN ENTRY FUNCTIONS
#======================

setup_bridge() {
    set -e

    echo
    echo -e "${GREEN}Fetching data${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    fetch_foreign_node_data

    echo
    echo -e "${GREEN}Generating keys${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    generate_bridge_keys

    echo
    echo -e "${GREEN}Configuring panel${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    create_bridge_profile
    echo
    create_bridge_node
    echo
    update_bridge_host
    echo
    update_bridge_squad

    echo
    echo -e "${PURPLE}=================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Setup complete"
    echo -e "${PURPLE}=================${NC}"
    echo
    echo -e "${CYAN}Install node on Bridge server:${NC}"
    echo -e "${WHITE}bash <(curl -s https://raw.githubusercontent.com/supermegaelf/rm-files/main/scripts/rm-install.sh)${NC}"
    echo
    echo -e "${CYAN}Selfsteal domain:${NC}"
    echo -e "${WHITE}${BRIDGE_DOMAIN}${NC}"
    echo

    if [ -n "$BRIDGE_SECRET_KEY" ]; then
        echo -e "${CYAN}Secret Key (${YELLOW}paste into install script${CYAN}):${NC}"
        echo -e "${WHITE}${BRIDGE_SECRET_KEY}${NC}"
        echo
    fi

    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check logs: cd /opt/remnanode && docker compose logs -f${NC}"
    echo -e "${WHITE}• Restart node: cd /opt/remnanode && docker compose restart${NC}"
    echo
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    check_root
    check_deps

    echo
    echo -e "${PURPLE}=======================${NC}"
    echo -e "${WHITE}REMNAWAVE BRIDGE SETUP${NC}"
    echo -e "${PURPLE}=======================${NC}"
    echo

    input_panel_url
    input_api_token
    input_sub_url
    input_bridge_domain
    input_foreign_domain

    setup_bridge
}

main
exit 0
