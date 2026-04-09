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
    echo
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

#=====================
# MAIN MENU FUNCTIONS
#=====================

show_main_menu() {
    echo
    echo -e "${PURPLE}=======================${NC}"
    echo -e "${WHITE}REMNAWAVE BRIDGE SETUP${NC}"
    echo -e "${PURPLE}=======================${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    echo -e "${GREEN}1.${NC} Setup bridge"
    echo -e "${GREEN}2.${NC} Add node to bridge"
    echo -e "${RED}3.${NC} Exit"
    echo
    echo -ne "${CYAN}Enter your choice (1, 2, or 3): ${NC}"
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
    echo -ne "${CYAN}Foreign node domain (e.g., example.com): ${NC}"
    read FOREIGN_DOMAIN
    while [[ -z "$FOREIGN_DOMAIN" ]] || ! validate_domain "$FOREIGN_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Foreign node domain: ${NC}"
        read FOREIGN_DOMAIN
    done
}

input_reality_sni() {
    echo -ne "${CYAN}Reality SNI (e.g., max.ru): ${NC}"
    read REALITY_SNI
    while [[ -z "$REALITY_SNI" ]] || ! validate_domain "$REALITY_SNI"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Reality SNI: ${NC}"
        read REALITY_SNI
    done
}

input_bridge_port() {
    echo -ne "${CYAN}Bridge port for new inbound (e.g., 9443): ${NC}"
    read BRIDGE_PORT
    while [[ -z "$BRIDGE_PORT" ]] || ! [[ "$BRIDGE_PORT" =~ ^[0-9]+$ ]] || [ "$BRIDGE_PORT" -lt 1024 ] || [ "$BRIDGE_PORT" -gt 65535 ]; do
        echo -e "${RED}${CROSS}${NC} Invalid port! Please enter a valid port number (1024-65535)."
        echo
        echo -ne "${CYAN}Bridge port: ${NC}"
        read BRIDGE_PORT
    done
}

input_host_remark() {
    echo -ne "${CYAN}Host remark (e.g., 🇳🇱 Нидерланды): ${NC}"
    read HOST_REMARK
    while [[ -z "$HOST_REMARK" ]]; do
        echo -e "${RED}${CROSS}${NC} Remark cannot be empty!"
        echo
        echo -ne "${CYAN}Host remark: ${NC}"
        read HOST_REMARK
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
    foreign_line=$(echo "$sub_data" | grep "sni=${FOREIGN_DOMAIN}" || true)
    if [ -z "$foreign_line" ]; then
        foreign_line=$(echo "$sub_data" | grep "@${FOREIGN_DOMAIN}:" || true)
    fi

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

fetch_panel_data() {
    echo -e "${CYAN}${INFO}${NC} Fetching panel configuration..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching config profiles"
    local profiles_response
    profiles_response=$(make_api_request GET "/api/config-profiles")

    BRIDGE_PROFILE_UUID=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "Bridge") | .uuid')
    BRIDGE_CONFIG=$(echo "$profiles_response" | jq -c '.response.configProfiles[] | select(.name == "Bridge") | .config')

    if [ -z "$BRIDGE_PROFILE_UUID" ] || [ "$BRIDGE_PROFILE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Bridge config profile not found"
        exit 1
    fi

    STEALCONFIG_UUID=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "StealConfig") | .uuid')
    STEALCONFIG_CONFIG=$(echo "$profiles_response" | jq -c '.response.configProfiles[] | select(.name == "StealConfig") | .config')

    if [ -z "$STEALCONFIG_UUID" ] || [ "$STEALCONFIG_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} StealConfig profile not found"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Fetching nodes"
    local nodes_response
    nodes_response=$(make_api_request GET "/api/nodes")

    BRIDGE_NODE_UUID=$(echo "$nodes_response" | jq -r \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        '.response[] | select(.configProfile.activeConfigProfileUuid == $profile_uuid) | .uuid')
    BRIDGE_ADDRESS=$(echo "$nodes_response" | jq -r \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        '.response[] | select(.configProfile.activeConfigProfileUuid == $profile_uuid) | .address')
    BRIDGE_CURRENT_INBOUNDS=$(echo "$nodes_response" | jq -c \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        '[.response[] | select(.configProfile.activeConfigProfileUuid == $profile_uuid) | .configProfile.activeInbounds[].uuid]')

    if [ -z "$BRIDGE_NODE_UUID" ] || [ "$BRIDGE_NODE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Bridge node not found"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Panel data fetched"
}

create_bridge_profile() {
    echo -e "${CYAN}${INFO}${NC} Creating Bridge config profile..."

    echo -e "${GRAY}  ${ARROW}${NC} Building config"
    local profile_data
    profile_data=$(jq -n \
        --arg bridge_private_key "$BRIDGE_PRIVATE_KEY" \
        --arg foreign_domain "$FOREIGN_DOMAIN" \
        --arg reality_sni "$REALITY_SNI" \
        --arg vless_uuid "$VLESS_UUID" \
        --arg foreign_pbk "$FOREIGN_PBK" \
        --arg foreign_sid "$FOREIGN_SID" \
        '{
            name: "Bridge",
            config: {
                log: { loglevel: "warning" },
                inbounds: [{
                    tag: "VLESS_INBOUND_10443",
                    port: 10443,
                    listen: "127.0.0.1",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
                    streamSettings: {
                        network: "raw",
                        security: "reality",
                        realitySettings: {
                            target: ($foreign_domain + ":443"),
                            shortIds: [""],
                            privateKey: $bridge_private_key,
                            serverNames: [$foreign_domain]
                        }
                    }
                }],
                outbounds: [
                    { tag: "DIRECT", protocol: "freedom" },
                    { tag: "BLOCK", protocol: "blackhole" },
                    {
                        tag: "VLESS_OUTBOUND_10443",
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
                                serverName: $reality_sni,
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
                        { inboundTag: ["VLESS_INBOUND_10443"], outboundTag: "VLESS_OUTBOUND_10443" }
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

update_bridge_config_profile() {
    echo -e "${CYAN}${INFO}${NC} Updating Bridge config profile..."

    echo -e "${GRAY}  ${ARROW}${NC} Building new inbound and outbound"
    local bridge_private_key
    bridge_private_key=$(echo "$BRIDGE_CONFIG" | jq -r '.inbounds[0].streamSettings.realitySettings.privateKey')

    local inbound_tag="VLESS_INBOUND_${NEW_LOCAL_PORT}"
    local outbound_tag="VLESS_OUTBOUND_${NEW_LOCAL_PORT}"

    local new_inbound
    new_inbound=$(jq -n \
        --arg tag "$inbound_tag" \
        --arg port "$NEW_LOCAL_PORT" \
        --arg private_key "$bridge_private_key" \
        --arg foreign_domain "$FOREIGN_DOMAIN" \
        '{
            tag: $tag,
            port: ($port | tonumber),
            listen: "127.0.0.1",
            protocol: "vless",
            settings: { clients: [], decryption: "none" },
            sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
            streamSettings: {
                network: "raw",
                security: "reality",
                realitySettings: {
                    target: ($foreign_domain + ":443"),
                    shortIds: [""],
                    privateKey: $private_key,
                    serverNames: [$foreign_domain]
                }
            }
        }')

    local new_outbound
    new_outbound=$(jq -n \
        --arg tag "$outbound_tag" \
        --arg domain "$FOREIGN_DOMAIN" \
        --arg reality_sni "$REALITY_SNI" \
        --arg uuid "$VLESS_UUID" \
        --arg pbk "$FOREIGN_PBK" \
        --arg sid "$FOREIGN_SID" \
        '{
            tag: $tag,
            protocol: "vless",
            settings: {
                vnext: [{
                    address: $domain,
                    port: 443,
                    users: [{ id: $uuid, flow: "xtls-rprx-vision", encryption: "none" }]
                }]
            },
            streamSettings: {
                network: "tcp",
                security: "reality",
                realitySettings: {
                    serverName: $reality_sni,
                    publicKey: $pbk,
                    shortId: $sid
                }
            }
        }')

    local new_rule
    new_rule=$(jq -n \
        --arg inbound_tag "$inbound_tag" \
        --arg outbound_tag "$outbound_tag" \
        '{ inboundTag: [$inbound_tag], outboundTag: $outbound_tag }')

    local updated_config
    updated_config=$(echo "$BRIDGE_CONFIG" | jq -c \
        --argjson inbound "$new_inbound" \
        --argjson outbound "$new_outbound" \
        --argjson rule "$new_rule" \
        '.inbounds += [$inbound] | .outbounds += [$outbound] | .routing.rules += [$rule]')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local patch_data
    patch_data=$(jq -n \
        --arg uuid "$BRIDGE_PROFILE_UUID" \
        --argjson config "$updated_config" \
        '{ uuid: $uuid, config: $config }')

    local patch_response
    patch_response=$(make_api_request PATCH "/api/config-profiles" "$patch_data")

    NEW_INBOUND_UUID=$(echo "$patch_response" | jq -r \
        --arg port "$NEW_LOCAL_PORT" \
        '.response.inbounds[] | select(.port == ($port | tonumber)) | .uuid')

    if [ -z "$NEW_INBOUND_UUID" ] || [ "$NEW_INBOUND_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to update Bridge config profile: $patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Bridge config profile updated"
}

update_bridge_node_inbounds() {
    echo -e "${CYAN}${INFO}${NC} Updating Bridge node inbounds..."

    local updated_inbounds
    updated_inbounds=$(echo "$BRIDGE_CURRENT_INBOUNDS" | jq -c \
        --arg new_uuid "$NEW_INBOUND_UUID" \
        '. + [$new_uuid] | unique')

    local patch_data
    patch_data=$(jq -n \
        --arg node_uuid "$BRIDGE_NODE_UUID" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --argjson inbounds "$updated_inbounds" \
        '{
            uuid: $node_uuid,
            configProfile: {
                activeConfigProfileUuid: $profile_uuid,
                activeInbounds: $inbounds
            }
        }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local patch_response
    patch_response=$(make_api_request PATCH "/api/nodes" "$patch_data")

    if ! echo "$patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update Bridge node: $patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Bridge node updated"
}

update_stealconfig_setup() {
    echo -e "${CYAN}${INFO}${NC} Updating StealConfig server names..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching StealConfig profile"
    local profiles_response
    profiles_response=$(make_api_request GET "/api/config-profiles")

    local stealconfig_uuid
    stealconfig_uuid=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "StealConfig") | .uuid')
    local stealconfig_config
    stealconfig_config=$(echo "$profiles_response" | jq -c '.response.configProfiles[] | select(.name == "StealConfig") | .config')

    if [ -z "$stealconfig_uuid" ] || [ "$stealconfig_uuid" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} StealConfig profile not found"
        exit 1
    fi

    if echo "$stealconfig_config" | jq -e \
        --arg domain "$REALITY_SNI" \
        '.inbounds[0].streamSettings.realitySettings.serverNames | contains([$domain])' > /dev/null 2>&1; then
        echo -e "${GRAY}  ${ARROW}${NC} Domain already present"
        echo -e "${GREEN}${CHECK}${NC} StealConfig unchanged"
        return 0
    fi

    local updated_config
    updated_config=$(echo "$stealconfig_config" | jq -c \
        --arg domain "$REALITY_SNI" \
        '.inbounds[0].streamSettings.realitySettings.serverNames += [$domain]')

    local patch_data
    patch_data=$(jq -n \
        --arg uuid "$stealconfig_uuid" \
        --argjson config "$updated_config" \
        '{ uuid: $uuid, config: $config }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local patch_response
    patch_response=$(make_api_request PATCH "/api/config-profiles" "$patch_data")

    if ! echo "$patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update StealConfig: $patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} StealConfig updated"
}

update_stealconfig_servernames() {
    echo -e "${CYAN}${INFO}${NC} Updating StealConfig server names..."

    if echo "$STEALCONFIG_CONFIG" | jq -e \
        --arg domain "$REALITY_SNI" \
        '.inbounds[0].streamSettings.realitySettings.serverNames | contains([$domain])' > /dev/null 2>&1; then
        echo -e "${GRAY}  ${ARROW}${NC} Domain already present"
        echo -e "${GREEN}${CHECK}${NC} StealConfig unchanged"
        return 0
    fi

    local updated_config
    updated_config=$(echo "$STEALCONFIG_CONFIG" | jq -c \
        --arg domain "$REALITY_SNI" \
        '.inbounds[0].streamSettings.realitySettings.serverNames += [$domain]')

    local patch_data
    patch_data=$(jq -n \
        --arg uuid "$STEALCONFIG_UUID" \
        --argjson config "$updated_config" \
        '{ uuid: $uuid, config: $config }')

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
    local patch_response
    patch_response=$(make_api_request PATCH "/api/config-profiles" "$patch_data")

    if ! echo "$patch_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to update StealConfig: $patch_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} StealConfig updated"
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

    echo -e "${GRAY}  ${ARROW}${NC} Sending request to panel"
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
        --arg foreign_domain "$FOREIGN_DOMAIN" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$BRIDGE_INBOUND_UUID" \
        '{
            uuid: $host_uuid,
            address: $bridge_domain,
            port: 443,
            sni: $foreign_domain,
            fingerprint: "chrome",
            overrideSniFromAddress: false,
            keepSniBlank: false,
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

create_bridge_host() {
    echo -e "${CYAN}${INFO}${NC} Configuring host..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching existing hosts"
    local hosts_response
    hosts_response=$(make_api_request GET "/api/hosts")

    local existing_host_uuid
    existing_host_uuid=$(echo "$hosts_response" | jq -r \
        --arg domain "$FOREIGN_DOMAIN" \
        '.response[] | select(.sni == $domain) | .uuid' | head -1)

    local host_payload
    host_payload=$(jq -n \
        --arg remark "$HOST_REMARK" \
        --arg address "$BRIDGE_ADDRESS" \
        --arg foreign_domain "$FOREIGN_DOMAIN" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$NEW_INBOUND_UUID" \
        '{
            remark: $remark,
            address: $address,
            port: 443,
            sni: $foreign_domain,
            fingerprint: "chrome",
            overrideSniFromAddress: false,
            keepSniBlank: false,
            inbound: {
                configProfileUuid: $profile_uuid,
                configProfileInboundUuid: $inbound_uuid
            }
        }')

    local host_response
    if [ -n "$existing_host_uuid" ] && [ "$existing_host_uuid" != "null" ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Updating existing host"
        host_payload=$(echo "$host_payload" | jq --arg uuid "$existing_host_uuid" '. + {uuid: $uuid}')
        host_response=$(make_api_request PATCH "/api/hosts" "$host_payload")
    else
        echo -e "${GRAY}  ${ARROW}${NC} Creating new host"
        host_response=$(make_api_request POST "/api/hosts" "$host_payload")
    fi

    if ! echo "$host_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${RED}${CROSS}${NC} Failed to configure host: $host_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Host configured"
}

update_bridge_squad() {
    local target_inbound_uuid="${1:-$BRIDGE_INBOUND_UUID}"

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
        --arg new "$target_inbound_uuid" \
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

assign_local_port() {
    local max_port=10442
    local port
    while IFS= read -r port; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 10443 ] && [ "$port" -gt "$max_port" ]; then
            max_port=$port
        fi
    done <<< "$(echo "$BRIDGE_CONFIG" | jq -r '.inbounds[].port')"
    NEW_LOCAL_PORT=$((max_port + 1))
}

install_docker() {
    echo -e "${CYAN}${INFO}${NC} Installing Docker..."

    echo -e "${GRAY}  ${ARROW}${NC} Installing prerequisites"
    if ! apt-get install -y ca-certificates curl gnupg > /dev/null 2>&1; then
        error "Failed to install Docker prerequisites"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Checking Docker DNS connectivity"
    if ! curl -s --max-time 5 https://download.docker.com >/dev/null 2>&1; then
        error "Unable to reach download.docker.com. Check your DNS settings."
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Adding Docker repository"
    install -m 0755 -d /etc/apt/keyrings
    if grep -q "Ubuntu" /etc/os-release; then
        if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null; then
            error "Failed to download Docker GPG key"
        fi
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    elif grep -q "Debian" /etc/os-release; then
        if ! curl -fsSL https://download.docker.com/linux/debian/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null; then
            error "Failed to download Docker GPG key"
        fi
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Updating package list"
    if ! apt-get update > /dev/null 2>&1; then
        error "Failed to update package list after adding Docker repository"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing Docker packages"
    if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1; then
        error "Failed to install Docker"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Starting Docker service"
    if ! systemctl is-active --quiet docker; then
        if ! systemctl start docker > /dev/null 2>&1; then
            error "Failed to start Docker"
        fi
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Enabling Docker auto-start"
    if ! systemctl is-enabled --quiet docker; then
        if ! systemctl enable docker > /dev/null 2>&1; then
            error "Failed to enable Docker auto-start"
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        error "Docker is not working properly"
    fi

    echo -e "${GREEN}${CHECK}${NC} Docker installed"
    echo
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        install_docker
    fi
}

setup_nginx_stream() {
    echo -e "${CYAN}${INFO}${NC} Setting up nginx stream..."

    mkdir -p /opt/remnabridge

    echo -e "${GRAY}  ${ARROW}${NC} Writing nginx.conf"
    cat > /opt/remnabridge/nginx.conf <<EOF
worker_processes auto;

events {
    worker_connections 1024;
}

stream {
    map \$ssl_preread_server_name \$backend {
        ${FOREIGN_DOMAIN}  127.0.0.1:10443;
        default         127.0.0.1:10443;
    }

    server {
        listen 443;
        proxy_pass \$backend;
        ssl_preread on;
        proxy_buffer_size 16k;
    }
}
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Writing docker-compose.yml"
    cat > /opt/remnabridge/docker-compose.yml <<EOF
services:
  remnabridge-nginx:
    image: nginx:stable
    container_name: remnabridge-nginx
    restart: always
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    network_mode: host
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Starting nginx container"
    cd /opt/remnabridge && docker compose up -d > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} Nginx stream started"
}

update_nginx_stream() {
    echo -e "${CYAN}${INFO}${NC} Updating nginx stream..."

    local nginx_conf="/opt/remnabridge/nginx.conf"

    echo -e "${GRAY}  ${ARROW}${NC} Adding SNI mapping"
    sed -i "/^        default /i\\        ${FOREIGN_DOMAIN}  127.0.0.1:${NEW_LOCAL_PORT};" "$nginx_conf"

    echo -e "${GRAY}  ${ARROW}${NC} Reloading nginx"
    docker exec remnabridge-nginx nginx -s reload > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} Nginx stream updated"
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
    update_stealconfig_setup
    echo
    update_bridge_squad

    echo
    echo -e "${GREEN}Setting up nginx${NC}"
    echo -e "${GREEN}================${NC}"
    echo

    check_docker
    setup_nginx_stream

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
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
}

add_node_to_bridge() {
    set -e

    echo
    echo -e "${GREEN}Fetching data${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    fetch_foreign_node_data

    echo
    echo -e "${GREEN}Fetching panel data${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    fetch_panel_data

    local existing_domain
    existing_domain=$(echo "$BRIDGE_CONFIG" | jq -r \
        --arg domain "$FOREIGN_DOMAIN" \
        '.inbounds[] | select(.streamSettings.realitySettings.serverNames[]? == $domain) | .port')
    if [ -n "$existing_domain" ]; then
        echo -e "${RED}${CROSS}${NC} Foreign domain ${FOREIGN_DOMAIN} is already configured on bridge"
        exit 1
    fi

    assign_local_port

    echo
    echo -e "${GREEN}Configuring panel${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    update_bridge_config_profile
    echo
    update_bridge_node_inbounds
    echo
    update_stealconfig_servernames
    echo
    create_bridge_host
    echo
    update_bridge_squad "$NEW_INBOUND_UUID"

    echo
    echo -e "${GREEN}Updating nginx${NC}"
    echo -e "${GREEN}==============${NC}"
    echo

    update_nginx_stream

    echo
    echo -e "${PURPLE}===================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Node added successfully"
    echo -e "${PURPLE}===================${NC}"
    echo
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    check_root
    check_deps

    show_main_menu
    read SETUP_TYPE

    case $SETUP_TYPE in
        1)
            echo
            echo -e "${PURPLE}=============${NC}"
            echo -e "${WHITE}Bridge Setup${NC}"
            echo -e "${PURPLE}=============${NC}"
            echo

            input_panel_url
            input_api_token
            input_sub_url
            input_bridge_domain
            input_foreign_domain
            input_reality_sni

            setup_bridge
            ;;
        2)
            echo
            echo -e "${PURPLE}===================${NC}"
            echo -e "${WHITE}Add Node to Bridge${NC}"
            echo -e "${PURPLE}===================${NC}"
            echo

            input_panel_url
            input_api_token
            input_sub_url
            input_foreign_domain
            input_reality_sni
            input_host_remark

            add_node_to_bridge
            ;;
        3)
            echo
            echo -e "${YELLOW}${WARNING}${NC} Exiting..."
            exit 0
            ;;
        *)
            echo
            echo -e "${RED}${CROSS}${NC} Invalid option. Please enter 1, 2, or 3."
            exit 1
            ;;
    esac
}

main
exit 0
