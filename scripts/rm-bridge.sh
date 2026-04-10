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
NODE_VERSION="2.7.0"

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

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
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

install_system_packages() {
    echo -e "${CYAN}${INFO}${NC} Installing system packages..."

    echo -e "${GRAY}  ${ARROW}${NC} Updating package lists"
    if ! apt-get update -y > /dev/null 2>&1; then
        error "Failed to update package list"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Installing essential packages"
    if ! apt-get install -y ca-certificates curl jq ufw gnupg unattended-upgrades > /dev/null 2>&1; then
        error "Failed to install required packages"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring TCP optimizations (BBR)"
    if ! grep -qE '^\s*net\.core\.default_qdisc\s*=\s*fq' /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi
    if ! grep -qE '^\s*net\.ipv4\.tcp_congestion_control\s*=\s*bbr' /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null

    echo -e "${GRAY}  ${ARROW}${NC} Configuring UFW firewall"
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
    ufw allow from "$PANEL_IP" to any port 2222 comment 'Remnawave panel' > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1

    if ! command -v docker &> /dev/null; then
        echo -e "${GRAY}  ${ARROW}${NC} Checking Docker DNS connectivity"
        if ! curl -s --max-time 5 https://download.docker.com >/dev/null 2>&1; then
            error "Unable to reach download.docker.com. Check your DNS settings."
        fi

        echo -e "${GRAY}  ${ARROW}${NC} Adding Docker repository"
        install -m 0755 -d /etc/apt/keyrings
        if grep -q "Ubuntu" /etc/os-release; then
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        elif grep -q "Debian" /etc/os-release; then
            curl -fsSL https://download.docker.com/linux/debian/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null
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
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Starting Docker service"
    if ! systemctl is-active --quiet docker; then
        systemctl start docker > /dev/null 2>&1 || error "Failed to start Docker"
    fi
    if ! systemctl is-enabled --quiet docker; then
        systemctl enable docker > /dev/null 2>&1 || error "Failed to enable Docker"
    fi

    if ! docker info >/dev/null 2>&1; then
        error "Docker is not working properly"
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Configuring automatic security updates"
    echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades > /dev/null 2>&1
    systemctl restart unattended-upgrades > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} System packages configured"
}

#=====================
# MAIN MENU FUNCTIONS
#=====================

show_main_menu() {
    BRIDGE_INSTALLED=false
    [ -d /opt/remnabridge ] && BRIDGE_INSTALLED=true

    echo
    echo -e "${PURPLE}=======================${NC}"
    echo -e "${WHITE}REMNAWAVE BRIDGE SETUP${NC}"
    echo -e "${PURPLE}=======================${NC}"
    echo
    echo -e "${CYAN}Please select an option:${NC}"
    echo
    echo -e "${GREEN}1.${NC} Setup bridge"
    echo -e "${GREEN}2.${NC} Add node to bridge"
    if [ "$BRIDGE_INSTALLED" = true ]; then
        echo -e "${RED}3.${NC} Remove bridge"
        echo -e "${YELLOW}4.${NC} Exit"
    else
        echo -e "${YELLOW}3.${NC} Exit"
    fi
    echo
    echo -ne "${CYAN}Enter your choice: ${NC}"
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
    echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
    read API_TOKEN
    while [[ -z "$API_TOKEN" ]]; do
        echo -e "${RED}${CROSS}${NC} API token cannot be empty!"
        echo
        echo -ne "${CYAN}API token (e.g., eyJhbGciOi...): ${NC}"
        read API_TOKEN
    done
}


input_bridge_domain() {
    echo -ne "${CYAN}Bridge domain (e.g., bridge.example.com or example.com): ${NC}"
    read BRIDGE_DOMAIN
    while [[ -z "$BRIDGE_DOMAIN" ]] || ! validate_domain "$BRIDGE_DOMAIN"; do
        echo -e "${RED}${CROSS}${NC} Invalid domain! Please enter a valid domain."
        echo
        echo -ne "${CYAN}Bridge domain: ${NC}"
        read BRIDGE_DOMAIN
    done
}

input_foreign_domain() {
    echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
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


fetch_foreign_node_data_api() {
    local use_docker_run="${1:-false}"

    echo -e "${CYAN}${INFO}${NC} Fetching foreign node data from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Finding foreign node"
    local nodes_response
    nodes_response=$(make_api_request GET "/api/nodes")

    local foreign_node
    foreign_node=$(echo "$nodes_response" | jq -c \
        --arg domain "$FOREIGN_DOMAIN" \
        '.response[] | select(.address == $domain)')

    if [ -z "$foreign_node" ] || [ "$foreign_node" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Node with address $FOREIGN_DOMAIN not found in panel"
        exit 1
    fi

    local foreign_profile_uuid
    foreign_profile_uuid=$(echo "$foreign_node" | jq -r '.configProfile.activeConfigProfileUuid')

    echo -e "${GRAY}  ${ARROW}${NC} Fetching config profile"
    local profile_response
    profile_response=$(make_api_request GET "/api/config-profiles")

    local foreign_config
    foreign_config=$(echo "$profile_response" | jq -c \
        --arg uuid "$foreign_profile_uuid" \
        '.response.configProfiles[] | select(.uuid == $uuid) | .config')

    if [ -z "$foreign_config" ] || [ "$foreign_config" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Config profile for $FOREIGN_DOMAIN not found"
        exit 1
    fi

    local private_key
    private_key=$(echo "$foreign_config" | jq -r '.inbounds[0].streamSettings.realitySettings.privateKey')
    FOREIGN_SID=$(echo "$foreign_config" | jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]')

    echo -e "${GRAY}  ${ARROW}${NC} Deriving public key"
    local xray_output
    if [ "$use_docker_run" = "true" ]; then
        xray_output=$(docker run --rm remnawave/node:${NODE_VERSION} xray x25519 -i "$private_key" 2>&1 || true)
    else
        xray_output=$(docker exec remnanode xray x25519 -i "$private_key" 2>&1 || true)
    fi
    FOREIGN_PBK=$(echo "$xray_output" | grep -oP 'Password \(PublicKey\): \K.*' || true)

    if [ -z "$FOREIGN_PBK" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to derive public key. xray output: $xray_output"
        exit 1
    fi

    echo -e "${GRAY}  ${ARROW}${NC} Fetching user data"
    local users_response
    users_response=$(make_api_request GET "/api/users?size=1&start=0")
    VLESS_UUID=$(echo "$users_response" | jq -r '.response.users[0].vlessUuid')

    if [ -z "$VLESS_UUID" ] || [ "$VLESS_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} No users found in panel"
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
                            target: ($reality_sni + ":443"),
                            shortIds: [""],
                            privateKey: $bridge_private_key,
                            serverNames: [$reality_sni]
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
        --arg reality_sni "$REALITY_SNI" \
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
                    target: ($reality_sni + ":443"),
                    shortIds: [""],
                    privateKey: $private_key,
                    serverNames: [$reality_sni]
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
                    serverName: $domain,
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

    if [ -z "$BRIDGE_NODE_UUID" ] || [ "$BRIDGE_NODE_UUID" = "null" ]; then
        echo -e "${RED}${CROSS}${NC} Failed to create node: $node_response"
        exit 1
    fi

    echo -e "${GREEN}${CHECK}${NC} Node created"
    echo
    echo -e "${CYAN}Enter the node's Secret Key from the panel and press \"Enter\" twice:${NC}"
    BRIDGE_SECRET_KEY=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            if [ -n "$BRIDGE_SECRET_KEY" ]; then
                break
            fi
        else
            BRIDGE_SECRET_KEY="$BRIDGE_SECRET_KEY$line"
        fi
    done

    echo -ne "${YELLOW}Are you sure the Secret Key is correct? (y/n): ${NC}"
    read confirm

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}${CROSS}${NC} Installation aborted by user"
        exit 1
    fi
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
        --arg reality_sni "$REALITY_SNI" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$BRIDGE_INBOUND_UUID" \
        '{
            uuid: $host_uuid,
            address: $bridge_domain,
            port: 443,
            sni: $reality_sni,
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
        '.response[] | select(.address == $domain) | .uuid' | head -1)

    local host_payload
    host_payload=$(jq -n \
        --arg remark "$HOST_REMARK" \
        --arg address "$BRIDGE_ADDRESS" \
        --arg reality_sni "$REALITY_SNI" \
        --arg profile_uuid "$BRIDGE_PROFILE_UUID" \
        --arg inbound_uuid "$NEW_INBOUND_UUID" \
        '{
            remark: $remark,
            address: $address,
            port: 443,
            sni: $reality_sni,
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

deploy_bridge_services() {
    echo -e "${CYAN}${INFO}${NC} Deploying bridge services..."

    mkdir -p /opt/remnabridge

    echo -e "${GRAY}  ${ARROW}${NC} Writing .env-node"
    cat > /opt/remnabridge/.env-node <<EOF
NODE_PORT=2222
SECRET_KEY=${BRIDGE_SECRET_KEY}
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Writing nginx.conf"
    cat > /opt/remnabridge/nginx.conf <<EOF
worker_processes auto;

events {
    worker_connections 1024;
}

stream {
    map \$ssl_preread_server_name \$backend {
        ${REALITY_SNI} 127.0.0.1:10443;
        default 127.0.0.1:10443;
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
    depends_on:
      - remnanode
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnanode:
    image: remnawave/node:${NODE_VERSION}
    container_name: remnanode
    hostname: remnanode
    restart: always
    cap_add:
      - NET_ADMIN
    network_mode: host
    env_file:
      - path: ./.env-node
        required: false
    volumes:
      - /dev/shm:/dev/shm:rw
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'
EOF

    echo -e "${GRAY}  ${ARROW}${NC} Starting bridge services"
    cd /opt/remnabridge && docker compose pull > /dev/null 2>&1
    if ! docker compose up -d > /dev/null 2>&1; then
        error "Failed to start bridge services"
    fi

    echo -e "${GREEN}${CHECK}${NC} Bridge services started"
}

restart_bridge_node() {
    echo -e "${CYAN}${INFO}${NC} Restarting bridge node..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending restart request"
    local restart_response
    restart_response=$(make_api_request POST "/api/nodes/${BRIDGE_NODE_UUID}/actions/restart")

    if echo "$restart_response" | jq -e '.response.eventSent' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} Bridge node restarted"
    else
        echo -e "${YELLOW}${WARNING}${NC} API restart failed, restarting via Docker"
        cd /opt/remnabridge && docker compose restart remnanode > /dev/null 2>&1
        echo -e "${GREEN}${CHECK}${NC} Bridge node restarted via Docker"
    fi
}

update_nginx_stream() {
    echo -e "${CYAN}${INFO}${NC} Updating nginx stream..."

    local nginx_conf="/opt/remnabridge/nginx.conf"

    echo -e "${GRAY}  ${ARROW}${NC} Adding SNI mapping"
    sed -i "/^        default /i\\        ${REALITY_SNI} 127.0.0.1:${NEW_LOCAL_PORT};" "$nginx_conf"

    echo -e "${GRAY}  ${ARROW}${NC} Restarting nginx"
    docker restart remnabridge-nginx > /dev/null 2>&1

    echo -e "${GREEN}${CHECK}${NC} Nginx stream updated"
}

#======================
# MAIN ENTRY FUNCTIONS
#======================

setup_bridge() {
    set -e

    echo
    echo -e "${GREEN}Installing packages${NC}"
    echo -e "${GREEN}===================${NC}"
    echo

    install_system_packages

    echo
    echo -e "${GREEN}Fetching data${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    fetch_foreign_node_data_api "true"

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
    echo -e "${GREEN}Deploying services${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    deploy_bridge_services

    echo
    echo -e "${PURPLE}========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Installation complete"
    echo -e "${PURPLE}========================${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "${WHITE}• Check logs: cd /opt/remnabridge && docker compose logs -f${NC}"
    echo -e "${WHITE}• Restart service: cd /opt/remnabridge && docker compose restart${NC}"
    echo
}

add_node_to_bridge() {
    set -e

    echo
    echo -e "${GREEN}Fetching data${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    fetch_panel_data
    echo
    fetch_foreign_node_data_api

    local existing_domain
    existing_domain=$(echo "$BRIDGE_CONFIG" | jq -r \
        --arg domain "$REALITY_SNI" \
        '.inbounds[] | select(.streamSettings.realitySettings.serverNames[]? == $domain) | .port')
    if [ -n "$existing_domain" ]; then
        echo -e "${RED}${CROSS}${NC} Reality SNI ${REALITY_SNI} is already configured on bridge"
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
    echo -e "${GREEN}Restarting node${NC}"
    echo -e "${GREEN}===============${NC}"
    echo

    restart_bridge_node

    echo
    echo -e "${PURPLE}==========================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Node added successfully"
    echo -e "${PURPLE}==========================${NC}"
    echo
}

remove_bridge() {
    echo
    echo -e "${GREEN}Fetching data${NC}"
    echo -e "${GREEN}=============${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Fetching Bridge configuration from panel..."

    echo -e "${GRAY}  ${ARROW}${NC} Fetching config profiles"
    local profiles_response
    profiles_response=$(make_api_request GET "/api/config-profiles")

    local bridge_profile_uuid
    bridge_profile_uuid=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "Bridge") | .uuid')

    if [ -z "$bridge_profile_uuid" ] || [ "$bridge_profile_uuid" = "null" ]; then
        echo -e "${YELLOW}${WARNING}${NC} Bridge is not installed"
        exit 0
    fi

    local bridge_config
    bridge_config=$(echo "$profiles_response" | jq -c '.response.configProfiles[] | select(.name == "Bridge") | .config')

    local bridge_inbound_uuids
    bridge_inbound_uuids=$(echo "$profiles_response" | jq -c \
        '[.response.configProfiles[] | select(.name == "Bridge") | .inbounds[].uuid]')

    local bridge_snis
    bridge_snis=$(echo "$bridge_config" | jq -c \
        '[.inbounds[].streamSettings.realitySettings.serverNames[]] | unique')

    local stealconfig_uuid
    stealconfig_uuid=$(echo "$profiles_response" | jq -r '.response.configProfiles[] | select(.name == "StealConfig") | .uuid')
    local stealconfig_config
    stealconfig_config=$(echo "$profiles_response" | jq -c '.response.configProfiles[] | select(.name == "StealConfig") | .config')

    echo -e "${GRAY}  ${ARROW}${NC} Fetching nodes"
    local nodes_response
    nodes_response=$(make_api_request GET "/api/nodes")

    local bridge_node_uuid
    bridge_node_uuid=$(echo "$nodes_response" | jq -r \
        --arg profile_uuid "$bridge_profile_uuid" \
        '.response[] | select(.configProfile.activeConfigProfileUuid == $profile_uuid) | .uuid')

    echo -e "${GRAY}  ${ARROW}${NC} Fetching hosts"
    local hosts_response
    hosts_response=$(make_api_request GET "/api/hosts")

    local bridge_hosts
    bridge_hosts=$(echo "$hosts_response" | jq -c \
        --arg profile_uuid "$bridge_profile_uuid" \
        '[.response[] | select(.inbound.configProfileUuid == $profile_uuid)]')

    local bridge_profile_data
    bridge_profile_data=$(echo "$profiles_response" | jq -c \
        '.response.configProfiles[] | select(.name == "Bridge")')

    local stealconfig_inbound_uuid
    stealconfig_inbound_uuid=$(echo "$profiles_response" | jq -r \
        '.response.configProfiles[] | select(.name == "StealConfig") | .inbounds[0].uuid')

    echo -e "${GREEN}${CHECK}${NC} Data fetched"

    echo
    echo -e "${GREEN}Cleaning up panel${NC}"
    echo -e "${GREEN}=================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Restoring bridge hosts to direct connection..."
    local host
    for host in $(echo "$bridge_hosts" | jq -r '.[] | @base64'); do
        local host_data
        host_data=$(echo "$host" | base64 -d)

        local host_uuid
        host_uuid=$(echo "$host_data" | jq -r '.uuid')
        local host_remark
        host_remark=$(echo "$host_data" | jq -r '.remark')
        local host_inbound_uuid
        host_inbound_uuid=$(echo "$host_data" | jq -r '.inbound.configProfileInboundUuid')

        local inbound_port
        inbound_port=$(echo "$bridge_profile_data" | jq -r \
            --arg uuid "$host_inbound_uuid" \
            '.inbounds[] | select(.uuid == $uuid) | .port')

        local foreign_domain
        foreign_domain=$(echo "$bridge_config" | jq -r \
            --arg tag "VLESS_OUTBOUND_${inbound_port}" \
            '.outbounds[] | select(.tag == $tag) | .settings.vnext[0].address')

        if [ -z "$foreign_domain" ] || [ "$foreign_domain" = "null" ]; then
            echo -e "${YELLOW}  ${WARNING}${NC} Could not resolve domain for host ${host_remark}, skipping"
            continue
        fi

        echo -e "${GRAY}  ${ARROW}${NC} Restoring ${host_remark} ${ARROW} ${foreign_domain}"
        local host_patch
        host_patch=$(jq -n \
            --arg uuid "$host_uuid" \
            --arg address "$foreign_domain" \
            --arg sni "$foreign_domain" \
            --arg profile_uuid "$stealconfig_uuid" \
            --arg inbound_uuid "$stealconfig_inbound_uuid" \
            '{
                uuid: $uuid,
                address: $address,
                port: 443,
                sni: $sni,
                inbound: {
                    configProfileUuid: $profile_uuid,
                    configProfileInboundUuid: $inbound_uuid
                }
            }')

        make_api_request PATCH "/api/hosts" "$host_patch" > /dev/null 2>&1
    done
    echo -e "${GREEN}${CHECK}${NC} Hosts restored"

    echo
    echo -e "${CYAN}${INFO}${NC} Removing bridge inbounds from squad..."
    local squad_response
    squad_response=$(make_api_request GET "/api/internal-squads")

    local squad_uuid
    squad_uuid=$(echo "$squad_response" | jq -r '.response.internalSquads[0].uuid')

    if [ -n "$squad_uuid" ] && [ "$squad_uuid" != "null" ]; then
        local remaining_inbounds
        remaining_inbounds=$(echo "$squad_response" | jq -c \
            --argjson bridge_uuids "$bridge_inbound_uuids" \
            --arg uuid "$squad_uuid" \
            '[.response.internalSquads[] | select(.uuid == $uuid) | .inbounds[].uuid]
             | map(select(. as $id | $bridge_uuids | index($id) | not))')

        echo -e "${GRAY}  ${ARROW}${NC} Updating squad inbounds"
        local squad_update
        squad_update=$(jq -n \
            --arg squad_uuid "$squad_uuid" \
            --argjson inbounds "$remaining_inbounds" \
            '{ uuid: $squad_uuid, inbounds: $inbounds }')

        make_api_request PATCH "/api/internal-squads" "$squad_update" > /dev/null 2>&1
    fi
    echo -e "${GREEN}${CHECK}${NC} Squad updated"

    echo
    if [ -n "$stealconfig_uuid" ] && [ "$stealconfig_uuid" != "null" ]; then
        echo -e "${CYAN}${INFO}${NC} Restoring StealConfig server names..."

        echo -e "${GRAY}  ${ARROW}${NC} Removing bridge SNIs from StealConfig"
        local updated_config
        updated_config=$(echo "$stealconfig_config" | jq -c \
            --argjson bridge_snis "$bridge_snis" \
            '.inbounds[0].streamSettings.realitySettings.serverNames |=
                map(select(. as $s | $bridge_snis | index($s) | not))')

        local patch_data
        patch_data=$(jq -n \
            --arg uuid "$stealconfig_uuid" \
            --argjson config "$updated_config" \
            '{ uuid: $uuid, config: $config }')

        make_api_request PATCH "/api/config-profiles" "$patch_data" > /dev/null 2>&1
        echo -e "${GREEN}${CHECK}${NC} StealConfig restored"
    fi

    echo
    if [ -n "$bridge_node_uuid" ] && [ "$bridge_node_uuid" != "null" ]; then
        echo -e "${CYAN}${INFO}${NC} Deleting bridge node..."

        echo -e "${GRAY}  ${ARROW}${NC} Sending delete request"
        local response
        response=$(make_api_request DELETE "/api/nodes/${bridge_node_uuid}")
        if echo "$response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
            echo -e "${GREEN}${CHECK}${NC} Bridge node deleted"
        else
            echo -e "${RED}${CROSS}${NC} Failed to delete bridge node: $response"
        fi
    fi

    echo
    echo -e "${CYAN}${INFO}${NC} Deleting bridge config profile..."

    echo -e "${GRAY}  ${ARROW}${NC} Sending delete request"
    local response
    response=$(make_api_request DELETE "/api/config-profiles/${bridge_profile_uuid}")
    if echo "$response" | jq -e '.response.isDeleted' > /dev/null 2>&1; then
        echo -e "${GREEN}${CHECK}${NC} Bridge config profile deleted"
    else
        echo -e "${RED}${CROSS}${NC} Failed to delete config profile: $response"
    fi

    echo
    echo -e "${GREEN}Cleaning up server${NC}"
    echo -e "${GREEN}==================${NC}"
    echo

    echo -e "${CYAN}${INFO}${NC} Stopping Docker services..."
    if [ -f /opt/remnabridge/docker-compose.yml ]; then
        echo -e "${GRAY}  ${ARROW}${NC} Running docker compose down"
        cd /opt/remnabridge && docker compose down > /dev/null 2>&1 || true
        echo -e "${GREEN}${CHECK}${NC} Docker services stopped"
    else
        echo -e "${GRAY}  ${ARROW}${NC} No Docker services found, skipping"
    fi

    echo
    echo -e "${CYAN}${INFO}${NC} Cleaning up files..."
    echo -e "${GRAY}  ${ARROW}${NC} Removing /opt/remnabridge"
    rm -rf /opt/remnabridge
    echo -e "${GRAY}  ${ARROW}${NC} Removing ${DIR_BRIDGE}"
    rm -rf "${DIR_BRIDGE}"
    echo -e "${GREEN}${CHECK}${NC} Files removed"

    echo
    echo -e "${PURPLE}=================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Bridge removed"
    echo -e "${PURPLE}=================${NC}"
    echo
}

#==================
# MAIN ENTRY POINT
#==================

main() {
    log_entry
    check_root

    show_main_menu
    read SETUP_TYPE

    case $SETUP_TYPE in
        1)
            echo
            echo -e "${PURPLE}=============${NC}"
            echo -e "${WHITE}Bridge Setup${NC}"
            echo -e "${PURPLE}=============${NC}"
            echo

            input_panel_ip
            input_panel_url
            input_api_token
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
            input_foreign_domain
            input_reality_sni
            input_host_remark

            add_node_to_bridge
            ;;
        3)
            if [ "$BRIDGE_INSTALLED" = true ]; then
                echo
                echo -e "${PURPLE}==============${NC}"
                echo -e "${WHITE}Remove Bridge${NC}"
                echo -e "${PURPLE}==============${NC}"
                echo

                input_panel_url
                input_api_token

                remove_bridge
            else
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting..."
                exit 0
            fi
            ;;
        4)
            if [ "$BRIDGE_INSTALLED" = true ]; then
                echo
                echo -e "${YELLOW}${WARNING}${NC} Exiting..."
                exit 0
            else
                echo
                echo -e "${RED}${CROSS}${NC} Invalid option. Please enter 1-3."
                exit 1
            fi
            ;;
        *)
            local max_option=3
            [ "$BRIDGE_INSTALLED" = true ] && max_option=4
            echo
            echo -e "${RED}${CROSS}${NC} Invalid option. Please enter 1-${max_option}."
            exit 1
            ;;
    esac
}

main
exit 0
