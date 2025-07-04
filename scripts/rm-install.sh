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

# Main menu
echo
echo -e "${PURPLE}==============================${NC}"
echo -e "${WHITE}REMNAWAVE INSTALLATION SCRIPT${NC}"
echo -e "${PURPLE}==============================${NC}"
echo
echo -e "${CYAN}Please select installation type:${NC}"
echo
echo -e "${GREEN}1.${NC} Install Panel"
echo -e "${GREEN}2.${NC} Install Node"
echo -e "${RED}3.${NC} Exit"
echo
echo -ne "${CYAN}Enter your choice (1, 2, or 3): ${NC}"
read INSTALL_TYPE

case $INSTALL_TYPE in
    1)
        echo
        echo -e "${GREEN}Starting Panel installation...${NC}"
        echo
        ;;
    2)
        echo
        echo -e "${GREEN}Starting Node installation...${NC}"
        echo
        ;;
    3)
        echo
        echo -e "${YELLOW}Exiting installation. Goodbye!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice. Please select 1, 2, or 3.${NC}"
        exit 1
        ;;
esac

# Pannel Installation

if [ "$INSTALL_TYPE" = "1" ]; then

# Remnawave setup script

echo -e "${PURPLE}====================${NC}"
echo -e "${NC}PANNEL INSTALLATION${NC}"
echo -e "${PURPLE}====================${NC}"
echo

set -e

echo -e "${GREEN}=========================${NC}"
echo -e "${NC}1. Environment variables${NC}"
echo -e "${GREEN}=========================${NC}"
echo

# Interactive input for variables
echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
read PANEL_DOMAIN
while [[ -z "$PANEL_DOMAIN" ]]; do
    echo -e "${RED}Panel domain cannot be empty!${NC}"
    echo -ne "${CYAN}Panel domain (e.g., example.com): ${NC}"
read PANEL_DOMAIN
done

echo -ne "${CYAN}Subscription domain (e.g., example.com): ${NC}"
read SUB_DOMAIN
while [[ -z "$SUB_DOMAIN" ]]; do
    echo -e "${RED}Subscription domain cannot be empty!${NC}"
    echo -ne "${CYAN}Subscription domain (e.g., example.com): ${NC}"
read SUB_DOMAIN
done

echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
read SELFSTEAL_DOMAIN
while [[ -z "$SELFSTEAL_DOMAIN" ]]; do
    echo -e "${RED}Self-steal domain cannot be empty!${NC}"
    echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
read SELFSTEAL_DOMAIN
done

echo -ne "${CYAN}Cloudflare Email: ${NC}"
read CLOUDFLARE_EMAIL
while [[ -z "$CLOUDFLARE_EMAIL" ]]; do
    echo -e "${RED}Cloudflare Email cannot be empty!${NC}"
    echo -ne "${CYAN}Cloudflare Email: ${NC}"
read CLOUDFLARE_EMAIL
done

echo -ne "${CYAN}Cloudflare API Key: ${NC}"
read CLOUDFLARE_API_KEY
while [[ -z "$CLOUDFLARE_API_KEY" ]]; do
    echo -e "${RED}Cloudflare API Key cannot be empty!${NC}"
    echo -ne "${CYAN}Cloudflare API Key: ${NC}"
read CLOUDFLARE_API_KEY
done

# Generate random values
echo
echo -e "${YELLOW}Generating secure random values...${NC}"
SUPERADMIN_USERNAME=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 8 | head -n 1)

password=""
password+=$(head /dev/urandom | tr -dc 'A-Z' | head -c 1)
password+=$(head /dev/urandom | tr -dc 'a-z' | head -c 1)
password+=$(head /dev/urandom | tr -dc '0-9' | head -c 1)
password+=$(head /dev/urandom | tr -dc '!@#%^&*()_+' | head -c 3)
password+=$(head /dev/urandom | tr -dc 'A-Za-z0-9!@#%^&*()_+' | head -c $((24 - 6)))
SUPERADMIN_PASSWORD=$(echo "$password" | fold -w1 | shuf | tr -d '\n')

cookies_random1=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 8 | head -n 1)
cookies_random2=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 8 | head -n 1)
METRICS_USER=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 8 | head -n 1)
METRICS_PASS=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 8 | head -n 1)
JWT_AUTH_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
JWT_API_TOKENS_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
WEBHOOK_SECRET_HEADER=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64)

POSTGRES_USER=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 10 | head -n 1)
pg_password=""
pg_password+=$(head /dev/urandom | tr -dc 'A-Z' | head -c 2)
pg_password+=$(head /dev/urandom | tr -dc 'a-z' | head -c 2)
pg_password+=$(head /dev/urandom | tr -dc '0-9' | head -c 2)
pg_password+=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c $((16 - 6)))
POSTGRES_PASSWORD=$(echo "$pg_password" | fold -w1 | shuf | tr -d '\n')
POSTGRES_DB="remnawave"

# Create variables file for persistence
cat > remnawave-vars.sh << EOF
# remnawave-vars.sh
export PANEL_DOMAIN="$PANEL_DOMAIN"
export SUB_DOMAIN="$SUB_DOMAIN"
export SELFSTEAL_DOMAIN="$SELFSTEAL_DOMAIN"
export CLOUDFLARE_API_KEY="$CLOUDFLARE_API_KEY"
export CLOUDFLARE_EMAIL="$CLOUDFLARE_EMAIL"

# Generated variables
export SUPERADMIN_USERNAME="$SUPERADMIN_USERNAME"
export SUPERADMIN_PASSWORD="$SUPERADMIN_PASSWORD"
export cookies_random1="$cookies_random1"
export cookies_random2="$cookies_random2"
export METRICS_USER="$METRICS_USER"
export METRICS_PASS="$METRICS_PASS"
export JWT_AUTH_SECRET="$JWT_AUTH_SECRET"
export JWT_API_TOKENS_SECRET="$JWT_API_TOKENS_SECRET"
export WEBHOOK_SECRET_HEADER="$WEBHOOK_SECRET_HEADER"

# PostgreSQL credentials
export POSTGRES_USER="$POSTGRES_USER"
export POSTGRES_PASSWORD="$POSTGRES_PASSWORD"
export POSTGRES_DB="$POSTGRES_DB"
EOF

echo
echo -e "${GREEN}Variables saved to remnawave-vars.sh${NC}"
echo

# Load environment variables
source remnawave-vars.sh

echo -e "${GREEN}------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Environment variables configured!"
echo -e "${GREEN}------------------------------------${NC}"
echo

echo -e "${GREEN}=======================${NC}"
echo -e "${NC}2. Installing packages${NC}"
echo -e "${GREEN}=======================${NC}"
echo

# Update package list and install basic packages
echo "Installing basic packages..."
apt-get update -y > /dev/null 2>&1
apt-get install -y ca-certificates curl jq ufw wget gnupg unzip nano dialog git certbot python3-certbot-dns-cloudflare unattended-upgrades locales dnsutils coreutils grep gawk > /dev/null 2>&1

# Configure logrotate for panel
echo
echo "Configuring logrotate for panel logs..."
mkdir -p /var/log/remnawave 2>/dev/null || true
apt-get install -y logrotate > /dev/null 2>&1 || true

cat > /etc/logrotate.d/remnawave <<'EOL' 2>/dev/null || true
/var/lib/docker/containers/*/*.log {
    size 100M
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
    delaycompress
}
/var/log/letsencrypt/*.log {
    size 10M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
/usr/local/remnawave_reverse/cron_jobs.log {
    size 10M
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
EOL

# Install and enable cron
echo
echo "Installing and enabling cron..."
apt-get install -y cron > /dev/null 2>&1
systemctl start cron > /dev/null 2>&1
systemctl enable cron > /dev/null 2>&1

# Configure locales
echo
echo "Configuring locales..."
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen 2>/dev/null
locale-gen > /dev/null 2>&1
update-locale LANG=en_US.UTF-8 > /dev/null 2>&1

# Set timezone
echo
echo "Setting timezone to Europe/Moscow..."
timedatectl set-timezone Europe/Moscow > /dev/null 2>&1

# Add Docker repository
echo
echo "Adding Docker repository..."
install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null 2>&1
chmod a+r /etc/apt/keyrings/docker.asc > /dev/null 2>&1
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1

# Install Docker
echo
echo "Installing Docker..."
apt-get update > /dev/null 2>&1
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1

# Configure TCP BBR
echo
echo "Configuring TCP BBR..."
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf 2>/dev/null
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf 2>/dev/null
sysctl -p > /dev/null 2>&1

# Configure UFW firewall
echo
echo "Configuring UFW firewall..."
ufw --force reset > /dev/null 2>&1
ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1

# Configure unattended upgrades
echo
echo "Configuring unattended upgrades..."
echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections > /dev/null 2>&1
dpkg-reconfigure -f noninteractive unattended-upgrades > /dev/null 2>&1
systemctl restart unattended-upgrades > /dev/null 2>&1

echo
echo -e "${GREEN}----------------------------------${NC}"
echo -e "${GREEN}✓${NC} Package installation completed!"
echo -e "${GREEN}----------------------------------${NC}"
echo

echo -e "${GREEN}=======================================${NC}"
echo -e "${NC}3. Creating structure and certificates${NC}"
echo -e "${GREEN}=======================================${NC}"
echo

# Create directory structure
echo "Creating directory structure..."
mkdir -p /opt/remnawave && cd /opt/remnawave

# Check Cloudflare API
echo
echo "Checking Cloudflare API..."
if [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; then
    api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "Authorization: Bearer ${CLOUDFLARE_API_KEY}" --header "Content-Type: application/json")
else
    api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "X-Auth-Key: ${CLOUDFLARE_API_KEY}" --header "X-Auth-Email: ${CLOUDFLARE_EMAIL}" --header "Content-Type: application/json")
fi

# Generate certificates
echo
echo "Setting up Cloudflare credentials..."
mkdir -p ~/.secrets/certbot
if [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; then
    cat > ~/.secrets/certbot/cloudflare.ini <<EOL
dns_cloudflare_api_token = $CLOUDFLARE_API_KEY
EOL
else
    cat > ~/.secrets/certbot/cloudflare.ini <<EOL
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_key = $CLOUDFLARE_API_KEY
EOL
fi
chmod 600 ~/.secrets/certbot/cloudflare.ini

# Extract base domains
echo
echo "Extracting base domains..."
PANEL_BASE_DOMAIN=$(echo "$PANEL_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
SUB_BASE_DOMAIN=$(echo "$SUB_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')

# Generate certificate for panel domain if not exists
echo
echo "Checking certificate for panel domain..."
if [ ! -d "/etc/letsencrypt/live/$PANEL_BASE_DOMAIN" ]; then
    echo "Generating certificate for $PANEL_BASE_DOMAIN..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 10 \
        -d "$PANEL_BASE_DOMAIN" \
        -d "*.$PANEL_BASE_DOMAIN" \
        --email "$CLOUDFLARE_EMAIL" \
        --agree-tos \
        --non-interactive \
        --key-type ecdsa \
        --elliptic-curve secp384r1
else
    echo "Certificate for $PANEL_BASE_DOMAIN already exists, skipping..."
fi

# Generate certificate for sub domain if not exists
echo
echo "Checking certificate for sub domain..."
if [ ! -d "/etc/letsencrypt/live/$SUB_BASE_DOMAIN" ]; then
    echo "Generating certificate for $SUB_BASE_DOMAIN..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 10 \
        -d "$SUB_BASE_DOMAIN" \
        -d "*.$SUB_BASE_DOMAIN" \
        --email "$CLOUDFLARE_EMAIL" \
        --agree-tos \
        --non-interactive \
        --key-type ecdsa \
        --elliptic-curve secp384r1
else
    echo "Certificate for $SUB_BASE_DOMAIN already exists, skipping..."
fi

# Configure renewal hooks and cron
echo
echo "Configuring certificate renewal..."
echo "renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'" >> /etc/letsencrypt/renewal/$PANEL_BASE_DOMAIN.conf
echo "renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'" >> /etc/letsencrypt/renewal/$SUB_BASE_DOMAIN.conf
(crontab -u root -l 2>/dev/null; echo "0 5 1 */2 * /usr/bin/certbot renew --quiet >> /usr/local/remnawave_reverse/cron_jobs.log 2>&1") | crontab -u root -

echo
echo -e "${GREEN}----------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Structure and certificates setup completed!"
echo -e "${GREEN}----------------------------------------------${NC}"
echo

echo -e "${GREEN}================================${NC}"
echo -e "${NC}4. Creating configuration files${NC}"
echo -e "${GREEN}================================${NC}"
echo

# Move variables file to configuration directory
echo "Moving variables file..."
echo
mv /root/remnawave-vars.sh /opt/remnawave/

# Create .env file
echo "Creating .env file..."
cat > /opt/remnawave/.env <<EOL
### APP ###
APP_PORT=3000
METRICS_PORT=3001

### API ###
# Possible values: max (start instances on all cores), number (start instances on number of cores), -1 (start instances on all cores - 1)
# !!! Do not set this value more than physical cores count in your machine !!!
# Review documentation: https://remna.st/docs/install/environment-variables#scaling-api
API_INSTANCES=1

### DATABASE ###
# FORMAT: postgresql://{user}:{password}@{host}:{port}/{database}
DATABASE_URL="postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@remnawave-db:5432/remnawave"

### REDIS ###
REDIS_HOST=remnawave-redis
REDIS_PORT=6379

### JWT ###
JWT_AUTH_SECRET=$JWT_AUTH_SECRET
JWT_API_TOKENS_SECRET=$JWT_API_TOKENS_SECRET

### TELEGRAM NOTIFICATIONS ###
IS_TELEGRAM_NOTIFICATIONS_ENABLED=false
TELEGRAM_BOT_TOKEN=change_me
TELEGRAM_NOTIFY_USERS_CHAT_ID=change_me
TELEGRAM_NOTIFY_NODES_CHAT_ID=change_me

### Telegram Oauth (Login with Telegram)
### Docs https://remna.st/docs/features/telegram-oauth
### true/false
TELEGRAM_OAUTH_ENABLED=false
### Array of Admin Chat Ids. These ids will be allowed to login.
TELEGRAM_OAUTH_ADMIN_IDS=[123, 321]

# Optional
# Only set if you want to use topics
TELEGRAM_NOTIFY_USERS_THREAD_ID=
TELEGRAM_NOTIFY_NODES_THREAD_ID=

### FRONT_END ###
# Used by CORS, you can leave it as * or place your domain there
FRONT_END_DOMAIN=$PANEL_DOMAIN

### SUBSCRIPTION PUBLIC DOMAIN ###
### DOMAIN, WITHOUT HTTP/HTTPS, DO NOT ADD / AT THE END ###
### Used in "profile-web-page-url" response header and in UI/API ###
### Review documentation: https://remna.st/docs/install/environment-variables#domains
SUB_PUBLIC_DOMAIN=$SUB_DOMAIN

### If CUSTOM_SUB_PREFIX is set in @remnawave/subscription-page, append the same path to SUB_PUBLIC_DOMAIN. Example: SUB_PUBLIC_DOMAIN=sub-page.example.com/sub ###

### SWAGGER ###
SWAGGER_PATH=/docs
SCALAR_PATH=/scalar
IS_DOCS_ENABLED=true

### PROMETHEUS ###
### Metrics are available at /api/metrics
METRICS_USER=$METRICS_USER
METRICS_PASS=$METRICS_PASS

### WEBHOOK ###
WEBHOOK_ENABLED=true
### Only https:// is allowed
WEBHOOK_URL=https://bot.$PANEL_DOMAIN/notify_user
### This secret is used to sign the webhook payload, must be exact 64 characters. Only a-z, 0-9, A-Z are allowed.
WEBHOOK_SECRET_HEADER=$WEBHOOK_SECRET_HEADER

### HWID DEVICE DETECTION AND LIMITATION ###
# Don't enable this if you don't know what you are doing.
# Review documentation before enabling this feature.
# https://remna.st/docs/features/hwid-device-limit/
HWID_DEVICE_LIMIT_ENABLED=false
HWID_FALLBACK_DEVICE_LIMIT=5
HWID_MAX_DEVICES_ANNOUNCE="You have reached the maximum number of devices for your subscription."

### HWID DEVICE DETECTION PROVIDER ID ###
# Apps, which currently support this feature:
# - Happ
PROVIDER_ID="123456"

### Bandwidth usage reached notifications
BANDWIDTH_USAGE_NOTIFICATIONS_ENABLED=false
# Only in ASC order (example: [60, 80]), must be valid array of integer(min: 25, max: 95) numbers. No more than 5 values.
BANDWIDTH_USAGE_NOTIFICATIONS_THRESHOLD=[60, 80]

### CLOUDFLARE ###
# USED ONLY FOR docker-compose-prod-with-cf.yml
# NOT USED BY THE APP ITSELF
CLOUDFLARE_TOKEN=ey...

### Database ###
### For Postgres Docker container ###
# NOT USED BY THE APP ITSELF
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=remnawave
EOL

# Create docker-compose.yml file
echo
echo "Creating docker-compose.yml file..."
cat > /opt/remnawave/docker-compose.yml <<EOL
services:
  remnawave-db:
    image: postgres:17
    container_name: 'remnawave-db'
    hostname: remnawave-db
    restart: always
    env_file:
      - .env
    environment:
      - POSTGRES_USER=\${POSTGRES_USER}
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
      - POSTGRES_DB=\${POSTGRES_DB}
      - TZ=UTC
    ports:
      - '127.0.0.1:6767:5432'
    volumes:
      - remnawave-db-data:/var/lib/postgresql/data
    networks:
      - remnawave-network
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U \$\${POSTGRES_USER} -d \$\${POSTGRES_DB}']
      interval: 3s
      timeout: 10s
      retries: 3
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave:
    image: remnawave/backend:latest
    container_name: remnawave
    hostname: remnawave
    restart: always
    env_file:
      - .env
    ports:
      - '127.0.0.1:3000:3000'
    networks:
      - remnawave-network
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_healthy
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-redis:
    image: valkey/valkey:8.1.1-alpine
    container_name: remnawave-redis
    hostname: remnawave-redis
    restart: always
    networks:
      - remnawave-network
    volumes:
      - remnawave-redis-data:/data
    healthcheck:
      test: [ "CMD", "valkey-cli", "ping" ]
      interval: 3s
      timeout: 10s
      retries: 3
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-nginx:
    image: nginx:1.26
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    restart: always
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt/live/$PANEL_BASE_DOMAIN/fullchain.pem:/etc/nginx/ssl/$PANEL_DOMAIN/fullchain.pem:ro
      - /etc/letsencrypt/live/$PANEL_BASE_DOMAIN/privkey.pem:/etc/nginx/ssl/$PANEL_DOMAIN/privkey.pem:ro
      - /etc/letsencrypt/live/$SUB_BASE_DOMAIN/fullchain.pem:/etc/nginx/ssl/$SUB_DOMAIN/fullchain.pem:ro
      - /etc/letsencrypt/live/$SUB_BASE_DOMAIN/privkey.pem:/etc/nginx/ssl/$SUB_DOMAIN/privkey.pem:ro
      - ./redirect.html:/opt/remnawave/redirect.html:ro
    network_mode: host
    depends_on:
      - remnawave
      - remnawave-subscription-page
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnawave-subscription-page:
    image: remnawave/subscription-page:latest
    container_name: remnawave-subscription-page
    hostname: remnawave-subscription-page
    restart: always
    environment:
      - REMNAWAVE_PANEL_URL=http://remnawave:3000
      - APP_PORT=3010
      - META_TITLE=Remnawave Subscription
      - META_DESCRIPTION=page
    ports:
      - '127.0.0.1:3010:3010'
    networks:
      - remnawave-network
    volumes:
      - ./index.html:/opt/app/frontend/index.html
      - ./assets:/opt/app/frontend/assets
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
    external: false

volumes:
  remnawave-db-data:
    driver: local
    external: false
    name: remnawave-db-data
  remnawave-redis-data:
    driver: local
    external: false
    name: remnawave-redis-data
EOL

# Download index.html
echo
echo "Downloading index.html..."
wget -P /opt/remnawave/ https://raw.githubusercontent.com/supermegaelf/rm-files/main/pages/sub-redirect/index.html > /dev/null 2>&1
sed -i "s/redirect\.example\.com/redirect.$PANEL_DOMAIN/g" /opt/remnawave/index.html

# Download redirect.html
echo
echo "Downloading redirect.html..."
wget -P /opt/remnawave/ https://raw.githubusercontent.com/supermegaelf/rm-files/main/pages/redirect/redirect.html > /dev/null 2>&1
echo

echo -e "${GREEN}--------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Configuration files created successfully!"
echo -e "${GREEN}--------------------------------------------${NC}"
echo

echo -e "${GREEN}===============================================${NC}"
echo -e "${NC}5. Creating nginx.conf and starting containers${NC}"
echo -e "${GREEN}===============================================${NC}"
echo

# Create nginx.conf file
echo "Creating nginx.conf file..."
cat > /opt/remnawave/nginx.conf <<EOL
upstream remnawave {
    server 127.0.0.1:3000;
}

upstream json {
    server 127.0.0.1:3010;
}

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

map \$http_cookie \$auth_cookie {
    default 0;
    "~*${cookies_random1}=${cookies_random2}" 1;
}

map \$arg_${cookies_random1} \$auth_query {
    default 0;
    "${cookies_random2}" 1;
}

map "\$auth_cookie\$auth_query" \$authorized {
    "~1" 1;
    default 0;
}

map \$arg_${cookies_random1} \$set_cookie_header {
    "${cookies_random2}" "${cookies_random1}=${cookies_random2}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000";
    default "";
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;

server {
    server_name $PANEL_DOMAIN;
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$PANEL_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$PANEL_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$PANEL_DOMAIN/fullchain.pem";

    add_header Set-Cookie \$set_cookie_header;

    location /api/ {
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location / {
        if (\$authorized = 0) {
            return 404;
        }
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

server {
    server_name $SUB_DOMAIN;
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$SUB_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$SUB_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$SUB_DOMAIN/fullchain.pem";

    location / {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_intercept_errors on;
        error_page 400 404 500 502 @redirect;
    }

    location @redirect {
        return 404;
    }
}

server {
    server_name redirect.$PANEL_DOMAIN;
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$PANEL_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$PANEL_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$PANEL_DOMAIN/fullchain.pem";

    root /opt/remnawave;
    index redirect.html;

    location / {
        try_files \$uri \$uri/ /redirect.html;
    }
}

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOL

# Start containers
echo
echo "Starting Docker containers..."
cd /opt/remnawave
docker compose up -d
sleep 20

# Wait for API to be ready
echo
echo "Waiting for API to be ready..."
until curl -s "http://127.0.0.1:3000/api/auth/register" \
    --header 'X-Forwarded-For: 127.0.0.1' \
    --header 'X-Forwarded-Proto: https' \
    > /dev/null; do
    sleep 10
done

echo
echo -e "${GREEN}--------------------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Nginx configured and containers started successfully!"
echo -e "${GREEN}--------------------------------------------------------${NC}"
echo

echo -e "${GREEN}==========================================${NC}"
echo -e "${NC}6. Registration and customization via API${NC}"
echo -e "${GREEN}==========================================${NC}"
echo

# Set API URL
domain_url="127.0.0.1:3000"

# Registration
echo "Registering superadmin user..."
register_response=$(curl -s -X POST "http://$domain_url/api/auth/register" \
    -H "Authorization: Bearer " \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https" \
    -d "{\"username\":\"$SUPERADMIN_USERNAME\",\"password\":\"$SUPERADMIN_PASSWORD\"}")

# Extract token
token=$(echo "$register_response" | jq -r '.response.accessToken')

# Get public key
echo
echo "Getting public key..."
api_response=$(curl -s -X GET "http://$domain_url/api/keygen" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https")

# Extract public key
pubkey=$(echo "$api_response" | jq -r '.response.pubKey')

# Generate Xray keys
echo
echo "Generating Xray keys..."
docker run --rm ghcr.io/xtls/xray-core x25519 > /tmp/xray_keys.txt 2>&1
keys=$(cat /tmp/xray_keys.txt)
rm -f /tmp/xray_keys.txt
private_key=$(echo "$keys" | grep "Private key:" | awk '{print $3}')
public_key=$(echo "$keys" | grep "Public key:" | awk '{print $3}')

# Create Xray configuration
echo
echo "Creating Xray configuration..."

# Generate necessary parameters
short_id=$(openssl rand -hex 8)
client_id=$(cat /proc/sys/kernel/random/uuid)
config_file="/opt/remnawave/config.json"

cat > "$config_file" <<EOL
{
  	"log": {
    	"error": "/var/log/remnanode/error.log",
    	"access": "/var/log/remnanode/access.log",
    	"loglevel": "warning"
  	},
    "dns": {
        "queryStrategy": "ForceIPv4",
        "servers": [
            {
                "address": "https://dns.google/dns-query",
                "skipFallback": false
            }
        ]
    },
    "inbounds": [
        {
            "tag": "VLESS Reality Steal Oneself",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$client_id",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "/dev/shm/nginx.sock",
                    "show": false,
                    "xver": 1,
                    "spiderX": "",
                    "shortIds": [
                        "$short_id"
                    ],
                    "publicKey": "$public_key",
                    "privateKey": "$private_key",
                    "serverNames": [
                        "$SELFSTEAL_DOMAIN"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "tag": "DIRECT",
            "protocol": "freedom"
        },
        {
            "tag": "BLOCK",
            "protocol": "blackhole"
        }
    ],
    "routing": {
        "rules": [
            {
                "ip": [
                    "geoip:private"
                ],
                "type": "field",
                "outboundTag": "BLOCK"
            },
            {
                "type": "field",
                "protocol": [
                    "bittorrent"
                ],
                "outboundTag": "BLOCK"
            }
        ]
    }
}
EOL

# Update Xray configuration via API
echo
echo "Updating Xray configuration..."
new_config=$(cat "$config_file")
update_response=$(curl -s -X PUT "http://$domain_url/api/xray" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https" \
    -d "$new_config")

# Remove temporary config file
rm -f "$config_file"

# Create API token for bot
echo
echo "Creating API token for bot..."
token_response=$(curl -s -X POST "http://$domain_url/api/tokens" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https" \
    -d '{
        "tokenName": "Bot API Token",
        "tokenDescription": "API token for bot integration and webhook notifications"
    }')

REMNAWAVE_TOKEN=$(echo "$token_response" | jq -r '.response.token')

if [ "$REMNAWAVE_TOKEN" != "null" ] && [ -n "$REMNAWAVE_TOKEN" ]; then
    
    # Add token to variables file
    echo "" >> /opt/remnawave/remnawave-vars.sh
    echo "# API Token" >> /opt/remnawave/remnawave-vars.sh
    echo "export REMNAWAVE_TOKEN=\"$REMNAWAVE_TOKEN\"" >> /opt/remnawave/remnawave-vars.sh
else
    echo "Failed to create API token"
    echo "Response: $token_response"
fi

echo
echo -e "${GREEN}-------------------------------${NC}"
echo -e "${GREEN}✓${NC} API configuration completed!"
echo -e "${GREEN}-------------------------------${NC}"
echo

echo -e "${GREEN}===============================================${NC}"
echo -e "${NC}7. Creating node, host and final configuration${NC}"
echo -e "${GREEN}===============================================${NC}"

# Create node
echo
echo "Creating node..."
node_data=$(cat <<EOF
{
    "name": "VLESS Reality Steal Oneself",
    "address": "$SELFSTEAL_DOMAIN",
    "port": 2222,
    "isTrafficTrackingActive": false,
    "trafficLimitBytes": 0,
    "notifyPercent": 0,
    "trafficResetDay": 31,
    "excludedInbounds": [],
    "countryCode": "XX",
    "consumptionMultiplier": 1.0
}
EOF
)

node_response=$(curl -s -X POST "http://$domain_url/api/nodes" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https" \
    -d "$node_data")

# Get inbound UUID
echo
echo "Getting inbound UUID..."
inbounds_response=$(curl -s -X GET "http://$domain_url/api/inbounds" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https")

inbound_uuid=$(echo "$inbounds_response" | jq -r '.response[0].uuid')

# Create host
echo
echo "Creating host..."
host_data=$(cat <<EOF
{
    "inboundUuid": "$inbound_uuid",
    "remark": "Steal",
    "address": "$SELFSTEAL_DOMAIN",
    "port": 443,
    "path": "",
    "sni": "$SELFSTEAL_DOMAIN",
    "host": "$SELFSTEAL_DOMAIN",
    "alpn": null,
    "fingerprint": "chrome",
    "allowInsecure": false,
    "isDisabled": false
}
EOF
)

host_response=$(curl -s -X POST "http://$domain_url/api/hosts" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Host: $PANEL_DOMAIN" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Forwarded-Proto: https" \
    -d "$host_data")

# Restart containers
echo
echo "Restarting containers..."
cd /opt/remnawave
docker compose down
sleep 1
docker compose up -d

# Install alias
echo
echo "Installing remnawave_reverse alias..."
mkdir -p /usr/local/remnawave_reverse/
wget -q -O /usr/local/remnawave_reverse/remnawave_reverse "https://raw.githubusercontent.com/eGamesAPI/remnawave-reverse-proxy/refs/heads/main/install_remnawave.sh"
chmod +x /usr/local/remnawave_reverse/remnawave_reverse
ln -sf /usr/local/remnawave_reverse/remnawave_reverse /usr/local/bin/remnawave_reverse

bashrc_file="/etc/bash.bashrc"
alias_line="alias rr='remnawave_reverse'"
echo "$alias_line" >> "$bashrc_file"

echo
echo -e "${GREEN}------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Remnawave setup completed successfully!"
echo -e "${GREEN}------------------------------------------${NC}"
echo
echo -e "${CYAN}Remnawave URL:${NC}"
echo "https://${PANEL_DOMAIN}/auth/login?${cookies_random1}=${cookies_random2}"
echo
echo -e "${CYAN}Pannel Credentials:${NC}"
echo "$SUPERADMIN_USERNAME"
echo "$SUPERADMIN_PASSWORD"
echo
echo -e "${CYAN}To check logs, use:${NC}"
echo "cd /opt/remnawave && docker compose logs -f"
echo

# Node Installation

elif [ "$INSTALL_TYPE" = "2" ]; then

# Remnawave Node setup script

echo -e "${PURPLE}==================${NC}"
echo -e "${NC}NODE INSTALLATION${NC}"
echo -e "${PURPLE}==================${NC}"
echo

set -e

echo -e "${GREEN}=========================${NC}"
echo -e "${NC}1. Environment variables${NC}"
echo -e "${GREEN}=========================${NC}"
echo

# Interactive input for variables
# Self-steal domain
echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
read SELFSTEAL_DOMAIN
while [[ -z "$SELFSTEAL_DOMAIN" ]]; do
    echo -e "${RED}Self-steal domain cannot be empty!${NC}"
    echo -ne "${CYAN}Self-steal domain (e.g., example.com): ${NC}"
read SELFSTEAL_DOMAIN
done

# Panel IP
echo -ne "${CYAN}Panel IP address: ${NC}"
read PANEL_IP
while [[ -z "$PANEL_IP" ]]; do
    echo -e "${RED}Panel IP cannot be empty!${NC}"
    echo -ne "${CYAN}Panel IP address: ${NC}"
read PANEL_IP
done

# Cloudflare Email
echo -ne "${CYAN}Cloudflare Email: ${NC}"
read CLOUDFLARE_EMAIL
while [[ -z "$CLOUDFLARE_EMAIL" ]]; do
    echo -e "${RED}Cloudflare Email cannot be empty!${NC}"
    echo -ne "${CYAN}Cloudflare Email: ${NC}"
read CLOUDFLARE_EMAIL
done

# Cloudflare API Key
echo -ne "${CYAN}Cloudflare API Key: ${NC}"
read CLOUDFLARE_API_KEY
while [[ -z "$CLOUDFLARE_API_KEY" ]]; do
    echo -e "${RED}Cloudflare API Key cannot be empty!${NC}"
    echo -ne "${CYAN}Cloudflare API Key: ${NC}"
read CLOUDFLARE_API_KEY
done

# Certificate from panel
echo
echo -e "${YELLOW}Please paste the certificate from the panel:${NC}"
echo -e "${CYAN}(Include the entire SSL_CERT=\"...\" line)${NC}"
echo -ne "${CYAN}Press Enter when done: ${NC}"
read -r CERTIFICATE
while [[ -z "$CERTIFICATE" ]]; do
    echo -e "${RED}Certificate cannot be empty!${NC}"
    echo -ne "${CYAN}Please paste the entire SSL_CERT=\"...\" line: ${NC}"
    read -r CERTIFICATE
done

# Create remnawave directory first
mkdir -p /opt/remnawave

# Create variables file for persistence
cat > /opt/remnawave/node-vars.sh << 'EOF'
# node-vars.sh
export SELFSTEAL_DOMAIN="${SELFSTEAL_DOMAIN}"
export PANEL_IP="${PANEL_IP}"
export CLOUDFLARE_API_KEY="${CLOUDFLARE_API_KEY}"
export CLOUDFLARE_EMAIL="${CLOUDFLARE_EMAIL}"
# Certificate from the panel
export CERTIFICATE='${CERTIFICATE}'
EOF

# Replace placeholders with actual values
sed -i "s|\${SELFSTEAL_DOMAIN}|$SELFSTEAL_DOMAIN|g" /opt/remnawave/node-vars.sh
sed -i "s|\${PANEL_IP}|$PANEL_IP|g" /opt/remnawave/node-vars.sh
sed -i "s|\${CLOUDFLARE_API_KEY}|$CLOUDFLARE_API_KEY|g" /opt/remnawave/node-vars.sh
sed -i "s|\${CLOUDFLARE_EMAIL}|$CLOUDFLARE_EMAIL|g" /opt/remnawave/node-vars.sh
# For certificate, we need to escape it properly
escaped_cert=$(printf '%s\n' "$CERTIFICATE" | sed 's/[[\.*^$()+?{|]/\\&/g')
sed -i "s|\${CERTIFICATE}|$escaped_cert|g" /opt/remnawave/node-vars.sh

# Set proper permissions
chmod 600 /opt/remnawave/node-vars.sh

echo
echo -e "${GREEN}Variables saved to /opt/remnawave/node-vars.sh${NC}"
echo

# Load environment variables
source /opt/remnawave/node-vars.sh

echo -e "${GREEN}------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Environment variables configured!"
echo -e "${GREEN}------------------------------------${NC}"
echo

# Rest of the script continues...

echo -e "${GREEN}=======================${NC}"
echo -e "${NC}2. Installing packages${NC}"
echo -e "${GREEN}=======================${NC}"
echo

# Update package list and install basic packages
echo "Installing basic packages..."
apt-get update -y > /dev/null 2>&1
apt-get install -y ca-certificates curl jq ufw wget gnupg unzip nano dialog git certbot python3-certbot-dns-cloudflare unattended-upgrades locales dnsutils coreutils grep gawk > /dev/null 2>&1

# Configure logrotate for remnanode
echo
echo "Configuring logrotate for remnanode..."
mkdir -p /var/log/remnanode
apt-get install -y logrotate > /dev/null 2>&1

# Create logrotate configuration
cat > /etc/logrotate.d/remnanode <<'EOL'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOL

# Test logrotate configuration
logrotate -vf /etc/logrotate.d/remnanode > /dev/null 2>&1

# Install and enable cron
echo
echo "Installing and enabling cron..."
apt-get install -y cron > /dev/null 2>&1
systemctl start cron > /dev/null 2>&1
systemctl enable cron > /dev/null 2>&1

# Configure locales
echo
echo "Configuring locales..."
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen 2>/dev/null
locale-gen > /dev/null 2>&1
update-locale LANG=en_US.UTF-8 > /dev/null 2>&1

# Set timezone
echo
echo "Setting timezone to Europe/Moscow..."
timedatectl set-timezone Europe/Moscow > /dev/null 2>&1

# Add Docker repository
echo
echo "Adding Docker repository..."
install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | tee /etc/apt/keyrings/docker.asc > /dev/null 2>&1
chmod a+r /etc/apt/keyrings/docker.asc > /dev/null 2>&1
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1

# Install Docker
echo
echo "Installing Docker..."
apt-get update > /dev/null 2>&1
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1

# Configure TCP BBR
echo
echo "Configuring TCP BBR..."
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf 2>/dev/null
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf 2>/dev/null
sysctl -p > /dev/null 2>&1

# Configure UFW firewall
echo
echo "Configuring UFW firewall..."
ufw --force reset > /dev/null 2>&1
ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1

# Configure unattended upgrades
echo
echo "Configuring unattended upgrades..."
echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections > /dev/null 2>&1
dpkg-reconfigure -f noninteractive unattended-upgrades > /dev/null 2>&1
systemctl restart unattended-upgrades > /dev/null 2>&1

echo
echo -e "${GREEN}----------------------------------${NC}"
echo -e "${GREEN}✓${NC} Package installation completed!"
echo -e "${GREEN}----------------------------------${NC}"
echo

echo -e "${GREEN}=======================================${NC}"
echo -e "${NC}3. Creating structure and certificates${NC}"
echo -e "${GREEN}=======================================${NC}"
echo

# Navigate to remnawave directory
echo "Navigating to project directory..."
echo
cd /opt/remnawave

# Create .env file
echo "Creating .env file..."
cat > .env-node <<EOL
### APP ###
APP_PORT=2222

### XRAY ###
$(echo -e "$CERTIFICATE" | sed 's/\\n$//')
EOL

# Check Cloudflare API
echo
echo "Checking Cloudflare API..."
if [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; then
    api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "Authorization: Bearer ${CLOUDFLARE_API_KEY}" --header "Content-Type: application/json")
else
    api_response=$(curl --silent --request GET --url https://api.cloudflare.com/client/v4/zones --header "X-Auth-Key: ${CLOUDFLARE_API_KEY}" --header "X-Auth-Email: ${CLOUDFLARE_EMAIL}" --header "Content-Type: application/json")
fi

# Generate certificates
echo
echo "Setting up Cloudflare credentials..."
mkdir -p ~/.secrets/certbot
if [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; then
    cat > ~/.secrets/certbot/cloudflare.ini <<EOL
dns_cloudflare_api_token = $CLOUDFLARE_API_KEY
EOL
else
    cat > ~/.secrets/certbot/cloudflare.ini <<EOL
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_key = $CLOUDFLARE_API_KEY
EOL
fi
chmod 600 ~/.secrets/certbot/cloudflare.ini

# Extract base domains
echo
echo "Extracting base domains..."
SELFSTEAL_BASE_DOMAIN=$(echo "$SELFSTEAL_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')

# Generate certificate for panel domain if not exists
echo
echo "Checking certificate for panel domain..."
if [ ! -d "/etc/letsencrypt/live/$SELFSTEAL_BASE_DOMAIN" ]; then
    echo "Generating certificate for $SELFSTEAL_BASE_DOMAIN..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 10 \
        -d "$SELFSTEAL_BASE_DOMAIN" \
        -d "*.$SELFSTEAL_BASE_DOMAIN" \
        --email "$CLOUDFLARE_EMAIL" \
        --agree-tos \
        --non-interactive \
        --key-type ecdsa \
        --elliptic-curve secp384r1
else
    echo "Certificate for $SELFSTEAL_BASE_DOMAIN already exists, skipping..."
fi

# Configure renewal hooks and cron
echo
echo "Configuring certificate renewal..."
echo "renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'" >> /etc/letsencrypt/renewal/$SELFSTEAL_BASE_DOMAIN.conf
(crontab -u root -l 2>/dev/null; echo "0 5 1 */2 * /usr/bin/certbot renew --quiet >> /usr/local/remnawave_reverse/cron_jobs.log 2>&1") | crontab -u root -

echo
echo -e "${GREEN}----------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Structure and certificates setup completed!"
echo -e "${GREEN}----------------------------------------------${NC}"
echo

echo -e "${GREEN}================================${NC}"
echo -e "${NC}4. Creating configuration files${NC}"
echo -e "${GREEN}================================${NC}"

# Create docker-compose.yml file
echo
echo "Creating docker-compose.yml file..."
cat > docker-compose.yml <<EOL
services:
  remnawave-nginx:
    image: nginx:1.26
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    restart: always
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt/live/$SELFSTEAL_BASE_DOMAIN/fullchain.pem:/etc/nginx/ssl/$SELFSTEAL_DOMAIN/fullchain.pem:ro
      - /etc/letsencrypt/live/$SELFSTEAL_BASE_DOMAIN/privkey.pem:/etc/nginx/ssl/$SELFSTEAL_DOMAIN/privkey.pem:ro
      - /dev/shm:/dev/shm:rw
      - /var/www/html:/var/www/html:ro
    command: sh -c 'rm -f /dev/shm/nginx.sock && nginx -g "daemon off;"'
    network_mode: host
    depends_on:
      - remnanode
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnanode:
    image: remnawave/node:latest
    container_name: remnanode
    hostname: remnanode
    restart: always
    network_mode: host
    env_file:
      - path: /opt/remnawave/.env-node
        required: false
    volumes:
      - /dev/shm:/dev/shm:rw
      - '/var/log/remnanode:/var/log/remnanode'
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'
EOL

# Create nginx.conf file
echo
echo "Creating nginx.conf file..."
cat > /opt/remnawave/nginx.conf <<EOL
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;

server {
    server_name $SELFSTEAL_DOMAIN;
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/fullchain.pem";

    root /var/www/html;
    index index.html;
}

server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;
    ssl_reject_handshake on;
    return 444;
}
EOL

echo
echo -e "${GREEN}--------------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Configuration files created successfully!"
echo -e "${GREEN}--------------------------------------------${NC}"
echo

echo -e "${GREEN}===========================================${NC}"
echo -e "${NC}5. Configuring UFW and starting containers${NC}"
echo -e "${GREEN}===========================================${NC}"

# Configure UFW and start containers
echo
echo "Configuring UFW and starting containers..."
ufw allow from $PANEL_IP to any port 2222 proto tcp
ufw reload
cd /opt/remnawave
docker compose up -d
sleep 3

echo
echo -e "${GREEN}----------------------------------------${NC}"
echo -e "${GREEN}✓${NC} UFW installed and containers started!"
echo -e "${GREEN}----------------------------------------${NC}"
echo

echo -e "${GREEN}====================================${NC}"
echo -e "${NC}6. Setting a random masking pattern${NC}"
echo -e "${GREEN}====================================${NC}"

# Set a random masking pattern
echo
echo "Setting a random masking pattern..."
cat > install_template.sh << 'EOF'
cd /opt/
rm -f main.zip 2>/dev/null
rm -rf simple-web-templates-main/ sni-templates-main/ 2>/dev/null

template_urls=(
    "https://github.com/eGamesAPI/simple-web-templates/archive/refs/heads/main.zip"
    "https://github.com/SmallPoppa/sni-templates/archive/refs/heads/main.zip"
)

selected_url=${template_urls[$RANDOM % ${#template_urls[@]}]}

while ! wget -q --timeout=30 --tries=10 --retry-connrefused "$selected_url"; do
    sleep 3
done

unzip -o main.zip &>/dev/null
rm -f main.zip

if [[ "$selected_url" == *"eGamesAPI"* ]]; then
    cd simple-web-templates-main/
    rm -rf assets ".gitattributes" "README.md" "_config.yml" 2>/dev/null
else
    cd sni-templates-main/
    rm -rf assets "README.md" "index.html" 2>/dev/null
fi

mapfile -t templates < <(find . -maxdepth 1 -type d -not -path . | sed 's|./||')
RandomHTML="${templates[$RANDOM % ${#templates[@]}]}"

if [[ "$selected_url" == *"SmallPoppa"* && "$RandomHTML" == "503 error pages" ]]; then
    cd "$RandomHTML"
    versions=("v1" "v2")
    RandomVersion="${versions[$RANDOM % ${#versions[@]}]}"
    RandomHTML="$RandomHTML/$RandomVersion"
    cd ..
fi

if [[ -d "${RandomHTML}" ]]; then
    if [[ ! -d "/var/www/html/" ]]; then
        mkdir -p "/var/www/html/"
    fi
    rm -rf /var/www/html/*
    cp -a "${RandomHTML}"/. "/var/www/html/"
fi

cd /opt/
rm -rf simple-web-templates-main/ sni-templates-main/

# Verifying node operation
if curl -s --fail --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -q "html"; then
    echo -e "${GREEN}✓${NC} Node successfully launched!"
else
    echo -e "${RED}✗${NC} Node is not accessible. Check configuration!"
fi
EOF

chmod +x install_template.sh
./install_template.sh

echo
echo -e "${GREEN}-------------------------------------${NC}"
echo -e "${GREEN}✓${NC} Node setup completed successfully!"
echo -e "${GREEN}-------------------------------------${NC}"
echo

fi
