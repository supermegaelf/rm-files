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

# Remnawave Panel Monitoring Management Script
echo
echo -e "${PURPLE}===================================${NC}"
echo -e "${NC}REMNAWAVE PANEL MONITORING MANAGER${NC}"
echo -e "${PURPLE}===================================${NC}"
echo

# Check if script is run with parameters
if [ "$1" = "uninstall" ] || [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
   ACTION="uninstall"
elif [ "$1" = "install" ] || [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
   ACTION="install"
else
   # Interactive menu
   echo -e "${CYAN}Please select an action:${NC}"
   echo
   echo -e "${GREEN}1.${NC} Install Panel Monitoring"
   echo -e "${RED}2.${NC} Uninstall Panel Monitoring"
   echo -e "${YELLOW}3.${NC} Exit"
   echo
   
   while true; do
       read -p "Enter your choice (1-3): " CHOICE
       case $CHOICE in
           1)
               ACTION="install"
               break
               ;;
           2)
               ACTION="uninstall"
               break
               ;;
           3)
               echo -e "${CYAN}Goodbye!${NC}"
               exit 0
               ;;
           *)
               echo -e "${RED}Invalid choice. Please enter 1, 2, or 3.${NC}"
               ;;
       esac
   done
fi

# Uninstall function
if [ "$ACTION" = "uninstall" ]; then
   echo
   echo -e "${PURPLE}=============================${NC}"
   echo -e "${NC}Panel Monitoring Uninstaller${NC}"
   echo -e "${PURPLE}=============================${NC}"
   echo

   # Check if monitoring is installed
   if [ ! -d "/opt/monitoring" ] && [ ! -f "/usr/local/bin/node_exporter" ]; then
       echo -e "${YELLOW}Panel monitoring is not installed on this system.${NC}"
       echo
       exit 0
   fi

   # Confirmation
   echo -e "${YELLOW}Are you sure you want to continue? (y/N)${NC}"
   read -r CONFIRM

   if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
       echo -e "${CYAN}Uninstallation cancelled.${NC}"
       exit 0
   fi

   echo
   echo -e "${GREEN}=============================${NC}"
   echo -e "${NC}Removing monitoring services${NC}"
   echo -e "${GREEN}=============================${NC}"
   echo

   # Stop and remove Docker containers
   echo "Stopping and removing monitoring containers..."
   cd /opt/monitoring 2>/dev/null
   if [ -f "docker-compose.yml" ]; then
       docker compose down 2>/dev/null && echo "✓ Monitoring containers stopped" || echo "ℹ Containers were not running"
   fi

   # Remove Docker volumes
   echo
   echo "Removing Docker volumes..."
   docker volume rm grafana-storage 2>/dev/null && echo "✓ Grafana volume removed" || echo "ℹ Grafana volume not found"
   docker volume rm prom_data 2>/dev/null && echo "✓ Prometheus volume removed" || echo "ℹ Prometheus volume not found"

   # Remove monitoring directory
   echo
   echo "Removing monitoring directory..."
   if [ -d "/opt/monitoring" ]; then
       rm -rf /opt/monitoring
       echo "✓ Monitoring directory removed"
   else
       echo "ℹ Monitoring directory not found"
   fi

   # Stop and remove Node Exporter
   echo
   echo "Removing Node Exporter..."
   systemctl stop node_exporter 2>/dev/null && echo "✓ Node Exporter stopped" || echo "ℹ Node Exporter was not running"
   systemctl disable node_exporter 2>/dev/null && echo "✓ Node Exporter disabled" || echo "ℹ Node Exporter was not enabled"

   if [ -f "/etc/systemd/system/node_exporter.service" ]; then
       rm -f /etc/systemd/system/node_exporter.service
       systemctl daemon-reload
       echo "✓ Node Exporter service removed"
   else
       echo "ℹ Node Exporter service file not found"
   fi

   if [ -f "/usr/local/bin/node_exporter" ]; then
       rm -f /usr/local/bin/node_exporter
       echo "✓ Node Exporter binary removed"
   else
       echo "ℹ Node Exporter binary not found"
   fi

   # Remove user
   if id "node_exporter" &>/dev/null; then
       userdel node_exporter 2>/dev/null
       echo "✓ Node Exporter user removed"
   else
       echo "ℹ Node Exporter user not found"
   fi

   # Remove UFW rule
   echo
   echo "Removing UFW rules..."
   ufw delete allow 9443/tcp 2>/dev/null && echo "✓ UFW rule removed" || echo "ℹ UFW rule not found"

   # Restore nginx configuration if backup exists
   echo
   echo "Restoring panel configuration..."
   if [ -f "/opt/remnawave/nginx.conf.backup" ]; then
       cd /opt/remnawave
       cp nginx.conf.backup nginx.conf
       echo "✓ Nginx configuration restored from backup"
       
       # Restore docker-compose.yml if backup exists
       if [ -f "/opt/remnawave/docker-compose.yml.backup" ]; then
           cp docker-compose.yml.backup docker-compose.yml
           echo "✓ Docker compose configuration restored from backup"
           
           # Restart remnawave containers
           docker compose down 2>/dev/null
           docker compose up -d 2>/dev/null
           echo "✓ Remnawave panel restarted"
       fi
       
       # Clean up backup files
       echo
       echo "Cleaning up backup files..."
       rm -f nginx.conf.backup docker-compose.yml.backup
       echo "✓ Backup files removed"
   else
       echo "ℹ No nginx backup found to restore"
   fi

   echo
   echo -e "${GREEN}=============================================${NC}"
   echo -e "${NC}✓ Panel monitoring uninstalled successfully!${NC}"
   echo -e "${GREEN}=============================================${NC}"
   echo
   echo -e "${CYAN}Note: Remnawave panel configuration has been restored.${NC}"
   echo
   exit 0
fi

# Installation process
echo
echo -e "${PURPLE}==============================${NC}"
echo -e "${NC}Panel Monitoring Installation${NC}"
echo -e "${PURPLE}==============================${NC}"
echo

# Check if monitoring is already installed
if [ -d "/opt/monitoring" ] && [ -f "/usr/local/bin/node_exporter" ]; then
   echo -e "${YELLOW}Panel monitoring appears to be already installed.${NC}"
   echo -e "${YELLOW}Do you want to reinstall? (y/N)${NC}"
   read -r REINSTALL
   
   if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
       echo -e "${CYAN}Installation cancelled.${NC}"
       exit 0
   fi
   
   echo -e "${YELLOW}Proceeding with reinstallation...${NC}"
fi

# Check if we're in panel directory and load variables
if [ ! -f "/opt/remnawave/remnawave-vars.sh" ]; then
    echo -e "${RED}Error: Panel variables file not found at /opt/remnawave/remnawave-vars.sh${NC}"
    echo -e "${RED}This script must be run on a server with Remnawave panel installed.${NC}"
    exit 1
fi

# Load panel variables
echo -e "${CYAN}Loading panel configuration...${NC}"
cd /opt/remnawave
source remnawave-vars.sh

# Display current configuration
echo
echo -e "${CYAN}Current panel configuration:${NC}"
echo
echo -e "Panel domain: ${WHITE}$PANEL_DOMAIN${NC}"
echo -e "Subscription domain: ${WHITE}$SUB_DOMAIN${NC}"
echo -e "Cookie auth: ${WHITE}${cookies_random1}=${cookies_random2}${NC}"
echo

# Extract Remnawave metrics credentials
echo "Extracting Remnawave metrics credentials..."
METRICS_USER=$(grep "METRICS_USER=" /opt/remnawave/.env | cut -d'=' -f2)
METRICS_PASS=$(grep "METRICS_PASS=" /opt/remnawave/.env | cut -d'=' -f2)

if [[ -z "$METRICS_USER" || -z "$METRICS_PASS" ]]; then
    echo -e "${RED}Error: Could not find Remnawave metrics credentials in .env file${NC}"
    echo -e "${RED}Make sure METRICS_USER and METRICS_PASS are set in /opt/remnawave/.env${NC}"
    exit 1
fi

echo -e "Metrics user: ${WHITE}$METRICS_USER${NC}"
echo -e "Metrics password: ${WHITE}$METRICS_PASS${NC}"
echo

# Confirm configuration
echo -e "${YELLOW}Use this configuration for monitoring? (Y/n)${NC}"
read -r USE_CONFIG

if [[ "$USE_CONFIG" =~ ^[Nn]$ ]]; then
    echo -e "${CYAN}Please enter the required information:${NC}"
    echo
    
    read -p "Panel domain (e.g., panel.example.com): " PANEL_DOMAIN
    while [[ -z "$PANEL_DOMAIN" ]]; do
        echo -e "${RED}Panel domain cannot be empty!${NC}"
        read -p "Panel domain: " PANEL_DOMAIN
    done
    
    read -p "Subscription domain (e.g., sub.example.com): " SUB_DOMAIN
    while [[ -z "$SUB_DOMAIN" ]]; do
        echo -e "${RED}Subscription domain cannot be empty!${NC}"
        read -p "Subscription domain: " SUB_DOMAIN
    done
fi

set -e

echo
echo -e "${GREEN}============================${NC}"
echo -e "${NC}1. Installing Node Exporter${NC}"
echo -e "${GREEN}============================${NC}"
echo

# Download and install Node Exporter
echo "Downloading Node Exporter..."
wget -q https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz
tar xvf node_exporter-1.9.1.linux-amd64.tar.gz > /dev/null
cp node_exporter-1.9.1.linux-amd64/node_exporter /usr/local/bin/
rm -rf node_exporter-1.9.1.linux-amd64*

# Create user and service
echo "Creating Node Exporter user and service..."
useradd --no-create-home --shell /bin/false node_exporter 2>/dev/null || true
chown node_exporter:node_exporter /usr/local/bin/node_exporter

cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Start Node Exporter
systemctl daemon-reload
systemctl enable node_exporter
systemctl start node_exporter

echo
echo -e "${GREEN}----------------------------------------${NC}"
echo -e "${NC}✓ Node Exporter installation completed!${NC}"
echo -e "${GREEN}----------------------------------------${NC}"
echo

echo -e "${GREEN}=========================${NC}"
echo -e "${NC}2. Setting up monitoring${NC}"
echo -e "${GREEN}=========================${NC}"
echo

# Create monitoring structure
echo "Creating monitoring structure..."
mkdir -p /opt/monitoring/prometheus
cd /opt/monitoring

# Create Prometheus configuration
cat > prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  scrape_timeout: 10s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['127.0.0.1:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['127.0.0.1:9100']
    scrape_interval: 15s
    scrape_timeout: 5s

  - job_name: 'remnawave'
    scheme: http
    metrics_path: /metrics
    static_configs:
      - targets: ['127.0.0.1:3001']
    scrape_interval: 30s
    scrape_timeout: 10s
    basic_auth:
      username: $METRICS_USER
      password: $METRICS_PASS
EOF

# Create Docker Compose for monitoring
cat > docker-compose.yml << 'EOF'
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    network_mode: host
    volumes:
      - grafana-storage:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_HTTP_PORT=3002
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prom_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
      - '--web.listen-address=0.0.0.0:9090'
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

volumes:
  grafana-storage:
    external: true
  prom_data:
    external: true
EOF

# Create Docker volumes
echo "Creating Docker volumes..."
docker volume create grafana-storage > /dev/null
docker volume create prom_data > /dev/null

echo
echo -e "${GREEN}------------------------------${NC}"
echo -e "${NC}✓ Monitoring setup completed!${NC}"
echo -e "${GREEN}------------------------------${NC}"
echo

echo -e "${GREEN}================================${NC}"
echo -e "${NC}3. Updating panel configuration${NC}"
echo -e "${GREEN}================================${NC}"
echo

# Update Remnawave panel configuration
cd /opt/remnawave

# Backup current configurations
echo "Creating configuration backups..."
cp nginx.conf nginx.conf.backup 2>/dev/null || true
cp docker-compose.yml docker-compose.yml.backup 2>/dev/null || true

# Update nginx.conf
echo "Updating nginx configuration..."
cat > nginx.conf << EOF
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
    server_name ${PANEL_DOMAIN};
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/${PANEL_DOMAIN}/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";

    add_header Set-Cookie \$set_cookie_header;

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
    server_name ${SUB_DOMAIN};
    listen 443 ssl;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/${SUB_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/${SUB_DOMAIN}/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/${SUB_DOMAIN}/fullchain.pem";

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
    listen 9443 ssl;
    http2 on;
    server_name grafana.${PANEL_DOMAIN};

    ssl_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/${PANEL_DOMAIN}/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";

    location / {
        proxy_pass http://127.0.0.1:3002;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
    }
}

server {
    listen 9443 ssl;
    http2 on;
    server_name prometheus.${PANEL_DOMAIN};

    ssl_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/${PANEL_DOMAIN}/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 9443 ssl;
    http2 on;
    server_name node-exporter.${PANEL_DOMAIN};

    ssl_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/${PANEL_DOMAIN}/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/${PANEL_DOMAIN}/fullchain.pem";

    location / {
        proxy_pass http://127.0.0.1:9100;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}

server {
    listen 9443 ssl default_server;
    http2 on;
    server_name _;
    ssl_reject_handshake on;
    return 444;
}
EOF

# Update docker-compose.yml to include metrics port
echo "Updating docker-compose.yml for metrics..."

# Extract base domains for SSL certificates
PANEL_BASE_DOMAIN=$(echo "$PANEL_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')
SUB_BASE_DOMAIN=$(echo "$SUB_DOMAIN" | awk -F'.' '{if (NF > 2) {print $(NF-1)"."$NF} else {print $0}}')

# Create new docker-compose.yml with metrics port
cat > docker-compose.yml << EOL
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
      - '127.0.0.1:3001:3001'
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

echo
echo -e "${GREEN}----------------------------------------${NC}"
echo -e "${NC}✓ Panel configuration update completed!${NC}"
echo -e "${GREEN}----------------------------------------${NC}"
echo

echo -e "${GREEN}===================${NC}"
echo -e "${NC}4. UFW and startup${NC}"
echo -e "${GREEN}===================${NC}"
echo

# UFW rule
echo "Adding UFW rule..."
ufw allow 9443/tcp comment "Panel Monitoring HTTPS" > /dev/null

# Start monitoring services
echo "Starting monitoring services..."
cd /opt/monitoring
docker compose up -d > /dev/null

# Restart Remnawave panel
echo "Restarting Remnawave panel..."
cd /opt/remnawave
docker compose down > /dev/null 2>&1
docker compose up -d > /dev/null

echo
echo -e "${GREEN}------------------------------${NC}"
echo -e "${NC}✓ Services startup completed!${NC}"
echo -e "${GREEN}------------------------------${NC}"
echo

echo -e "${GREEN}======================${NC}"
echo -e "${NC}5. Final verification${NC}"
echo -e "${GREEN}======================${NC}"
echo

# Wait for services to start
echo "Waiting for services to start..."
sleep 15

# Verify Node Exporter
if systemctl is-active --quiet node_exporter; then
   echo -e "${GREEN}✓ Node Exporter is running${NC}"
else
   echo -e "${RED}✗ Node Exporter is not running${NC}"
fi

# Verify Docker containers
if docker ps | grep -q "grafana\|prometheus"; then
   echo -e "${GREEN}✓ Monitoring containers are running${NC}"
else
   echo -e "${RED}✗ Monitoring containers are not running${NC}"
fi

# Verify nginx
if docker ps | grep -q "remnawave-nginx"; then
   echo -e "${GREEN}✓ Nginx container is running${NC}"
else
   echo -e "${RED}✗ Nginx container is not running${NC}"
fi

# Check ports
if ss -tlnp | grep -q 9443; then
   echo -e "${GREEN}✓ Port 9443 is listening${NC}"
else
   echo -e "${YELLOW}⚠ Port 9443 is not listening${NC}"
fi

# Test Prometheus targets
echo "Checking Prometheus targets..."
sleep 5
if curl -s http://localhost:9090/api/v1/targets 2>/dev/null | grep -q '"health":"up"'; then
   echo -e "${GREEN}✓ Prometheus targets are healthy${NC}"
else
   echo -e "${YELLOW}⚠ Some Prometheus targets may be down${NC}"
fi

# Test Remnawave metrics endpoint
echo "Checking Remnawave metrics..."
if curl -s -u "$METRICS_USER:$METRICS_PASS" http://127.0.0.1:3001/metrics 2>/dev/null | grep -q "# HELP"; then
   echo -e "${GREEN}✓ Remnawave metrics are accessible${NC}"
else
   echo -e "${YELLOW}⚠ Remnawave metrics endpoint is not responding${NC}"
   echo -e "${CYAN}  Check if Remnawave container is running and METRICS_PORT=3001${NC}"
fi

echo
echo -e "${GREEN}--------------------------------${NC}"
echo -e "${NC}✓ Final verification completed!${NC}"
echo -e "${GREEN}--------------------------------${NC}"
echo

echo -e "${GREEN}========================================================${NC}"
echo -e "${NC}✓ Panel monitoring installation completed successfully!${NC}"
echo -e "${GREEN}========================================================${NC}"
echo
echo -e "${CYAN}Access URLs:${NC}"
echo -e "Grafana: ${WHITE}https://grafana.$PANEL_DOMAIN:9443${NC}"
echo -e "Prometheus: ${WHITE}https://prometheus.$PANEL_DOMAIN:9443${NC}"
echo
echo -e "${CYAN}Test Remnawave metrics:${NC}"
echo -e "${WHITE}curl -u '$METRICS_USER:$METRICS_PASS' http://localhost:3001/metrics${NC}"
echo
echo -e "${CYAN}Check all targets:${NC}"
echo -e "${WHITE}curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'${NC}"
echo
