#!/bin/bash

# ==============================================================================
# PuckerUp - One-Shot Installer for Debian/Ubuntu
# This script installs the Puck dedicated server, SteamCMD, and the PuckerUp
# web-based administration panel.
# ==============================================================================

# --- Configuration ---
# The GitHub repository where the PuckerUp application files are stored.
# The script will download the files from the /app subdirectory.
PUCKERUP_REPO_RAW_URL="https://raw.githubusercontent.com/pogsee/PuckerUp/main/app"

# --- Style Definitions ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Script Functions ---

# Function to print a formatted heading.
print_heading() {
    echo -e "\n${YELLOW}=======================================================================${NC}"
    echo -e "${YELLOW} $1${NC}"
    echo -e "${YELLOW}=======================================================================${NC}"
}

# Function to check if the script is being run as root.
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root. Please use 'sudo'.${NC}"
        exit 1
    fi
}

# --- Main Script Logic ---

# 1. Introduction and Confirmation
clear
echo -e "${GREEN}Welcome to the PuckerUp Installer!${NC}"
echo ""
echo "This script will perform the following actions:"
echo " - Update your system and install necessary dependencies."
echo " - Create a swap file to ensure stable performance."
echo " - Install SteamCMD and the Puck server files."
echo " - Create a low-privilege 'puck' user to run the game servers."
echo " - Set up systemd services to manage the game servers."
echo " - Download and install the PuckerUp admin panel."
echo " - Set up a systemd service to ensure PuckerUp runs on boot."
echo ""
echo "If you only want PuckerUp, choose no and read manual instructions at https://github.com/pogsee/PuckerUp"
echo ""
read -p "Do you wish to continue with installation? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Set the script to exit immediately if any command fails.
set -e

# 2. Check for Root Privileges
check_root

# 3. System Setup and Dependency Installation
print_heading "Updating System and Installing Dependencies"
apt update && apt upgrade -y
apt install -y software-properties-common curl wget

print_heading "Creating 500MB Swap File"
if [ ! -f /swapfile ]; then
    fallocate -l 500M /swapfile
    dd if=/dev/zero of=/swapfile bs=1M count=500
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
    echo -e "${GREEN}Swap file created and enabled.${NC}"
else
    echo -e "${YELLOW}Swap file already exists. Skipping creation.${NC}"
fi

print_heading "Configuring Repositories for SteamCMD"
dpkg --add-architecture i386
apt update

print_heading "Installing SteamCMD"
echo steam steam/question select "I AGREE" | debconf-set-selections
echo steam steam/license note '' | debconf-set-selections
apt install -y steamcmd

# 4. Puck Server Installation
print_heading "Installing Puck Dedicated Server"
mkdir -p /srv/puckserver
/usr/games/steamcmd +force_install_dir /srv/puckserver +login anonymous +app_update 3481440 validate +quit

print_heading "Creating 'puck' System User"
if ! id "puck" &>/dev/null; then
    useradd -r -s /bin/false puck
    echo -e "${GREEN}'puck' user created.${NC}"
else
    echo -e "${YELLOW}'puck' user already exists.${NC}"
fi
chown -R puck:puck /srv/puckserver

print_heading "Creating Puck Server Systemd Service"
cat > /etc/systemd/system/puck@.service << 'EOF'
[Unit]
Description=Puck Dedicated Server (Instance %i)
After=network.target

[Service]
WorkingDirectory=/srv/puckserver
User=puck
Group=puck
# The game server binary requires a start_server.sh script to run.
# This is a common pattern for Unity games.
ExecStart=/srv/puckserver/Puck.x86_64 --serverConfigurationPath %i.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

print_heading "Generating Initial Server Config Files"
# Generate a random password for the game servers themselves.
GAME_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)

for i in {1..4}; do
    port=$((7777 + (i-1)*2))
    pingPort=$((7778 + (i-1)*2))
    cat > "/srv/puckserver/server${i}.json" <<EOF
{
  "port": ${port},
  "pingPort": ${pingPort},
  "name": "Puck Server ${i}",
  "maxPlayers": 10,
  "password": "${GAME_PASSWORD}",
  "voip": false,
  "isPublic": true,
  "adminSteamIds": [],
  "reloadBannedSteamIds": true,
  "usePuckBannedSteamIds": true,
  "printMetrics": true,
  "kickTimeout": 1800,
  "sleepTimeout": 900,
  "joinMidMatchDelay": 10,
  "targetFrameRate": 380,
  "serverTickRate": 360,
  "clientTickRate": 360,
  "startPaused": false,
  "allowVoting": true,
  "phaseDurationMap": {"Warmup":600,"FaceOff":3,"Playing":300,"BlueScore":5,"RedScore":5,"Replay":10,"PeriodOver":15,"GameOver":15},
  "mods": [
    {"id": 3497097214, "enabled": true, "clientRequired": false},
    {"id": 3497344177, "enabled": true, "clientRequired": false},
    {"id": 3503065207, "enabled": true, "clientRequired": true}
  ]
}
EOF
done
chown puck:puck /srv/puckserver/*.json
echo -e "${GREEN}Default config files created for servers 1-4.${NC}"

# 5. PuckerUp Admin Panel Installation
print_heading "Downloading and Installing PuckerUp Admin Panel"
mkdir -p /srv/PuckerUp
wget -qO /srv/PuckerUp/index.html "${PUCKERUP_REPO_RAW_URL}/index.html"
wget -qO /srv/PuckerUp/login.html "${PUCKERUP_REPO_RAW_URL}/login.html"
wget -qO /srv/PuckerUp/puckerup "${PUCKERUP_REPO_RAW_URL}/puckerup"
wget -qO /srv/PuckerUp/puckerup-passwd "${PUCKERUP_REPO_RAW_URL}/puckerup-passwd"
echo -e "${GREEN}PuckerUp files downloaded.${NC}"

chmod +x /srv/PuckerUp/puckerup
chmod +x /srv/PuckerUp/puckerup-passwd

# 6. Generate PuckerUp Admin Password
print_heading "Generating Admin Panel Password"
ADMIN_PASSWORD=$(/srv/PuckerUp/puckerup-passwd)

# 7. Setup PuckerUp Systemd Service
print_heading "Creating PuckerUp Systemd Service"
cat > /etc/systemd/system/puckerup.service << 'EOF'
[Unit]
Description=PuckerUp Admin Panel Web Server
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/srv/PuckerUp
ExecStart=/srv/PuckerUp/puckerup
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable puckerup.service
systemctl start puckerup.service
echo -e "${GREEN}PuckerUp service created and started.${NC}"

# 8. Final Instructions
IP_ADDRESS=$(hostname -I | awk '{print $1}')
print_heading "Installation Complete!"
echo -e "You can now access the PuckerUp admin panel in your web browser."
echo ""
echo -e "    PuckerUp URL: ${YELLOW}http://${IP_ADDRESS}:8080${NC}"
echo -e "    PuckerUp password: ${GREEN}${ADMIN_PASSWORD}${NC}"
echo -e "    SAVE THE ABOVE PASSWORD. It cannot be changed or displayed again."
echo ""
echo -e "The randomly generated password for your actual puck servers is:"
echo -e "    Puck Server Password: ${GREEN}${GAME_PASSWORD}${NC}"
echo ""
echo -e "Thank you for using PuckerUp!"

