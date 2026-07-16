#!/bin/bash

set -e

# Determine server architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        HYS_ARCH="amd64"
        YQ_ARCH="amd64"
        ;;
    aarch64)
        HYS_ARCH="arm64"
        YQ_ARCH="arm64"
        ;;
    *)
        echo "❌ Architecture $ARCH is not supported!"
        exit 1
        ;;
esac

get_all_ips() {
    ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d'/' -f1
}

# ============================================================
# AUTO-CLEANUP
# ============================================================
cleanup_dead_services() {
    local FOUND_DEAD=0
    local SERVICE_FILE SERVICE_NAME IP_SAFE SERVICE_IP
    local SOCKS_SERVICE TABLE_ID MARK_ID
    local GW IFACE

    declare -A ACTIVE_IPS_MAP
    while IFS= read -r ip; do
        ACTIVE_IPS_MAP["$ip"]=1
    done < <(get_all_ips)

    GW=$(ip route show | grep "^default" | awk '{print $3}' | head -1)
    IFACE=$(ip route show | grep "^default" | awk '{print $5}' | head -1)

    for SERVICE_FILE in /etc/systemd/system/hysteria-server-*.service; do
        [ -f "$SERVICE_FILE" ] || continue

        SERVICE_NAME=$(basename "$SERVICE_FILE" .service)
        IP_SAFE=$(echo "$SERVICE_NAME" | sed 's/hysteria-server-//')
        SERVICE_IP=$(echo "$IP_SAFE" | tr '_' '.')

        [[ "${ACTIVE_IPS_MAP[$SERVICE_IP]+_}" ]] && continue

        if [ "$FOUND_DEAD" -eq 0 ]; then
            echo ""
            echo "🧹 ============================================"
            echo "🧹  CLEANUP: Found services for removed IPs"
            echo "🧹 ============================================"
            FOUND_DEAD=1
        fi

        echo "🗑️  Removing dead service for IP: $SERVICE_IP"
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "$SERVICE_FILE"

        SOCKS_SERVICE="microsocks-${IP_SAFE}"
        if [ -f "/etc/systemd/system/${SOCKS_SERVICE}.service" ]; then
            systemctl stop "$SOCKS_SERVICE" 2>/dev/null || true
            systemctl disable "$SOCKS_SERVICE" 2>/dev/null || true
            rm -f "/etc/systemd/system/${SOCKS_SERVICE}.service"
        fi

        rm -f "/etc/hysteria/config_${IP_SAFE}.yaml" \
              "/etc/hysteria/cert_${IP_SAFE}.pem" \
              "/etc/hysteria/key_${IP_SAFE}.pem"

        TABLE_ID=$(echo "$SERVICE_IP" | cksum | awk '{print ($1 % 8000) + 1000}')
        MARK_ID=$TABLE_ID

        if [ -n "$IFACE" ]; then
            ip rule del from "$SERVICE_IP" table "$TABLE_ID" 2>/dev/null || true
            while iptables -t mangle -D POSTROUTING -s "$SERVICE_IP" -j TTL --ttl-set 128 2>/dev/null; do :; done
            tc filter del dev "$IFACE" protocol ip parent 1:0 prio "$MARK_ID" 2>/dev/null || true
            tc class del dev "$IFACE" classid "1:${MARK_ID}" 2>/dev/null || true
        fi
        echo "   ✅ Fully cleaned: $SERVICE_IP"
    done

    if [ "$FOUND_DEAD" -eq 1 ]; then
        systemctl daemon-reload
        echo "🧹 Cleanup complete"
    else
        echo "✅ No dead services found."
    fi
}

cleanup_dead_services


select_ip() {
    IPS=($(get_all_ips))
    
    if [ ${#IPS[@]} -eq 0 ]; then
        echo "❌ No public IP addresses found."
        read -p "Enter IP address manually: " MANUAL_IP
        echo "$MANUAL_IP"
        return
    fi
    
    echo ""
    echo "=============================="
    echo "Available IP addresses on the server:"
    echo "=============================="
    for i in "${!IPS[@]}"; do
        echo "$((i+1)). ${IPS[$i]}"
    done
    echo "=============================="
    echo ""
}

NEW_USER="user$(shuf -i 1000-9999 -n 1)"
NEW_PASS=$(openssl rand -base64 12)

IPS=($(get_all_ips))
select_ip

while true; do
    read -p "Select IP number (1-${#IPS[@]}): " IP_CHOICE
    
    if [[ "$IP_CHOICE" =~ ^[0-9]+$ ]] && [ "$IP_CHOICE" -ge 1 ] && [ "$IP_CHOICE" -le ${#IPS[@]} ]; then
        SELECTED_IP="${IPS[$((IP_CHOICE-1))]}"
        break
    else
        echo "❌ Error: please enter a number from 1 to ${#IPS[@]}"
    fi
done

while true; do
    read -p "Install additional SOCKS5 proxy on this IP? (1 - Yes, 0 - No): " SOCKS_CHOICE
    if [[ "$SOCKS_CHOICE" == "0" || "$SOCKS_CHOICE" == "1" ]]; then
        break
    else
        echo "❌ Error: enter 1 (Yes) or 0 (No)."
    fi
done

echo ""
echo "✅ Selected IP: $SELECTED_IP"
if [ "$SOCKS_CHOICE" == "1" ]; then
    echo "✅ SOCKS5: Will be installed"
else
    echo "✅ SOCKS5: Installation skipped"
fi
echo ""

IP_SAFE=$(echo $SELECTED_IP | tr '.' '_')
CONFIG_PATH="/etc/hysteria/config_${IP_SAFE}.yaml"
CERT_PATH="/etc/hysteria/cert_${IP_SAFE}.pem"
KEY_PATH="/etc/hysteria/key_${IP_SAFE}.pem"
SERVICE_NAME="hysteria-server-${IP_SAFE}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SOCKS_SERVICE_NAME="microsocks-${IP_SAFE}"
SOCKS_SERVICE_PATH="/etc/systemd/system/${SOCKS_SERVICE_NAME}.service"

# Unique routing table and marker based on the last IP octet (Collision protection)
# Уникальная таблица и маркер на основе хэша от полного IP-адреса (100% защита от коллизий)
# Уникальный ID от 1000 до 8999 (безопасно и для iproute2, и для HEX-парсера tc)
TABLE_ID=$(echo "$SELECTED_IP" | cksum | awk '{print ($1 % 8000) + 1000}')
MARK_ID=$TABLE_ID

# Get gateway and interface for routing
GATEWAY=$(ip route show | grep "^default" | awk '{print $3}' | head -1)
INTERFACE=$(ip route show | grep "^default" | awk '{print $5}' | head -1)

if [ -z "$GATEWAY" ] || [ -z "$INTERFACE" ]; then
    echo "⚠️ Warning: Failed to determine gateway. Routing may not work correctly."
    GATEWAY="127.0.0.1" 
    INTERFACE="eth0"
fi

# --- GLOBAL ANTI-DETECT OS & NETWORK OPTIMIZATIONS ---
echo "🥷 Applying global kernel network settings and DNS protection..."

# Strict DNS protection
if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf 2>/dev/null; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf
fi

# Advanced network settings (BBR, Forwarding, TCP Timestamps, Nonlocal Bind)
cat > /etc/sysctl.d/99-proxy-tuning.conf <<EOF
net.ipv4.tcp_timestamps=0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.ip_nonlocal_bind=1
EOF
sysctl --system > /dev/null 2>&1 || true

# Base packages
PACKAGES="wget curl tar openssl qrencode python3 iptables iproute2 e2fsprogs"
if [ "$SOCKS_CHOICE" == "1" ]; then
    PACKAGES="$PACKAGES build-essential git"
fi

if [ ! -f "/usr/local/bin/hysteria" ] || { [ "$SOCKS_CHOICE" == "1" ] && [ ! -f "/usr/local/bin/microsocks" ]; }; then
  echo "📦 Installing base dependencies..."
  apt update
  apt install -y $PACKAGES
fi

# Check and install yq utility
if ! command -v yq &> /dev/null; then
  echo "📥 Installing yq ($YQ_ARCH architecture)..."
  wget -qO /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${YQ_ARCH}"
  chmod +x /usr/local/bin/yq
fi

# --- Hysteria2 Installation ---
if [ ! -f "/usr/local/bin/hysteria" ]; then
  echo "⬇️  Fetching the latest Hysteria2 version..."
  VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name":' | cut -d'"' -f4)

  echo "📥 Downloading Hysteria2 version $VERSION ($HYS_ARCH architecture)..."
  wget -qO /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/download/${VERSION}/hysteria-linux-${HYS_ARCH}"
  chmod +x /usr/local/bin/hysteria
else
  echo "✅ Hysteria2 is already installed."
fi

# --- SOCKS5 (microsocks) Installation ---
if [ "$SOCKS_CHOICE" == "1" ] && [ ! -f "/usr/local/bin/microsocks" ]; then
  echo "📦 Compiling MicroSocks..."
  cd /tmp
  rm -rf microsocks
  git clone -q https://github.com/rofl0r/microsocks.git
  cd microsocks
  make > /dev/null
  cp microsocks /usr/local/bin/
  cd ~
fi

# --- Configuration Logic ---
if [ ! -f "$CONFIG_PATH" ]; then
  echo "🔐 Generating certificate for IP $SELECTED_IP..."
  mkdir -p /etc/hysteria
  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout "$KEY_PATH" -out "$CERT_PATH" -subj "/CN=$SELECTED_IP" 2>/dev/null
  chmod 600 "$KEY_PATH"

  echo "⚙️  Creating Hysteria2 configuration..."
  cat > "$CONFIG_PATH" <<EOF
listen: $SELECTED_IP:443
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
auth:
  type: userpass
  userpass:
    $NEW_USER: "$NEW_PASS"
resolver:
  type: https
  https:
    addr: 8.8.8.8:443
    timeout: 10s
    sni: dns.google
    insecure: false
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
outbounds:
  - name: ip_outbound
    type: direct
    direct:
      bindIPv4: $SELECTED_IP
acl:
  inline:
    - ip_outbound(all)
EOF
  chmod 600 "$CONFIG_PATH"

  DELAY=$(shuf -i 4-15 -n 1)           
             

  echo "🔧 Creating Hysteria2 systemd service (Anti-Detect) for IP $SELECTED_IP..."
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Hysteria2 Server - $SELECTED_IP
After=network-online.target
Wants=network-online.target

[Service]
LimitNOFILE=1048576
ExecStartPre=-/bin/bash -c "ip rule del from $SELECTED_IP table $TABLE_ID 2>/dev/null"
ExecStartPre=/bin/bash -c "ip rule add from $SELECTED_IP table $TABLE_ID"
ExecStartPre=/bin/bash -c "ip route replace default via $GATEWAY dev $INTERFACE table $TABLE_ID onlink"

ExecStartPre=-/bin/bash -c "iptables -t mangle -D POSTROUTING -s $SELECTED_IP -j TTL --ttl-set 128 2>/dev/null"
ExecStartPre=/bin/bash -c "iptables -t mangle -A POSTROUTING -s $SELECTED_IP -j TTL --ttl-set 128"

ExecStartPre=-/bin/bash -c "tc qdisc show dev $INTERFACE | grep -q 'htb' || tc qdisc add dev $INTERFACE root handle 1: htb default 10"
ExecStartPre=-/bin/bash -c "tc class show dev $INTERFACE | grep -q 'classid 1:10' || tc class add dev $INTERFACE parent 1: classid 1:10 htb rate 1000mbit"
ExecStartPre=-/bin/bash -c "tc class del dev $INTERFACE classid 1:$MARK_ID 2>/dev/null"
ExecStartPre=/bin/bash -c "tc class add dev $INTERFACE parent 1: classid 1:$MARK_ID htb rate 1000mbit"
ExecStartPre=/bin/bash -c "tc qdisc add dev $INTERFACE parent 1:$MARK_ID handle $MARK_ID: netem delay ${DELAY}ms"
ExecStartPre=/bin/bash -c "tc filter add dev $INTERFACE protocol ip parent 1:0 prio $MARK_ID u32 match ip src $SELECTED_IP flowid 1:$MARK_ID"

ExecStart=/usr/local/bin/hysteria server -c $CONFIG_PATH
Restart=always
RestartSec=5
User=root
Environment="GODEBUG=madvdontneed=1"

ExecStopPost=-/bin/bash -c "ip rule del from $SELECTED_IP table $TABLE_ID 2>/dev/null"
ExecStopPost=-/bin/bash -c "iptables -t mangle -D POSTROUTING -s $SELECTED_IP -j TTL --ttl-set 128 2>/dev/null"
ExecStopPost=-/bin/bash -c "tc filter del dev $INTERFACE protocol ip parent 1:0 prio $MARK_ID 2>/dev/null"
ExecStopPost=-/bin/bash -c "tc class del dev $INTERFACE classid 1:$MARK_ID 2>/dev/null"

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  echo "🚀 Starting Hysteria2 on IP $SELECTED_IP..."
  systemctl enable --now $SERVICE_NAME

  if [ "$SOCKS_CHOICE" == "1" ]; then
    echo "🔧 Creating SOCKS5 systemd service for IP $SELECTED_IP..."
    cat > "$SOCKS_SERVICE_PATH" <<EOF
[Unit]
Description=MicroSocks Server - $SELECTED_IP
After=network-online.target
Wants=network-online.target

[Service]
LimitNOFILE=1048576
ExecStart=/usr/local/bin/microsocks -1 -i $SELECTED_IP -b $SELECTED_IP -p 1080 -u $NEW_USER -P "$NEW_PASS"
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    chmod 600 "$SOCKS_SERVICE_PATH"
    systemctl daemon-reload
    echo "🚀 Starting SOCKS5 on IP $SELECTED_IP..."
    systemctl enable --now $SOCKS_SERVICE_NAME
  fi

else
  echo "⚙️  Updating Hysteria2 configuration for IP $SELECTED_IP..."

  yq -i '.auth.type = "userpass"' "$CONFIG_PATH"

  if ! yq eval '.auth.userpass' "$CONFIG_PATH" &>/dev/null || [ "$(yq eval '.auth.userpass' "$CONFIG_PATH")" = "null" ]; then
    yq -i '.auth.userpass = {}' "$CONFIG_PATH"
  fi

  if ! yq eval ".auth.userpass.$NEW_USER" "$CONFIG_PATH" &>/dev/null || [ "$(yq eval ".auth.userpass.$NEW_USER" "$CONFIG_PATH")" = "null" ]; then
    yq -i ".auth.userpass.\"$NEW_USER\" = \"$NEW_PASS\"" "$CONFIG_PATH"
  fi

  if [ "$(yq eval '.outbounds' "$CONFIG_PATH")" = "null" ]; then
    echo "🔧 Adding IP bind (outbounds) to the existing config..."
    yq -i '.outbounds = [{"name": "ip_outbound", "type": "direct", "direct": {"bindIPv4": "'$SELECTED_IP'"}}]' "$CONFIG_PATH"
    yq -i '.acl.inline = ["ip_outbound(all)"]' "$CONFIG_PATH"
  fi
  
  if [ "$(yq eval '.resolver' "$CONFIG_PATH")" = "null" ]; then
    echo "🔧 Adding secure DNS (Google DoH) to the existing config..."
    yq -i '.resolver.type = "https"' "$CONFIG_PATH"
    yq -i '.resolver.https.addr = "8.8.8.8:443"' "$CONFIG_PATH"
    yq -i '.resolver.https.timeout = "10s"' "$CONFIG_PATH"
    yq -i '.resolver.https.sni = "dns.google"' "$CONFIG_PATH"
    yq -i '.resolver.https.insecure = false' "$CONFIG_PATH"
  fi

  echo "🔄 Restarting Hysteria2 for IP $SELECTED_IP..."
  systemctl restart $SERVICE_NAME
  
  if [ "$SOCKS_CHOICE" == "1" ]; then
    echo "⚠️ WARNING: SOCKS5 will be overwritten for this IP!"
    cat > "$SOCKS_SERVICE_PATH" <<EOF
[Unit]
Description=MicroSocks Server - $SELECTED_IP
After=network-online.target
Wants=network-online.target

[Service]
LimitNOFILE=1048576
ExecStart=/usr/local/bin/microsocks -1 -i $SELECTED_IP -b $SELECTED_IP -p 1080 -u $NEW_USER -P "$NEW_PASS"
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    chmod 600 "$SOCKS_SERVICE_PATH"
    systemctl daemon-reload
    systemctl restart $SOCKS_SERVICE_NAME || systemctl enable --now $SOCKS_SERVICE_NAME
  fi
fi

# URL-encode password
ENCODED_PASS=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$NEW_PASS', safe=''))")
HYST_LINK="hysteria2://$NEW_USER:$ENCODED_PASS@$SELECTED_IP:443/?insecure=1"

if [ "$SOCKS_CHOICE" == "1" ]; then
    SOCKS_LINK="socks5://$NEW_USER:$ENCODED_PASS@$SELECTED_IP:1080"
else
    SOCKS_LINK="-"
fi

# --- SEND TO GOOGLE SHEETS ---
if [ -n "$WEBHOOK_URL" ]; then
    echo "📊 Sending data to Google Sheets..."
    SHEET_IP="${SELECTED_IP}:1080"
    
    # Base curl command
    CURL_CMD=(curl -s -L -X POST "$WEBHOOK_URL"
        --data-urlencode "ip=$SHEET_IP"
        --data-urlencode "user=$NEW_USER"
        --data-urlencode "pass=$NEW_PASS"
        --data-urlencode "hyst=$HYST_LINK"
        --data-urlencode "socks=$SOCKS_LINK")
    
    # Append sheetName only if SHEET_NAME variable is provided
    if [ -n "$SHEET_NAME" ]; then
        CURL_CMD+=(--data-urlencode "sheetName=$SHEET_NAME")
        TARGET_SHEET="$SHEET_NAME"
    else
        TARGET_SHEET="Default Sheet"
    fi
        
    HTTP_RESPONSE=$("${CURL_CMD[@]}")
        
    if [[ "$HTTP_RESPONSE" == *"Success"* ]]; then
        echo "✅ Data successfully added to the sheet ($TARGET_SHEET)!"
    else
        echo "⚠️ Error sending to sheet. Response: $HTTP_RESPONSE"
    fi
fi

echo ""
echo "=========================================="
echo "✅ PROXY SUCCESSFULLY INSTALLED!"
echo "=========================================="
echo "IP Address:   $SELECTED_IP"
echo "User:         $NEW_USER"
echo "Password:     $NEW_PASS"
echo "------------------------------------------"
echo "🟢 Hysteria2 (Port: 443)"
echo "Service:      $SERVICE_NAME"
echo "Link:"
echo "$HYST_LINK"

if [ "$SOCKS_CHOICE" == "1" ]; then
  echo "------------------------------------------"
  echo "🟡 SOCKS5 (Port: 1080)"
  echo "Service:      $SOCKS_SERVICE_NAME"
  echo "Link:"
  echo "$SOCKS_LINK"
fi

echo "=========================================="
if command -v qrencode &> /dev/null; then
  echo "=== Hysteria2 QR Code for Mobile ==="
  qrencode -t ANSIUTF8 "$HYST_LINK"
  echo "======================================="
  echo ""
fi
echo ""
