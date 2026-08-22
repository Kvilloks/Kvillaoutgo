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
    ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d'/' -f1 | \
    grep -Ev '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'
}

# ============================================================
# UNIVERSAL GATEWAY DETECTION (with real connectivity test)
# ============================================================
# Логика:
# 1) Если задана переменная MANUAL_GATEWAY - используем её без тестов (аварийный ручной режим)
# 2) Если уже есть policy routing для этого IP - берём шлюз оттуда (без теста, он уже проверен ранее)
# 3) Тестируем кандидата "общий (shared) default gateway из main таблицы" - реальным пингом
# 4) Тестируем кандидата "эвристика: сеть+1" - реальным пингом
# 5) Если оба теста не прошли - берём shared gateway как best-effort (лучше, чем ничего)

test_gateway_works() {
    local ip="$1" gw="$2" iface="$3"
    [ -z "$gw" ] || [ -z "$iface" ] && return 1
    ip route add 1.1.1.1/32 via "$gw" dev "$iface" onlink 2>/dev/null
    local result=1
    if timeout 4 ping -c 2 -W 2 -I "$ip" 1.1.1.1 &>/dev/null; then
        result=0
    fi
    ip route del 1.1.1.1/32 via "$gw" dev "$iface" onlink 2>/dev/null || true
    return $result
}

detect_gateway_for_ip() {
    local ip="$1"
    local table gw cidr iface shared_gw heuristic_gw

    read -r iface cidr <<< "$(ip -o addr show | awk -v ip="$ip" '$0 ~ ip"/" {print $2, $4}' | head -1)"
    [ -z "$iface" ] && iface=$(ip route show | awk '/^default/{print $5; exit}')

    # 1) Ручное переопределение (без тестов)
    if [ -n "$MANUAL_GATEWAY" ]; then
        echo "$MANUAL_GATEWAY|$iface"
        return
    fi

    # 2) Уже существующий policy routing (доверяем без повторного теста)
    table=$(ip rule list | grep "from $ip " | grep -oP 'lookup \K[0-9]+' | head -1)
    if [ -n "$table" ]; then
        gw=$(ip route show table "$table" 2>/dev/null | awk '/^default/{print $3; exit}')
        if [ -n "$gw" ]; then
            echo "$gw|$iface"
            return
        fi
    fi

    # 3) Кандидат: общий (shared) шлюз из main-таблицы
    shared_gw=$(ip route show | awk '/^default/{print $3; exit}')

    # 4) Кандидат: эвристика "сеть+1"
    if [ -n "$cidr" ]; then
        heuristic_gw=$(python3 -c "
import ipaddress
print(str(ipaddress.ip_interface('$cidr').network.network_address + 1))
" 2>/dev/null) || true
    fi

    # Реальный тест связи - сначала shared, потом heuristic
    if [ -n "$shared_gw" ] && test_gateway_works "$ip" "$shared_gw" "$iface"; then
        echo "$shared_gw|$iface"
        return
    fi

    if [ -n "$heuristic_gw" ] && [ "$heuristic_gw" != "$ip" ] && test_gateway_works "$ip" "$heuristic_gw" "$iface"; then
        echo "$heuristic_gw|$iface"
        return
    fi

    # 5) Best-effort fallback
    echo "${shared_gw:-$heuristic_gw}|$iface"
}

# ============================================================
# AUTO-CLEANUP
# ============================================================
cleanup_dead_services() {
    local FOUND_DEAD=0
    local SERVICE_FILE SERVICE_NAME IP_SAFE SERVICE_IP
    local SOCKS_SERVICE TABLE_ID MARK_ID
    local IFACE

    declare -A ACTIVE_IPS_MAP
    while IFS= read -r ip; do
        ACTIVE_IPS_MAP["$ip"]=1
    done < <(get_all_ips)

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

TABLE_ID=$(echo "$SELECTED_IP" | cksum | awk '{print ($1 % 8000) + 1000}')
MARK_ID=$TABLE_ID

# --- UNIVERSAL GATEWAY/INTERFACE DETECTION (с реальным тестом связности) ---
echo "🔎 Detecting working gateway for $SELECTED_IP (testing connectivity)..."
GW_IFACE=$(detect_gateway_for_ip "$SELECTED_IP")
GATEWAY="${GW_IFACE%%|*}"
INTERFACE="${GW_IFACE##*|}"

if [ -z "$GATEWAY" ] || [ -z "$INTERFACE" ]; then
    echo "⚠️ Warning: Failed to determine gateway. Routing may not work correctly."
    GATEWAY="127.0.0.1"
    INTERFACE="eth0"
fi

echo "🌐 Detected gateway for $SELECTED_IP: $GATEWAY (via $INTERFACE)"

# --- GLOBAL ANTI-DETECT OS & NETWORK OPTIMIZATIONS ---
echo "🥷 Applying global kernel network settings and DNS protection..."

if ! grep -q "nameserver 1.1.1.1" /etc/resolv.conf 2>/dev/null; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 1.0.0.1" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf
fi

cat > /etc/sysctl.d/99-proxy-tuning.conf <<EOF
net.ipv4.tcp_timestamps=0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.ip_nonlocal_bind=1
EOF
sysctl --system > /dev/null 2>&1 || true

PACKAGES="wget curl tar openssl qrencode python3 iptables iproute2 e2fsprogs"
if [ "$SOCKS_CHOICE" == "1" ]; then
    PACKAGES="$PACKAGES build-essential git"
fi

if [ ! -f "/usr/local/bin/hysteria" ] || { [ "$SOCKS_CHOICE" == "1" ] && [ ! -f "/usr/local/bin/microsocks" ]; }; then
  echo "📦 Installing base dependencies..."
  apt update
  apt install -y $PACKAGES
fi

if ! command -v yq &> /dev/null; then
  echo "📥 Installing yq ($YQ_ARCH architecture)..."
  wget -4 --timeout=30 --tries=3 -qO /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${YQ_ARCH}"
  chmod +x /usr/local/bin/yq
fi

if [ ! -f "/usr/local/bin/hysteria" ]; then
  echo "⬇️  Fetching the latest Hysteria2 version..."

  # Метод 1 (основной, официальный): собственный API Hysteria2, без лимитов GitHub
  VERSION=$(curl -4 -s --max-time 10 \
    "https://api.hy2.io/v1/update?cver=installscript&plat=linux&arch=${HYS_ARCH}&chan=release&side=server" \
    | grep -oP '"lver":\s*"v[0-9.]+"' | cut -d'"' -f4)
  [ -n "$VERSION" ] && VERSION="app/$VERSION"

  # Метод 2 (fallback): GitHub API
  if [ -z "$VERSION" ]; then
    echo "⚠️  api.hy2.io недоступен, пробуем через GitHub API..."
    VERSION=$(curl -4 -s --max-time 10 https://api.github.com/repos/apernet/hysteria/releases/latest \
               | grep '"tag_name":' | cut -d'"' -f4)
  fi

  # Метод 3 (fallback): редирект со страницы /releases/latest — не подпадает под лимит API
  if [ -z "$VERSION" ]; then
    echo "⚠️  GitHub API недоступен/лимит исчерпан, пробуем через редирект..."
    VERSION=$(curl -4 -s --max-time 10 -o /dev/null -w '%{redirect_url}' \
               https://github.com/apernet/hysteria/releases/latest \
               | sed -n 's#.*/tag/##p')
    VERSION=$(python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "$VERSION")
  fi

  if [ -z "$VERSION" ]; then
    echo "❌ Не удалось определить версию Hysteria2 (все 3 метода не сработали)."
    echo "   Укажите версию вручную, например: VERSION=app/v2.12.1 $0"
    exit 1
  fi

  echo "📥 Downloading Hysteria2 version $VERSION ($HYS_ARCH architecture)..."
  if ! wget -4 --timeout=30 --tries=3 -qO /usr/local/bin/hysteria \
       "https://github.com/apernet/hysteria/releases/download/${VERSION}/hysteria-linux-${HYS_ARCH}"; then
    echo "❌ Ошибка загрузки бинарника Hysteria2. Проверьте сеть/версию."
    exit 1
  fi
else
  echo "✅ Hysteria2 is already installed."
fi
chmod +x /usr/local/bin/hysteria

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
if [ "$SOCKS_CHOICE" == "1" ]; then
    chmod +x /usr/local/bin/microsocks
fi

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
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
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
ExecStartPre=-/bin/bash -c "iptables -t mangle -A POSTROUTING -s $SELECTED_IP -j TTL --ttl-set 128"

ExecStartPre=-/bin/bash -c "tc qdisc show dev $INTERFACE | grep -q 'htb' || tc qdisc add dev $INTERFACE root handle 1: htb default 10"
ExecStartPre=-/bin/bash -c "tc class show dev $INTERFACE | grep -q 'classid 1:10' || tc class add dev $INTERFACE parent 1: classid 1:10 htb rate 1000mbit"
ExecStartPre=-/bin/bash -c "tc class del dev $INTERFACE classid 1:$MARK_ID 2>/dev/null"
ExecStartPre=-/bin/bash -c "tc class add dev $INTERFACE parent 1: classid 1:$MARK_ID htb rate 1000mbit"
ExecStartPre=-/bin/bash -c "tc qdisc add dev $INTERFACE parent 1:$MARK_ID handle $MARK_ID: netem delay ${DELAY}ms"
ExecStartPre=-/bin/bash -c "tc filter add dev $INTERFACE protocol ip parent 1:0 prio $MARK_ID u32 match ip src $SELECTED_IP flowid 1:$MARK_ID"

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
    echo "🔧 Adding secure DNS (Cloudflare DoH) to the existing config..."
    yq -i '.resolver.type = "https"' "$CONFIG_PATH"
    yq -i '.resolver.https.addr = "1.1.1.1:443"' "$CONFIG_PATH"
    yq -i '.resolver.https.timeout = "10s"' "$CONFIG_PATH"
    yq -i '.resolver.https.sni = "cloudflare-dns.com"' "$CONFIG_PATH"
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

ENCODED_PASS=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$NEW_PASS', safe=''))")
HYST_LINK="hysteria2://$NEW_USER:$ENCODED_PASS@$SELECTED_IP:443/?insecure=1"

if [ "$SOCKS_CHOICE" == "1" ]; then
    SOCKS_LINK="socks5://$NEW_USER:$ENCODED_PASS@$SELECTED_IP:1080"
else
    SOCKS_LINK="-"
fi

if [ -n "$WEBHOOK_URL" ]; then
    echo "📊 Sending data to Google Sheets..."
    SHEET_IP="${SELECTED_IP}:1080"

    CURL_CMD=(curl -4 -s -L -X POST "$WEBHOOK_URL"
        --data-urlencode "ip=$SHEET_IP"
        --data-urlencode "user=$NEW_USER"
        --data-urlencode "pass=$NEW_PASS"
        --data-urlencode "hyst=$HYST_LINK"
        --data-urlencode "socks=$SOCKS_LINK")

    if [ -n "$SHEET_NAME" ]; then
        CURL_CMD+=(--data-urlencode "sheetName=$SHEET_NAME")
        TARGET_SHEET="$SHEET_NAME"
    else
        TARGET_SHEET="Default Sheet"
    fi

    HTTP_RESPONSE=$("${CURL_CMD[@]}") || HTTP_RESPONSE="curl_failed"

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
