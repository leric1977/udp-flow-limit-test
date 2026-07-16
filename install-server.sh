#!/usr/bin/env bash
set -Eeuo pipefail

REPO_RAW="https://raw.githubusercontent.com/leric1977/udp-flow-limit-test/main"
INSTALL_DIR="/opt/udp-flow-limit-test"
CONFIG_DIR="/etc/udp-flow-limit-test"
PORTS_FILE="${CONFIG_DIR}/ports.conf"
OLD_PORTS_FILE="${CONFIG_DIR}/ports.previous"
CLEANUP_PORTS_FILE="${CONFIG_DIR}/ports.cleanup"
SERVICE_NAME="udp-flow-limit-test"
FIREWALL_HELPER="/usr/local/sbin/udp-flow-limit-firewall"
FIREWALL_SERVICE="udp-flow-limit-firewall"
DISCOVERY_PORT=62970
TEST_PORT_COUNT=10
PORT_MIN=20000
PORT_MAX=60999
LOG_LEVEL="${UDP_TEST_LOG_LEVEL:-INFO}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: curl ... | sudo bash"
  exit 1
fi

case "$LOG_LEVEL" in
  DEBUG|INFO|WARNING|ERROR) ;;
  *) echo "Invalid log level: $LOG_LEVEL"; exit 1 ;;
esac

install_packages() {
  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  command -v curl >/dev/null 2>&1 || missing+=(curl ca-certificates)

  if ((${#missing[@]} == 0)); then
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${missing[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${missing[@]}"
  else
    echo "Cannot install required packages automatically. Install Python 3 and curl."
    exit 1
  fi
}

install_packages
install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"

systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
systemctl stop "${FIREWALL_SERVICE}.service" 2>/dev/null || true

if [[ -f "$PORTS_FILE" ]]; then
  cp -f "$PORTS_FILE" "$OLD_PORTS_FILE"
else
  : > "$OLD_PORTS_FILE"
fi

{
  cat "$OLD_PORTS_FILE" 2>/dev/null || true
  echo 62971
} | awk '/^[0-9]+$/ && !seen[$1]++ {print $1}' > "$CLEANUP_PORTS_FILE"

python3 - "$PORTS_FILE" "$TEST_PORT_COUNT" "$PORT_MIN" "$PORT_MAX" "$DISCOVERY_PORT" <<'PORTGEN'
import random
import socket
import sys
from pathlib import Path

path = Path(sys.argv[1])
count = int(sys.argv[2])
minimum = int(sys.argv[3])
maximum = int(sys.argv[4])
discovery = int(sys.argv[5])
rng = random.SystemRandom()
selected = []
attempts = 0

while len(selected) < count and attempts < 20000:
    attempts += 1
    port = rng.randint(minimum, maximum)
    if port == discovery or port in selected:
        continue
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    selected.append(port)

if len(selected) != count:
    raise SystemExit(f"Could not select {count} free UDP ports")
path.write_text("\n".join(map(str, selected)) + "\n", encoding="ascii")
PORTGEN

cat >"$FIREWALL_HELPER" <<'FWHELPER'
#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-apply}"
PORTS_FILE="${2:-/etc/udp-flow-limit-test/ports.conf}"
DISCOVERY_PORT="${3:-62970}"
COMMENT_PREFIX="udp-flow-limit-test:"
MODE="none"
DETAIL="No active host firewall detected"

mapfile -t FILE_PORTS < <(awk '/^[0-9]+$/ && $1 >= 1 && $1 <= 65535 && !seen[$1]++ {print $1}' "$PORTS_FILE" 2>/dev/null || true)
PORTS=("$DISCOVERY_PORT" "${FILE_PORTS[@]}")

log() { printf '[firewall] %s\n' "$*"; }

ufw_is_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | grep -Eqi '^Status:[[:space:]]*active|^Состояние:[[:space:]]*актив'
}

firewalld_is_active() {
  command -v firewall-cmd >/dev/null 2>&1 || return 1
  systemctl is-active --quiet firewalld 2>/dev/null
}

find_nft_input_chain() {
  command -v nft >/dev/null 2>&1 || return 1
  nft list ruleset 2>/dev/null | awk '
    /^table (inet|ip) / { family=$2; table_name=$3; gsub(/[{}]/,"",table_name) }
    /^[[:space:]]*chain[[:space:]]+/ { chain_name=$2; gsub(/[{}]/,"",chain_name) }
    /hook[[:space:]]+input/ && family != "" && table_name != "" && chain_name != "" {
      print family, table_name, chain_name; exit
    }
  '
}

iptables_has_input_chain() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -S INPUT >/dev/null 2>&1
}

remove_ufw() {
  local port
  for port in "${PORTS[@]}"; do
    ufw --force delete allow "${port}/udp" >/dev/null 2>&1 || true
  done
}

apply_ufw() {
  local port
  MODE="ufw"; DETAIL="UFW"
  for port in "${PORTS[@]}"; do
    if ! ufw status 2>/dev/null | grep -Eq "${port}/udp([[:space:]]|$).*ALLOW"; then
      ufw allow "${port}/udp"
    fi
  done
}

remove_firewalld() {
  local port
  for port in "${PORTS[@]}"; do
    firewall-cmd --quiet --query-port="${port}/udp" && firewall-cmd --remove-port="${port}/udp" >/dev/null || true
    firewall-cmd --quiet --permanent --query-port="${port}/udp" && firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null || true
  done
}

apply_firewalld() {
  local port
  MODE="firewalld"; DETAIL="firewalld default zone"
  for port in "${PORTS[@]}"; do
    firewall-cmd --quiet --query-port="${port}/udp" || firewall-cmd --add-port="${port}/udp" >/dev/null
    firewall-cmd --quiet --permanent --query-port="${port}/udp" || firewall-cmd --permanent --add-port="${port}/udp" >/dev/null
  done
}

remove_nftables() {
  local chain_info family table_name chain_name handle
  chain_info="$(find_nft_input_chain || true)"
  [[ -n "$chain_info" ]] || return 0
  read -r family table_name chain_name <<<"$chain_info"
  while read -r handle; do
    [[ -n "$handle" ]] || continue
    nft delete rule "$family" "$table_name" "$chain_name" handle "$handle" || true
  done < <(
    nft -a list chain "$family" "$table_name" "$chain_name" 2>/dev/null |
    awk -v tag="$COMMENT_PREFIX" 'index($0, tag) {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}'
  )
}

apply_nftables() {
  local chain_info family table_name chain_name port comment
  chain_info="$(find_nft_input_chain || true)"
  [[ -n "$chain_info" ]] || return 1
  read -r family table_name chain_name <<<"$chain_info"
  MODE="nftables"; DETAIL="nftables: ${family} ${table_name} ${chain_name}"
  for port in "${PORTS[@]}"; do
    comment="${COMMENT_PREFIX}${port}"
    if ! nft list chain "$family" "$table_name" "$chain_name" 2>/dev/null | grep -Fq "$comment"; then
      nft insert rule "$family" "$table_name" "$chain_name" udp dport "$port" counter accept comment "$comment"
    fi
  done
}

remove_iptables() {
  local port
  for port in "${PORTS[@]}"; do
    while iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do
      iptables -D INPUT -p udp --dport "$port" -j ACCEPT || break
    done
  done
}

apply_iptables() {
  local port
  MODE="iptables"; DETAIL="iptables INPUT"
  for port in "${PORTS[@]}"; do
    iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null ||
      iptables -I INPUT 1 -p udp --dport "$port" -j ACCEPT
  done
}

if ufw_is_active; then
  [[ "$ACTION" == "remove" ]] && remove_ufw || apply_ufw
elif firewalld_is_active; then
  [[ "$ACTION" == "remove" ]] && remove_firewalld || apply_firewalld
else
  NFT_CHAIN="$(find_nft_input_chain || true)"
  if [[ -n "$NFT_CHAIN" ]]; then
    [[ "$ACTION" == "remove" ]] && remove_nftables || apply_nftables
  elif iptables_has_input_chain; then
    [[ "$ACTION" == "remove" ]] && remove_iptables || apply_iptables
  else
    MODE="none"; DETAIL="No active host input firewall detected"
  fi
fi

if [[ "$ACTION" == "apply" ]]; then
  install -d -m 0755 /run/udp-flow-limit-test
  printf '%s\n' "$MODE" > /run/udp-flow-limit-test/firewall-mode
  printf '%s\n' "$DETAIL" > /run/udp-flow-limit-test/firewall-detail
  log "Mode: $MODE"
  log "Detail: $DETAIL"
  log "Allowed UDP ports: ${PORTS[*]}"
fi
FWHELPER
chmod 0755 "$FIREWALL_HELPER"

"$FIREWALL_HELPER" remove "$CLEANUP_PORTS_FILE" "$DISCOVERY_PORT" || true
"$FIREWALL_HELPER" apply "$PORTS_FILE" "$DISCOVERY_PORT"

cat >"/etc/systemd/system/${FIREWALL_SERVICE}.service" <<EOF
[Unit]
Description=Open discovery and random UDP ports for flow-limit test
After=network-online.target nftables.service firewalld.service ufw.service
Wants=network-online.target
Before=${SERVICE_NAME}.service

[Service]
Type=oneshot
ExecStart=${FIREWALL_HELPER} apply ${PORTS_FILE} ${DISCOVERY_PORT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

curl -fsSL "$REPO_RAW/server/udp_flow_server.py" -o "$INSTALL_DIR/udp_flow_server.py"
chmod 0755 "$INSTALL_DIR/udp_flow_server.py"
chmod 0644 "$PORTS_FILE"

cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=UDP flow-limit test server on 10 random ports
After=network-online.target ${FIREWALL_SERVICE}.service
Wants=network-online.target
Requires=${FIREWALL_SERVICE}.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/udp_flow_server.py --host 0.0.0.0 --discovery-port ${DISCOVERY_PORT} --ports-file ${PORTS_FILE} --log-level ${LOG_LEVEL}
Restart=on-failure
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_UNIX
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${FIREWALL_SERVICE}.service" "${SERVICE_NAME}.service" >/dev/null
systemctl restart "${FIREWALL_SERVICE}.service"
systemctl restart "${SERVICE_NAME}.service"
sleep 1

python3 - "$DISCOVERY_PORT" "$PORTS_FILE" <<'LOCALCHECK'
import json
import socket
import sys
from pathlib import Path

discovery = int(sys.argv[1])
ports = [int(x) for x in Path(sys.argv[2]).read_text().split()]

def request(port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(payload, ("127.0.0.1", port))
    data, _ = sock.recvfrom(65535)
    sock.close()
    return data

info = json.loads(request(discovery, b"DISCOVER|2").decode())
if info.get("test_ports") != ports:
    raise SystemExit("Discovery returned an unexpected port list")
for port in ports:
    reply = request(port, b"PING").decode("ascii", errors="replace")
    if not reply.startswith("PONG|udp-flow-limit-test|2|"):
        raise SystemExit(f"No valid PONG on UDP/{port}: {reply!r}")
print("Local discovery and all 10 PING checks: OK")
LOCALCHECK

echo
echo "========== INSTALLATION COMPLETE =========="
echo "Discovery UDP port: ${DISCOVERY_PORT}"
echo "Random test ports:  $(paste -sd, "$PORTS_FILE")"
echo "Firewall mode:      $(cat /run/udp-flow-limit-test/firewall-mode 2>/dev/null || echo unknown)"
echo "Firewall detail:    $(cat /run/udp-flow-limit-test/firewall-detail 2>/dev/null || echo unknown)"
echo
systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
echo
echo "Listening sockets:"
ss -lunp | grep -E ":(${DISCOVERY_PORT}|$(paste -sd'|' "$PORTS_FILE"))[[:space:]]" || true
echo
echo "The installer opens only 11 UDP ports: one discovery port and ten random test ports."
echo "It does not open every UDP port. External cloud firewalls must still allow these ports."
echo "Show ports later: cat ${PORTS_FILE}"
echo "Show logs: journalctl -u ${SERVICE_NAME} -f"
