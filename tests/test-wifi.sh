#!/usr/bin/env bash
# Проверка прод-профиля (QUIC + :500 + MTU1280) на проводном/WiFi
set -u
cd "$(dirname "$0")/.." || exit 1
R=./results/wifi-report.txt; mkdir -p results; : > "$R"
S="${TMPDIR:-/tmp}"; PID=""
TRACE="https://www.cloudflare.com/cdn-cgi/trace"
# Сырой лог идёт с loglevel=debug и содержит домены и коннекты пользователя, поэтому
# остаётся только в "$S". В репозиторий публикуется копия, отфильтрованная по белому
# списку: старт ядра + события wireguard/handshake/keepalive.
FILTER_RE='^#|^Xray [0-9]|^A unified platform|\] core: |\] app/log: |\] infra/conf/serial: |\] transport/internet/(tcp|udp): listening|\] proxy/wireguard: |\] (peer\(|Routine:|UAPI:|Device|Interface|Binding|Bind|Starting|Stopping|Sending|Receiving|Received|Handshake|Invalid|Failed|Retrying|Obtained|Zeroing|Resetting|Adding|Removing|Creating|Keepalive|Sending keepalive)'
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
bare(){ echo "$*" | tee -a "$R"; }
cleanup(){ [ -n "$PID" ] && { kill "$PID" 2>/dev/null; sleep 1; kill -9 "$PID" 2>/dev/null; }; }
trap cleanup EXIT; trap 'cleanup; exit 130' INT TERM

bare "=============================================================="
bare "  ПРОВЕРКА ПРОД-ПРОФИЛЯ НА WiFi/ПРОВОДНОМ   $(date '+%F %T %z')"
bare "=============================================================="
bare "Интерфейсы:"; ip -brief addr | grep -v DOWN | sed 's/^/  /' >> "$R"; ip -brief addr | grep -v DOWN | sed 's/^/  /'
DEF=$(ip route show default | head -1); bare "Дефолт: $DEF"
case "$DEF" in
  *172.20.10.*) bare "-> ВНИМАНИЕ: это тетеринг iPhone (мобильная), а не WiFi-роутер!";;
  *) bare "-> не тетеринг: похоже на домашний WiFi/провод, тест по адресу";;
esac
ip link show throne-tun >/dev/null 2>&1 && bare "!!! throne-tun ПОДНЯТ — VPN не выключен, результат недостоверен" || bare "OK: throne-tun нет (VPN выключен)"

run(){  # имя, конфиг, сколько секунд стабильности (0 = без), имя публикуемого лога
  local name="$1" cfg="$2" stab="$3" pub="$4"
  bare ""; bare "--------------------------------------------------------------"
  log "ВАРИАНТ: $name"
  bare "  конфиг: $cfg"
  bare "  endpoint: $(python3 -c "import json;d=json.load(open('$cfg'));print([o for o in d['outbounds'] if o.get('protocol')=='wireguard'][0]['settings']['peers'][0]['endpoint'])" 2>/dev/null)"
  bare "  mtu: $(python3 -c "import json;d=json.load(open('$cfg'));print([o for o in d['outbounds'] if o.get('protocol')=='wireguard'][0]['settings'].get('mtu'))" 2>/dev/null)"
  bare "  noises: $(python3 -c "
import json;d=json.load(open('$cfg'))
n=[o for o in d['outbounds'] if o.get('protocol')=='freedom' and 'noises' in o.get('settings',{})]
if not n: print('нет (чистый WG)')
else:
    ns=n[0]['settings']['noises']
    print(len(ns),'элементов:', ', '.join(sorted({x['type'] for x in ns})))" 2>/dev/null)"
  xray run -test -c "$cfg" >/dev/null 2>&1 || { bare "  КОНФИГ НЕ ВАЛИДЕН"; return; }
  nohup xray run -c "$cfg" > "$S/wifi-$name.log" 2>&1 & PID=$!
  sleep 5
  local T W RC
  T=$(curl -s --max-time 15 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?
  [ -z "$T" ] && { sleep 2; T=$(curl -s --max-time 15 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?; }
  W=$(echo "$T" | grep -oP '^warp=\K.*')
  local SI RI
  SI=$(grep -ac 'Sending handshake initiation' "$S/wifi-$name.log" 2>/dev/null || echo 0)
  RI=$(grep -ac 'Received handshake response' "$S/wifi-$name.log" 2>/dev/null || echo 0)
  if [ "$W" = "on" ] || [ "$W" = "plus" ]; then
    bare "  РЕЗУЛЬТАТ: OK — warp=$W  ip=$(echo "$T" | grep -oP '^ip=\K.*')  хендшейк $SI/$RI"
    if [ "$stab" -gt 0 ]; then
      bare "  стабильность $stab с (запрос каждые 20 с):"
      local ok=0 fail=0 i=0
      while [ $((i*20)) -lt "$stab" ]; do
        i=$((i+1)); sleep 20
        local t2 w2
        t2=$(curl -s --max-time 12 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null)
        w2=$(echo "$t2" | grep -oP '^warp=\K.*')
        if [ "$w2" = "on" ] || [ "$w2" = "plus" ]; then ok=$((ok+1)); bare "    $i) +$((i*20))s OK"; else fail=$((fail+1)); bare "    $i) +$((i*20))s FAIL"; fi
      done
      bare "  итог стабильности: OK=$ok FAIL=$fail"
      SI=$(grep -ac 'Sending handshake initiation' "$S/wifi-$name.log"); RI=$(grep -ac 'Received handshake response' "$S/wifi-$name.log")
      bare "  хендшейков за всё время: отправлено=$SI получено=$RI"
    fi
  else
    bare "  РЕЗУЛЬТАТ: FAIL — нет ответа (curl rc=$RC)  хендшейк отправлено=$SI получено=$RI"
  fi
  kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; sleep 2
  {
    echo "# NOTE: log filtered for publication — only Xray startup and WireGuard transport/handshake events are kept."
    echo "# Проверка на домашнем WiFi, вариант $name"
    echo "# Отчёт прогона: results/wifi-report.txt"
    grep -aE "$FILTER_RE" "$S/wifi-$name.log"
  } > "./results/wifi-$pub.log"
  bare "  публикуемый лог: ./results/wifi-$pub.log"
}

# A: новый прод-профиль (QUIC + 162.159.192.1:500 + MTU 1280) + стабильность 100 с
sed 's/"loglevel": *"warning"/"loglevel":"debug"/' warp-xray.json > "$S/wifi-A.json"
run "A-quic-500-mtu1280" "$S/wifi-A.json" 100 "A-quic-500-mtu1280"
# B: старый SIP-профиль (8.6.112.7:946 + MTU 1420) — раньше работал на проводном
sed 's/"loglevel": *"warning"/"loglevel":"debug"/' legacy/warp-xray-sip-profile.json > "$S/wifi-B.json"
run "B-sip-946-mtu1420" "$S/wifi-B.json" 0 "B-sip-946-mtu1420"
# C: контроль — чистый WG без обфускации на том же endpoint, что у A
python3 - "$S/wifi-A.json" "$S/wifi-C.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
d['outbounds']=[o for o in d['outbounds'] if not (o.get('protocol')=='freedom' and 'noises' in o.get('settings',{}))]
for o in d['outbounds']:
    if o.get('protocol')=='wireguard': o.pop('streamSettings',None)
json.dump(d,open(sys.argv[2],'w'),indent=1)
PY
run "C-чистый-WG-контроль" "$S/wifi-C.json" 0 "C-cleanwg-control"

bare ""; bare "=============================================================="
bare "  ГОТОВО. Отчёт: $R   Отфильтрованные логи: ./results/wifi-*.log"
bare "  Сырые debug-логи: $S/wifi-*.log — в репозиторий не идут (домены пользователя)"
bare "=============================================================="
