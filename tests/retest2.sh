#!/usr/bin/env bash
# Ретест-2: (1) нативный AmneziaWG с фиксом IPv6, (2) ключ p1Fqp с рабочим профилем
set -u
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1   # корень репозитория
AWGONLY=0
[ "${1:-}" = "--awg-only" ] && AWGONLY=1
R=./results/retest2-report.txt; : > "$R"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
bare(){ echo "$*" | tee -a "$R"; }
S="${TMPDIR:-/tmp}"; IF=awgtest; AC="$S/$IF.conf"
PID=""; AWGUP=0
TRACE="https://www.cloudflare.com/cdn-cgi/trace"

cleanup(){
  [ -n "$PID" ] && { kill "$PID" 2>/dev/null; sleep 1; kill -9 "$PID" 2>/dev/null; }
  if [ "$AWGUP" = "1" ] || ip link show "$IF" >/dev/null 2>&1; then
    echo "[cleanup] гашу $IF"
    sudo awg-quick down "$AC" 2>/dev/null || sudo awg-quick down "$IF" 2>/dev/null || sudo ip link del "$IF" 2>/dev/null
  fi
}
trap cleanup EXIT; trap 'cleanup; exit 130' INT TERM

bare "=================================================="
bare "  РЕТЕСТ-2: нативный AWG (фикс IPv6) + ключ p1Fqp"
bare "  $(date '+%Y-%m-%d %H:%M:%S %z')"
bare "=================================================="
bare "Сеть:"; ip -brief addr | grep -v DOWN | tee -a "$R" >/dev/null; ip -brief addr | grep -v DOWN >> "$R"
DEF=$(ip route show default | head -1); bare "Дефолт: $DEF"
case "$DEF" in *172.20.10.*) bare "-> тетеринг iPhone: МОБИЛЬНАЯ СЕТЬ, тест по адресу";; *) bare "-> ВНИМАНИЕ: не похоже на мобильную сеть!";; esac
ip link show throne-tun >/dev/null 2>&1 && bare "!!! throne-tun ПОДНЯТ — VPN не выключен" || bare "OK: throne-tun нет"
bare ""
log "Запрашиваю sudo (нужен для awg-quick)..."
if sudo -v 2>/dev/null; then bare "SUDO: получен"; SUDO=1; else bare "SUDO: НЕ получен — этап 1 пропускается"; SUDO=0; fi

bare ""; bare "=================================================="
bare "  ЭТАП 1. НАТИВНЫЙ AmneziaWG (IPv6 убран из конфига)"
bare "=================================================="
bare "IPv6 в системе отключён, поэтому из временной копии удаляются:"
bare "  IPv6 в Address, IPv6 в DNS, ::/0 в AllowedIPs. Остальное как в оригинале."
for f in awg-samples/megafon-ok-1180.conf awg-samples/megafon-ok-903.conf awg-samples/megafon-ok-500-jc120.conf; do
  [ "$SUDO" = "0" ] && { bare "  $(basename $f): ПРОПУЩЕН (нет sudo)"; continue; }
  EP=$(grep -oP 'Endpoint = \K.*' "$f")
  bare ""; bare "--------------------------------------------------"
  log "AWG: $(basename $f)  (Endpoint $EP)"
  sed -E -e 's|^(Address = [0-9.]+).*|\1/32|' -e "/^DNS = /d" \
         -e 's|^AllowedIPs = .*|AllowedIPs = 0.0.0.0/0|' "$f" > "$AC"
  chmod 600 "$AC"
  bare "  Address/DNS/AllowedIPs после фикса:"; grep -E '^(Address|DNS|AllowedIPs|MTU) ' "$AC" | sed 's/^/    /' | tee -a "$R" >/dev/null; grep -E '^(Address|DNS|AllowedIPs|MTU) ' "$AC" | sed 's/^/    /' >> "$R"
  OUT=$(sudo awg-quick up "$AC" 2>&1); RC=$?
  if [ $RC -ne 0 ]; then
    bare "  awg-quick up НЕ СРАБОТАЛ (rc=$RC):"; echo "$OUT" | sed 's/^/    /' >> "$R"; echo "$OUT" | sed 's/^/    /'
    sudo ip link del "$IF" 2>/dev/null; continue
  fi
  AWGUP=1; bare "  интерфейс поднят, жду 5 с..."; sleep 5
  T=$(curl -s --max-time 15 "$TRACE" 2>/dev/null)
  W=$(echo "$T" | grep -oP '^warp=\K.*'); I=$(echo "$T" | grep -oP '^ip=\K.*')
  if [ "$W" = "on" ] || [ "$W" = "plus" ]; then bare "  РЕЗУЛЬТАТ: OK — warp=$W ip=$I"; else bare "  РЕЗУЛЬТАТ: FAIL — warp='${W:-нет}' (ответ: ${T:0:60})"; fi
  sudo awg-quick down "$AC" >/dev/null 2>&1; AWGUP=0; sleep 2
  ip link show "$IF" >/dev/null 2>&1 && bare "  !!! интерфейс не исчез" || bare "  интерфейс опущен"
  BACK=$(curl -s --max-time 10 "$TRACE" 2>/dev/null | grep -c '^ip=')
  [ "$BACK" -ge 1 ] && bare "  связь восстановлена" || { bare "  !!! СВЯЗЬ НЕ ВЕРНУЛАСЬ. Аварийно: sudo awg-quick down $IF ; sudo ip link del $IF"; break; }
done

bare ""; bare "=================================================="
bare "  ЭТАП 2. КЛЮЧ p1Fqp С РАБОЧИМ ПРОФИЛЕМ (вариант 3.1)"
bare "=================================================="
[ "$AWGONLY" = "1" ] && { bare ""; bare "ЭТАП 2 ПРОПУЩЕН (--awg-only)"; exit 0; }
I1=$(grep -oP 'I1 = <b 0x\K[0-9a-f]+' awg-samples/megafon-ok-500-jc120.conf)
bare "hex I1 из ok-500: ${#I1} символов ($(( ${#I1} / 2 )) байт), начало ${I1:0:16}"
RAND=$(for i in $(seq 8); do printf '{"type":"rand","packet":"23-911","delay":"1-3"},'; done | sed 's/,$//')
run_xray(){
  local name="$1" key="$2" v6="$3"
  cat > "$S/r2.json" <<EOF
{"log":{"loglevel":"debug"},
 "inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],
 "outbounds":[
  {"tag":"warp","protocol":"wireguard","streamSettings":{"sockopt":{"dialerProxy":"noise-out"}},"settings":{
    "secretKey":"$key","address":["172.16.0.2/32","$v6"],"mtu":1280,
    "peers":[{"publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint":"162.159.192.1:500","keepAlive":5,"allowedIPs":["0.0.0.0/0","::/0"]}]}},
  {"tag":"noise-out","protocol":"freedom","settings":{"noises":[{"type":"hex","packet":"$I1"},$RAND]}}
 ],
 "routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":"warp"}]}}
EOF
  bare ""; log "ВАРИАНТ: $name (ключ ${key:0:5})"
  if ! xray run -test -c "$S/r2.json" >/dev/null 2>&1; then bare "  конфиг НЕ валиден"; return; fi
  nohup xray run -c "$S/r2.json" > "$S/r2-$name.log" 2>&1 & PID=$!
  sleep 5
  local T W RC
  T=$(curl -s --max-time 12 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?
  [ -z "$T" ] && { sleep 2; T=$(curl -s --max-time 12 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?; }
  W=$(echo "$T" | grep -oP '^warp=\K.*')
  local SI RI
  SI=$(grep -ac 'Sending handshake initiation' "$S/r2-$name.log"); RI=$(grep -ac 'Received handshake response' "$S/r2-$name.log")
  if [ "$W" = "on" ] || [ "$W" = "plus" ]; then
    bare "  РЕЗУЛЬТАТ: OK — warp=$W  ip=$(echo "$T" | grep -oP '^ip=\K.*')  хендшейк $SI/$RI"
  else
    bare "  РЕЗУЛЬТАТ: FAIL — нет ответа (curl rc=$RC)  хендшейк отправлено=$SI получено=$RI"
  fi
  kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; sleep 1
}
run_xray "IFkdR-control" "IFkdRgGBo+opmk2ra5WUGJsvlf4e9+QkCkgeeVleR3o=" "2606:4700:110:8e79:4cda:60e6:6ac5:9143/128"
run_xray "p1Fqp-test"    "p1FqpOMu1cDKDc8+7INZPyrunI/Z4FsvKeMYw7ktrIk=" "2606:4700:110:8798:f77d:7e3b:a4ad:2943/128"

bare ""; bare "=================================================="
bare "  ГОТОВО. Отчёт: $R"
bare "  Сырые логи xray: $S/r2-*.log (в репозиторий не идут)"
bare "=================================================="
