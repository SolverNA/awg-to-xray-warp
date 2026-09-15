#!/usr/bin/env bash
# test-warp.sh — A/B тест WARP через Xray.
#   Вариант A (обфускация)      : ./warp-xray.json как есть (wireguard + dialerProxy -> noises)
#   Вариант B (контроль, без обф): копия A БЕЗ dialerProxy/noises, генерируется программно
#                                  в scratchpad (креды в скрипте не хардкодятся)
# Цель — доказать, нужна ли обфускация: A должен работать, B (чистый WireGuard)
# ожидаемо режется ТСПУ (хендшейк уходит, ответа нет).
#
# Запуск:  ./test-warp.sh          (в конце гасит оба инстанса)
#          ./test-warp.sh --keep   (оставляет жить ТОЛЬКО инстанс A; B гасится всегда)
# Всё пишется в stdout и в ./test-report.txt (перезаписывается при каждом запуске).
# Без sudo, без изменения маршрутов/nft/iptables/ip rule.

set -u

cd "$(dirname "$(readlink -f "$0")")" || exit 1

# --- пути и порты ----------------------------------------------------------
CONFIG_A="./warp-xray.json"
SCRATCH="${SCRATCH_DIR:-${TMPDIR:-/tmp}}"
CONFIG_B="$SCRATCH/warp-noobf.json"

REPORT="./test-report.txt"
XLOG_A="./xray-A.log"
XLOG_B="./xray-B.log"
XPID_A="./xray-A.pid"
XPID_B="./xray-B.pid"

SOCKS_HOST="127.0.0.1"
PORT_A="10808"
HTTP_A="10809"
PORT_B="10818"
HTTP_B="10819"
PROXY_A="socks5h://${SOCKS_HOST}:${PORT_A}"
PROXY_B="socks5h://${SOCKS_HOST}:${PORT_B}"

# ВАЖНО: без завершающего слеша — на .../trace/ Cloudflare отдаёт 404.
TRACE_URL="https://www.cloudflare.com/cdn-cgi/trace"

# стабильность A: 9 попыток с интервалом 20 с = 160 с (2 мин 40 с)
STAB_ATTEMPTS=9
STAB_INTERVAL=20
# тест B: 4 попытки по 15 с = до 60 с
B_ATTEMPTS=4
B_MAXTIME=15

KEEP=0
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    *) echo "Неизвестный аргумент: $a (поддерживается только --keep)" >&2; exit 2 ;;
  esac
done

: > "$REPORT"

ts() { date '+%H:%M:%S'; }
log() { printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$REPORT"; }
bare() { printf '%s\n' "$*" | tee -a "$REPORT"; }
sect() {
  bare ""
  bare "==================================================================="
  bare "== $*"
  bare "==================================================================="
}
pipe_out() { sed 's/^/    /' | tee -a "$REPORT"; }

# ---- итоговые переменные --------------------------------------------------
A_WARP="не проверено"
A_IP4="не проверено"
A_IP6="не проверено"
A_UDP="не проверено"
A_LAT="n/a"
A_SPEED="n/a"
A_STAB_OK=0
A_STAB_FAIL=0
A_STAB_BAD=0
A_STAB_FIRST_FAIL=""
A_STAB_TOTAL=0
B_RESULT="не проверено"
B_DETAIL=""
B_HS_SENT=0
B_HS_RECV=0
B_HS_INCOMPLETE=0
A_HS_SENT=0
A_HS_RECV=0
A_HS_INCOMPLETE=0
PID_A=""
PID_B=""

# ---- гашение по PID (никакого pkill) --------------------------------------
# stop_by_pid <label> <pid> <port>
stop_by_pid() {
  _lbl="$1"; _pid="$2"; _port="$3"
  case "${_pid:-}" in ''|*[!0-9]*) return 0 ;; esac
  if kill -0 "$_pid" 2>/dev/null; then
    log "Гашу xray-${_lbl} (PID $_pid) через SIGTERM"
    kill -TERM "$_pid" 2>/dev/null || true
    _n=0
    while kill -0 "$_pid" 2>/dev/null && [ "$_n" -lt 20 ]; do
      _n=$((_n+1)); sleep 0.5
    done
    if kill -0 "$_pid" 2>/dev/null; then
      log "xray-${_lbl} не умер за 10 с — SIGKILL"
      kill -KILL "$_pid" 2>/dev/null || true
      sleep 1
    fi
  fi
  if kill -0 "$_pid" 2>/dev/null; then
    log "FAIL: процесс xray-${_lbl} ($_pid) всё ещё жив"
  else
    log "OK: процесс xray-${_lbl} ($_pid) мёртв"
  fi
  if ss -ltnup 2>/dev/null | grep -q ":${_port}[[:space:]]"; then
    log "FAIL: порт ${_port} всё ещё занят"
  else
    log "OK: порт ${_port} освободился"
  fi
}

stop_A() {
  [ -n "$PID_A" ] || return 0
  stop_by_pid A "$PID_A" "$PORT_A"
  rm -f "$XPID_A" 2>/dev/null || true
  PID_A=""
}
stop_B() {
  [ -n "$PID_B" ] || return 0
  stop_by_pid B "$PID_B" "$PORT_B"
  rm -f "$XPID_B" 2>/dev/null || true
  PID_B=""
}

on_exit() {
  rc=$?
  # B гасится ВСЕГДА
  stop_B
  if [ "$KEEP" = "1" ] && [ -n "$PID_A" ]; then
    :
  else
    stop_A
  fi
  exit $rc
}
trap on_exit EXIT
trap 'KEEP=0; log "Прервано пользователем (SIGINT) — гашу оба инстанса"; exit 130' INT
trap 'KEEP=0; log "Получен SIGTERM — гашу оба инстанса"; exit 143' TERM

# ---- запрос к trace: возвращает "rc|http_code|time_total|warp" ------------
probe_trace() {
  _proxy="$1"; _mt="$2"
  _out="$(curl -s --proxy "$_proxy" --max-time "$_mt" \
          -w '\n__HTTP=%{http_code}\n__T=%{time_total}\n' "$TRACE_URL" 2>/dev/null)"
  _rc=$?
  _http="$(printf '%s\n' "$_out" | sed -n 's/^__HTTP=//p' | head -1)"
  _tt="$(printf '%s\n' "$_out" | sed -n 's/^__T=//p' | head -1)"
  _warp="$(printf '%s\n' "$_out" | sed -n 's/^warp=//p' | head -1 | tr -d '\r')"
  printf '%s|%s|%s|%s\n' "$_rc" "${_http:-000}" "${_tt:-—}" "${_warp:-}"
}

# ---- шапка ----------------------------------------------------------------
bare "###################################################################"
bare "#  A/B ТЕСТ WARP через Xray"
bare "#    A = wireguard + noise-обфускация (dialerProxy -> noise-out)"
bare "#    B = КОНТРОЛЬ: тот же WARP, но чистый WireGuard без noises"
bare "#  Дата запуска : $(date '+%Y-%m-%d %H:%M:%S %z')"
bare "#  Хост         : $(hostname) / $(uname -sr)"
bare "#  Xray         : $(xray version 2>/dev/null | head -1)"
bare "#  curl         : $(curl -V 2>/dev/null | head -1)"
bare "#  Конфиг A     : $CONFIG_A"
bare "#  Конфиг B     : $CONFIG_B (генерируется из A автоматически)"
bare "#  trace URL    : $TRACE_URL  (БЕЗ завершающего слеша — иначе 404)"
bare "#  Режим        : $([ "$KEEP" = 1 ] && echo '--keep (инстанс A останется работать, B гасится)' || echo 'обычный (оба инстанса гасятся)')"
bare "###################################################################"

# ---- 1. эталон окружения --------------------------------------------------
sect "1. СОСТОЯНИЕ СЕТИ ДО ЗАПУСКА"

log "Интерфейсы (кроме DOWN):"
ip -brief addr 2>&1 | grep -v -w 'DOWN' | pipe_out

log "Таблица маршрутов (main):"
ip route 2>&1 | pipe_out

DEFGW="$(ip route show default 2>/dev/null | head -1)"
log "Дефолтный шлюз: ${DEFGW:-НЕ НАЙДЕН}"

log "ip rule (для контроля, что policy-routing VPN не активен):"
ip rule 2>&1 | pipe_out

VPN_SUSPECT=0
VPN_WHY=""
if ip link show throne-tun >/dev/null 2>&1; then
  TUN_STATE="$(ip -brief addr show throne-tun 2>/dev/null | awk '{print $2}')"
  log "Интерфейс throne-tun СУЩЕСТВУЕТ, состояние: ${TUN_STATE:-?}"
  ip -brief addr show throne-tun 2>&1 | pipe_out
  if [ "$TUN_STATE" = "DOWN" ]; then
    log "throne-tun есть, но DOWN"
  else
    VPN_SUSPECT=1
    VPN_WHY="интерфейс throne-tun поднят (состояние $TUN_STATE)"
  fi
else
  log "OK: интерфейса throne-tun НЕТ (VPN пользователя выключен)"
fi
if ip rule 2>/dev/null | grep -qE 'throne-tun|lookup 2022'; then
  log "Обнаружены ip rule от VPN-клиента (throne-tun / table 2022)"
  if [ "$VPN_SUSPECT" = "0" ]; then
    VPN_SUSPECT=1
    VPN_WHY="активны ip rule VPN-клиента (table 2022 / throne-tun)"
  else
    VPN_WHY="$VPN_WHY; активны ip rule VPN-клиента (table 2022)"
  fi
fi

if [ "$VPN_SUSPECT" = "1" ]; then
  bare ""
  bare "*******************************************************************"
  bare "*  ВНИМАНИЕ: VPN пользователя, похоже, НЕ ВЫКЛЮЧЕН"
  bare "*  Причина: $VPN_WHY"
  bare "*  A/B ТЕСТ БЕССМЫСЛЕН: трафик может идти внутри рабочего VPN,"
  bare "*  тогда и вариант B (без обфускации) заработает, и вывод про"
  bare "*  необходимость обфускации будет ЛОЖНЫМ. Выключи VPN и повтори."
  bare "*******************************************************************"
  bare ""
else
  log "Признаков активного VPN пользователя не найдено — тест валиден."
fi

# ---- 2. порты и конфиги ---------------------------------------------------
sect "2. ПОРТЫ И КОНФИГИ"
for p in "$PORT_A" "$HTTP_A" "$PORT_B" "$HTTP_B"; do
  if ss -ltnup 2>/dev/null | grep -q ":${p}[[:space:]]"; then
    log "FAIL: порт ${p} уже занят:"
    ss -ltnup 2>/dev/null | grep ":${p}[[:space:]]" | pipe_out
    log "Освободи порт (возможно, xray уже запущен) и повтори. Выход."
    exit 1
  fi
  log "OK: порт ${p} свободен"
done

if [ ! -f "$CONFIG_A" ]; then
  log "FAIL: не найден $CONFIG_A в $(pwd). Выход."
  exit 1
fi

log "Генерирую конфиг B (контроль без обфускации) из A программно:"
mkdir -p "$SCRATCH" 2>/dev/null || true
GEN_LOG="$SCRATCH/.genb.$$.log"
if python3 - "$CONFIG_A" "$CONFIG_B" "$PORT_B" "$HTTP_B" >"$GEN_LOG" 2>&1 <<'PYGEN'
import json, sys

src, dst, socks_port, http_port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(src, "r", encoding="utf-8") as f:
    cfg = json.load(f)

# 1) развести порты, чтобы A и B не конфликтовали
for ib in cfg.get("inbounds", []):
    if ib.get("protocol") == "socks":
        ib["port"] = socks_port
    elif ib.get("protocol") == "http":
        ib["port"] = http_port

# 2) снять обфускацию: убрать dialerProxy у wireguard-аутбаунда
outs = cfg.get("outbounds", [])
noise_tags = set()
for ob in outs:
    if ob.get("protocol") == "wireguard":
        ss = ob.get("streamSettings") or {}
        sock = ss.get("sockopt") or {}
        dp = sock.pop("dialerProxy", None)
        if dp:
            noise_tags.add(dp)
        if not sock:
            ss.pop("sockopt", None)
        if not ss:
            ob.pop("streamSettings", None)
        else:
            ob["streamSettings"] = ss

# 3) выкинуть ставшие ненужными noise-аутбаунды (freedom с noises)
def is_noise(ob):
    if ob.get("tag") in noise_tags:
        return True
    return ob.get("protocol") == "freedom" and (ob.get("settings") or {}).get("noises")

cfg["outbounds"] = [ob for ob in outs if not is_noise(ob)]

with open(dst, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")

wg = [o for o in cfg["outbounds"] if o.get("protocol") == "wireguard"]
print("конфиг B записан: %s" % dst)
print("аутбаунды B: %s" % ", ".join("%s/%s" % (o.get("tag"), o.get("protocol")) for o in cfg["outbounds"]))
print("streamSettings у wireguard: %s" % ("ЕСТЬ (плохо)" if any("streamSettings" in o for o in wg) else "НЕТ (ок)"))
PYGEN
then
  pipe_out < "$GEN_LOG"
  rm -f "$GEN_LOG" 2>/dev/null || true
else
  log "FAIL: не удалось сгенерировать конфиг B (python3 вернул ошибку):"
  pipe_out < "$GEN_LOG"
  rm -f "$GEN_LOG" 2>/dev/null || true
  exit 1
fi
if [ ! -s "$CONFIG_B" ]; then
  log "FAIL: конфиг B не создан или пуст: $CONFIG_B. Выход."
  exit 1
fi

if grep -qiE 'dialerProxy|noises' "$CONFIG_B" 2>/dev/null; then
  log "FAIL: в конфиге B остались dialerProxy/noises — контроль невалиден. Выход."
  grep -niE 'dialerProxy|noises' "$CONFIG_B" | pipe_out
  exit 1
fi
log "OK: в конфиге B нет ни dialerProxy, ни noises (чистый WireGuard)"

log "Проверка конфига A (xray run -test):"
if xray run -test -c "$CONFIG_A" >"$SCRATCH/.xraytestA.$$" 2>&1; then
  log "OK: конфиг A валиден"
else
  log "Внимание: xray run -test для A вернул ошибку:"
  head -10 "$SCRATCH/.xraytestA.$$" 2>/dev/null | pipe_out
fi
log "Проверка конфига B (xray run -test):"
if xray run -test -c "$CONFIG_B" >"$SCRATCH/.xraytestB.$$" 2>&1; then
  log "OK: конфиг B валиден"
else
  log "Внимание: xray run -test для B вернул ошибку:"
  head -10 "$SCRATCH/.xraytestB.$$" 2>/dev/null | pipe_out
fi
rm -f "$SCRATCH/.xraytestA.$$" "$SCRATCH/.xraytestB.$$" 2>/dev/null || true

###########################################################################
# ВАРИАНТ A — С ОБФУСКАЦИЕЙ
###########################################################################
sect "3. ЗАПУСК ВАРИАНТА A (с обфускацией, socks ${PORT_A})"
: > "$XLOG_A"
log "Команда: xray run -c $CONFIG_A  (лог -> $XLOG_A)"
nohup xray run -c "$CONFIG_A" >>"$XLOG_A" 2>&1 &
PID_A=$!
echo "$PID_A" > "$XPID_A"
log "PID(A) = $PID_A (записан в $XPID_A). Ждём 5 с на старт..."
sleep 5

if ! kill -0 "$PID_A" 2>/dev/null; then
  log "FAIL: процесс xray-A умер сразу после старта. Последние 20 строк лога:"
  tail -20 "$XLOG_A" 2>&1 | pipe_out
  PID_A=""
  exit 1
fi
log "OK: процесс xray-A жив"
if ss -ltn 2>/dev/null | grep -q ":${PORT_A}[[:space:]]"; then
  log "OK: socks-порт ${PORT_A} слушается"
else
  log "FAIL: порт ${PORT_A} не слушается. Последние 20 строк лога:"
  tail -20 "$XLOG_A" 2>&1 | pipe_out
  exit 1
fi

sect "4. ТЕСТ A: ПРОВЕРКИ ЧЕРЕЗ SOCKS ${PROXY_A}"

log "--- 4.1 ГЛАВНЫЙ ТЕСТ: cloudflare cdn-cgi/trace ---"
TRACE_OUT="$(curl -s --proxy "$PROXY_A" --max-time 25 \
             -w '\n__HTTP=%{http_code}\n' "$TRACE_URL" 2>&1)"
TRACE_RC=$?
if [ -n "$TRACE_OUT" ]; then
  printf '%s\n' "$TRACE_OUT" | pipe_out
fi
A_HTTP="$(printf '%s\n' "$TRACE_OUT" | sed -n 's/^__HTTP=//p' | head -1)"
WARP_VAL="$(printf '%s\n' "$TRACE_OUT" | sed -n 's/^warp=//p' | head -1 | tr -d '\r')"
log "curl rc=$TRACE_RC, http_code=${A_HTTP:-нет}"
if [ "$TRACE_RC" -ne 0 ]; then
  log "FAIL: curl вернул код $TRACE_RC (нет ответа от cloudflare через прокси) — проблема ТУННЕЛЯ"
  A_WARP="FAIL (curl rc=$TRACE_RC, туннель не отвечает)"
elif [ "${A_HTTP:-000}" != "200" ]; then
  log "FAIL (HTTP ${A_HTTP:-нет}, ответ не является trace) — это проблема ТЕСТА/URL, не туннеля"
  A_WARP="FAIL (HTTP ${A_HTTP:-нет}, ответ не является trace)"
elif [ "$WARP_VAL" = "on" ] || [ "$WARP_VAL" = "plus" ]; then
  log "OK: HTTP 200, warp=$WARP_VAL — трафик идёт ЧЕРЕЗ WARP"
  A_WARP="OK (warp=$WARP_VAL)"
else
  log "FAIL: HTTP 200, но warp='${WARP_VAL:-нет поля}' — трафик НЕ через WARP"
  A_WARP="FAIL (HTTP 200, warp=${WARP_VAL:-нет})"
fi

log "--- 4.2 Внешний IPv4 ---"
IP4="$(curl -s -4 --proxy "$PROXY_A" --max-time 20 https://api.ipify.org 2>/dev/null)"
if [ -z "$IP4" ]; then
  IP4="$(curl -s -4 --proxy "$PROXY_A" --max-time 20 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\r\n')"
fi
if [ -n "$IP4" ]; then
  log "OK: внешний IPv4 = $IP4"
  A_IP4="OK ($IP4)"
else
  log "FAIL: внешний IPv4 не получен"
  A_IP4="FAIL"
fi

log "--- 4.3 Внешний IPv6 (не критично) ---"
IP6="$(curl -s --proxy "$PROXY_A" --max-time 20 https://ipv6.icanhazip.com 2>/dev/null | tr -d '\r\n')"
if [ -n "$IP6" ]; then
  log "OK: внешний IPv6 = $IP6"
  A_IP6="OK ($IP6)"
else
  log "WARN: IPv6 через прокси не отвечает (не критично для обхода ТСПУ)"
  A_IP6="WARN (нет IPv6)"
fi

log "--- 4.4 UDP через SOCKS (DNS-запрос к 1.1.1.1:53 через UDP ASSOCIATE) ---"
UDPTEST="$(mktemp "${TMPDIR:-/tmp}/socks5udp.XXXXXX.py")"
cat > "$UDPTEST" <<'PYUDP'
import socket, struct, sys, random

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10808
QNAME = "cloudflare.com"
DNS_SRV = "1.1.1.1"

def dns_query(name, qid):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        b = part.encode()
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", 1, 1)   # A, IN
    return q

try:
    tcp = socket.create_connection((HOST, PORT), timeout=10)
    tcp.settimeout(10)
    tcp.sendall(b"\x05\x01\x00")
    g = tcp.recv(2)
    if g != b"\x05\x00":
        print("FAIL: socks5 greeting =", g.hex()); sys.exit(2)
    # UDP ASSOCIATE, клиентский адрес 0.0.0.0:0
    tcp.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + struct.pack("!H", 0))
    head = b""
    while len(head) < 4:
        c = tcp.recv(4 - len(head))
        if not c:
            print("FAIL: соединение закрыто на UDP ASSOCIATE"); sys.exit(3)
        head += c
    if head[1] != 0:
        print("FAIL: UDP ASSOCIATE отклонён, REP=%d" % head[1]); sys.exit(3)
    atyp = head[3]
    if atyp == 1:
        rest = b""
        while len(rest) < 6:
            rest += tcp.recv(6 - len(rest))
        baddr = socket.inet_ntoa(rest[0:4]); bport = struct.unpack("!H", rest[4:6])[0]
    elif atyp == 3:
        ln = tcp.recv(1)[0]
        rest = b""
        while len(rest) < ln + 2:
            rest += tcp.recv(ln + 2 - len(rest))
        baddr = rest[:ln].decode(); bport = struct.unpack("!H", rest[ln:ln+2])[0]
    elif atyp == 4:
        rest = b""
        while len(rest) < 18:
            rest += tcp.recv(18 - len(rest))
        baddr = socket.inet_ntop(socket.AF_INET6, rest[0:16]); bport = struct.unpack("!H", rest[16:18])[0]
    else:
        print("FAIL: неизвестный ATYP", atyp); sys.exit(3)
    if baddr in ("0.0.0.0", "::", ""):
        baddr = HOST
    print("UDP relay: %s:%d" % (baddr, bport))

    qid = random.randint(0, 65535)
    payload = (b"\x00\x00\x00\x01" + socket.inet_aton(DNS_SRV)
               + struct.pack("!H", 53) + dns_query(QNAME, qid))
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(15)
    u.sendto(payload, (baddr, bport))
    data, _ = u.recvfrom(4096)
    if len(data) < 10 or data[0:2] != b"\x00\x00":
        print("FAIL: некорректный SOCKS UDP-ответ:", data[:16].hex()); sys.exit(4)
    a = data[3]
    off = 4 + (4 if a == 1 else 16 if a == 4 else data[4] + 1) + 2
    dns = data[off:]
    if len(dns) < 12:
        print("FAIL: пустой DNS-ответ"); sys.exit(4)
    rid, flags, qd, an = struct.unpack("!HHHH", dns[0:8])
    if rid != qid:
        print("FAIL: DNS id не совпал (%d != %d)" % (rid, qid)); sys.exit(4)
    if an == 0:
        print("FAIL: DNS ответ без записей (rcode=%d)" % (flags & 0xF)); sys.exit(4)
    print("OK: UDP ходит через SOCKS, DNS %s -> %d A-записей (rcode=%d)"
          % (QNAME, an, flags & 0xF))
    sys.exit(0)
except Exception as e:
    print("FAIL: %s: %s" % (type(e).__name__, e))
    sys.exit(5)
PYUDP
UDP_OUT="$(python3 "$UDPTEST" "$PORT_A" 2>&1)"
UDP_RC=$?
printf '%s\n' "$UDP_OUT" | pipe_out
rm -f "$UDPTEST"
if [ "$UDP_RC" = "0" ]; then
  log "OK: UDP через прокси работает (значит WireGuard-UDP наружу проходит)"
  A_UDP="OK"
else
  log "FAIL: UDP через прокси не подтверждён (код $UDP_RC)"
  A_UDP="FAIL"
fi

log "--- 4.5 Задержка: 5 запросов к cdn-cgi/trace ---"
LAT_SUM=0; LAT_N=0
for i in 1 2 3 4 5; do
  R="$(probe_trace "$PROXY_A" 20)"
  RC="${R%%|*}"; REST="${R#*|}"
  HTTP="${REST%%|*}"; REST="${REST#*|}"
  T="${REST%%|*}"
  if [ "$RC" = "0" ] && [ "$HTTP" = "200" ]; then
    log "  попытка $i: OK  http=$HTTP  time_total=${T}s"
    LAT_SUM="$(awk -v a="$LAT_SUM" -v b="$T" 'BEGIN{printf "%.4f", a+b}')"
    LAT_N=$((LAT_N+1))
  elif [ "$RC" = "0" ]; then
    log "  попытка $i: BAD (HTTP $HTTP — проблема теста/URL, не туннеля)"
  else
    log "  попытка $i: FAIL (curl rc=$RC)"
  fi
done
if [ "$LAT_N" -gt 0 ]; then
  A_LAT="$(awk -v s="$LAT_SUM" -v n="$LAT_N" 'BEGIN{printf "%.3f s (среднее по %d)", s/n, n}')"
  log "Средняя задержка: $A_LAT"
else
  A_LAT="все 5 запросов неудачны"
  log "Задержку измерить не удалось"
fi

log "--- 4.6 Скорость: скачивание 10 МБ ---"
SP="$(curl -s -o /dev/null --proxy "$PROXY_A" --max-time 120 \
      -w '%{time_total} %{speed_download} %{size_download}' \
      'https://speed.cloudflare.com/__down?bytes=10000000' 2>/dev/null)"
RC=$?
if [ "$RC" = "0" ] && [ -n "$SP" ]; then
  A_SPEED="$(printf '%s\n' "$SP" | awk '{printf "%.2f MB/s (%.1f Мбит/с), %.1f МБ за %.2f s", $2/1048576, $2*8/1000000, $3/1048576, $1}')"
  log "OK: $A_SPEED"
else
  A_SPEED="FAIL (curl rc=$RC)"
  log "FAIL: скорость измерить не удалось (curl rc=$RC)"
fi

# ---- 5. стабильность A ----------------------------------------------------
sect "5. ТЕСТ A: СТАБИЛЬНОСТЬ 2 мин 40 с, запрос каждые ${STAB_INTERVAL} с (${STAB_ATTEMPTS} попыток)"
bare "    Цель — поймать разрыв на рехендшейке WireGuard (~каждые 2 минуты)."
bare "    noise-пакеты Xray отправляет только один раз при создании сокета,"
bare "    поэтому ТСПУ может переклассифицировать флоу и срезать его позже."
bare "    Статусы: OK = warp=on;  FAIL = туннель не ответил / не через WARP;"
bare "             BAD = HTTP != 200 (проблема самого теста, не туннеля)."
bare ""
bare "    №   время      статус  http  warp=   time_total  прошло"
bare "    ------------------------------------------------------------"
STAB_START=$(date +%s)
i=1
while [ "$i" -le "$STAB_ATTEMPTS" ]; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - STAB_START))
  R="$(probe_trace "$PROXY_A" 15)"
  RC="${R%%|*}"; REST="${R#*|}"
  HTTP="${REST%%|*}"; REST="${REST#*|}"
  TT="${REST%%|*}"; W="${REST#*|}"
  if [ "$RC" != "0" ]; then
    A_STAB_FAIL=$((A_STAB_FAIL+1)); ST="FAIL"
    [ -z "$A_STAB_FIRST_FAIL" ] && A_STAB_FIRST_FAIL="попытка $i, ${ELAPSED}s (~$((ELAPSED/60)) мин $((ELAPSED%60)) с), curl rc=$RC"
  elif [ "$HTTP" != "200" ]; then
    A_STAB_BAD=$((A_STAB_BAD+1)); ST="BAD "
  elif [ "$W" = "on" ] || [ "$W" = "plus" ]; then
    A_STAB_OK=$((A_STAB_OK+1)); ST="OK  "
  else
    A_STAB_FAIL=$((A_STAB_FAIL+1)); ST="FAIL"
    [ -z "$A_STAB_FIRST_FAIL" ] && A_STAB_FIRST_FAIL="попытка $i, ${ELAPSED}s (~$((ELAPSED/60)) мин $((ELAPSED%60)) с), HTTP 200 но warp=${W:-нет}"
  fi
  printf '    %-3s %s  %s    %-5s %-6s  %-10s  %ss\n' \
    "$i" "$(ts)" "$ST" "$HTTP" "${W:-—}" "${TT:-—}" "$ELAPSED" | tee -a "$REPORT"
  i=$((i+1))
  [ "$i" -le "$STAB_ATTEMPTS" ] && sleep "$STAB_INTERVAL"
done
A_STAB_TOTAL=$(( $(date +%s) - STAB_START ))
bare "    ------------------------------------------------------------"
log "Итог стабильности A: OK=$A_STAB_OK, FAIL=$A_STAB_FAIL, BAD=$A_STAB_BAD из $STAB_ATTEMPTS (длительность ${A_STAB_TOTAL}s)"
if [ "$A_STAB_FAIL" = "0" ]; then
  log "РАЗРЫВОВ НЕ БЫЛО — туннель A прожил ${A_STAB_TOTAL}s без потерь"
else
  log "БЫЛИ РАЗРЫВЫ. Первый сбой: $A_STAB_FIRST_FAIL"
fi
if [ "$A_STAB_BAD" != "0" ]; then
  log "Внимание: $A_STAB_BAD попыток дали HTTP != 200 — это дефект теста/URL, а не туннеля"
fi

# ---- 6. гашение A перед запуском B ---------------------------------------
sect "6. ОСТАНОВКА ВАРИАНТА A ПЕРЕД КОНТРОЛЬНЫМ ТЕСТОМ B"
if [ "$KEEP" = "1" ]; then
  log "Режим --keep: A будет перезапущен в самом конце, сейчас гашу его, чтобы B не мешал"
fi
stop_A

###########################################################################
# ВАРИАНТ B — КОНТРОЛЬ, БЕЗ ОБФУСКАЦИИ
###########################################################################
sect "7. ТЕСТ B (КОНТРОЛЬ): чистый WireGuard без noises, socks ${PORT_B}"
bare "    Ожидание: если ТСПУ режет WireGuard по протокольной сигнатуре,"
bare "    хендшейк уйдёт ('Sending handshake initiation'), но ответа"
bare "    ('Received handshake response') НЕ будет -> trace не ответит."
bare ""
: > "$XLOG_B"
log "Команда: xray run -c $CONFIG_B  (лог -> $XLOG_B)"
nohup xray run -c "$CONFIG_B" >>"$XLOG_B" 2>&1 &
PID_B=$!
echo "$PID_B" > "$XPID_B"
log "PID(B) = $PID_B (записан в $XPID_B). Ждём 5 с на старт..."
sleep 5

B_STARTED=0
if ! kill -0 "$PID_B" 2>/dev/null; then
  log "FAIL: процесс xray-B умер сразу после старта. Последние 20 строк лога:"
  tail -20 "$XLOG_B" 2>&1 | pipe_out
  PID_B=""
  B_RESULT="НЕ ЗАПУСТИЛСЯ"
  B_DETAIL="процесс xray-B умер после старта — контроль не состоялся"
elif ! ss -ltn 2>/dev/null | grep -q ":${PORT_B}[[:space:]]"; then
  log "FAIL: порт ${PORT_B} не слушается. Последние 20 строк лога:"
  tail -20 "$XLOG_B" 2>&1 | pipe_out
  B_RESULT="НЕ ЗАПУСТИЛСЯ"
  B_DETAIL="socks-порт ${PORT_B} не слушается — контроль не состоялся"
else
  log "OK: процесс xray-B жив, socks-порт ${PORT_B} слушается"
  B_STARTED=1
fi

if [ "$B_STARTED" = "1" ]; then
  bare ""
  bare "    До 60 с: ${B_ATTEMPTS} попытки по --max-time ${B_MAXTIME} через ${PROXY_B}"
  bare "    №   время      статус  http  warp=   time_total"
  bare "    ------------------------------------------------------"
  B_OK=0
  B_WARP_VAL=""
  B_LAST_RC=""
  B_LAST_HTTP=""
  j=1
  while [ "$j" -le "$B_ATTEMPTS" ]; do
    R="$(probe_trace "$PROXY_B" "$B_MAXTIME")"
    RC="${R%%|*}"; REST="${R#*|}"
    HTTP="${REST%%|*}"; REST="${REST#*|}"
    TT="${REST%%|*}"; W="${REST#*|}"
    B_LAST_RC="$RC"; B_LAST_HTTP="$HTTP"
    if [ "$RC" != "0" ]; then
      ST="FAIL"
    elif [ "$HTTP" != "200" ]; then
      ST="BAD "
    elif [ "$W" = "on" ] || [ "$W" = "plus" ]; then
      ST="OK  "; B_OK=1; B_WARP_VAL="$W"
    else
      ST="FAIL"
    fi
    printf '    %-3s %s  %s    %-5s %-6s  %-10s\n' \
      "$j" "$(ts)" "$ST" "$HTTP" "${W:-—}" "${TT:-—}" | tee -a "$REPORT"
    [ "$B_OK" = "1" ] && break
    j=$((j+1))
  done
  bare "    ------------------------------------------------------"

  log "Хендшейки в $XLOG_B:"
  B_HS_SENT="$(grep -ci 'Sending handshake initiation' "$XLOG_B" 2>/dev/null || true)"
  B_HS_RECV="$(grep -ci 'Received handshake response' "$XLOG_B" 2>/dev/null || true)"
  B_HS_INCOMPLETE="$(grep -ci 'handshake did not complete' "$XLOG_B" 2>/dev/null || true)"
  B_HS_SENT="${B_HS_SENT:-0}"; B_HS_RECV="${B_HS_RECV:-0}"; B_HS_INCOMPLETE="${B_HS_INCOMPLETE:-0}"
  bare "    Sending handshake initiation  : $B_HS_SENT"
  bare "    Received handshake response   : $B_HS_RECV"
  bare "    handshake did not complete    : $B_HS_INCOMPLETE"
  bare "    строки про хендшейк (до 20):"
  grep -Ei 'handshake|keepalive' "$XLOG_B" 2>/dev/null | head -20 | pipe_out

  if [ "$B_OK" = "1" ]; then
    B_RESULT="УСПЕХ (warp=$B_WARP_VAL)"
    B_DETAIL="чистый WireGuard БЕЗ обфускации тоже прошёл; хендшейков отправлено $B_HS_SENT, получено ответов $B_HS_RECV"
    log "B УСПЕШЕН: чистый WireGuard прошёл без обфускации"
  else
    if [ "$B_HS_SENT" -gt 0 ] && [ "$B_HS_RECV" = "0" ]; then
      B_RESULT="ПРОВАЛ (хендшейк без ответа)"
      B_DETAIL="отправлено $B_HS_SENT handshake initiation, получено 0 handshake response, 'handshake did not complete' = $B_HS_INCOMPLETE — классическая картина блокировки WireGuard на ТСПУ"
    elif [ "$B_HS_SENT" = "0" ]; then
      B_RESULT="ПРОВАЛ (хендшейк даже не ушёл)"
      B_DETAIL="в логе нет 'Sending handshake initiation' — проверь лог $XLOG_B, возможно проблема не в ТСПУ (last curl rc=$B_LAST_RC, http=$B_LAST_HTTP)"
    else
      B_RESULT="ПРОВАЛ (хендшейк прошёл, данные нет)"
      B_DETAIL="отправлено $B_HS_SENT, получено ответов $B_HS_RECV, но trace не ответил (last curl rc=$B_LAST_RC, http=$B_LAST_HTTP) — похоже на срез флоу после установления"
    fi
    log "B ПРОВАЛИЛСЯ: $B_RESULT"
  fi
fi

sect "8. ОСТАНОВКА ВАРИАНТА B"
stop_B

# ---- 9. разбор логов ------------------------------------------------------
sect "9. РАЗБОР ЛОГОВ"
A_HS_SENT="$(grep -ci 'Sending handshake initiation' "$XLOG_A" 2>/dev/null || true)"
A_HS_RECV="$(grep -ci 'Received handshake response' "$XLOG_A" 2>/dev/null || true)"
A_HS_INCOMPLETE="$(grep -ci 'handshake did not complete' "$XLOG_A" 2>/dev/null || true)"
A_HS_SENT="${A_HS_SENT:-0}"; A_HS_RECV="${A_HS_RECV:-0}"; A_HS_INCOMPLETE="${A_HS_INCOMPLETE:-0}"

log "--- 9.1 Лог A ($XLOG_A, $(wc -l < "$XLOG_A" 2>/dev/null || echo 0) строк) ---"
bare "    Sending handshake initiation  : $A_HS_SENT"
bare "    Received handshake response   : $A_HS_RECV"
bare "    handshake did not complete    : $A_HS_INCOMPLETE"
bare "    grep -Ei 'handshake|keepalive|failed|timeout|error|rejected' (до 30 строк):"
grep -Ei 'handshake|keepalive|failed|timeout|error|rejected' "$XLOG_A" 2>/dev/null | head -30 | pipe_out
if ! grep -Eiq 'handshake|keepalive|failed|timeout|error|rejected' "$XLOG_A" 2>/dev/null; then
  bare "    (совпадений нет — смотри полный лог $XLOG_A)"
fi

log "--- 9.2 Лог B ($XLOG_B, $(wc -l < "$XLOG_B" 2>/dev/null || echo 0) строк) ---"
bare "    Sending handshake initiation  : $B_HS_SENT"
bare "    Received handshake response   : $B_HS_RECV"
bare "    handshake did not complete    : $B_HS_INCOMPLETE"
bare "    grep -Ei 'handshake|keepalive|failed|timeout|error|rejected' (до 30 строк):"
grep -Ei 'handshake|keepalive|failed|timeout|error|rejected' "$XLOG_B" 2>/dev/null | head -30 | pipe_out
if ! grep -Eiq 'handshake|keepalive|failed|timeout|error|rejected' "$XLOG_B" 2>/dev/null; then
  bare "    (совпадений нет — смотри полный лог $XLOG_B)"
fi

# ---- 10. финальное состояние / --keep ------------------------------------
sect "10. ЗАВЕРШЕНИЕ"
if [ "$KEEP" = "1" ]; then
  log "Режим --keep: поднимаю инстанс A заново (вариант B гасится всегда)"
  nohup xray run -c "$CONFIG_A" >>"$XLOG_A" 2>&1 &
  PID_A=$!
  echo "$PID_A" > "$XPID_A"
  sleep 3
  if kill -0 "$PID_A" 2>/dev/null && ss -ltn 2>/dev/null | grep -q ":${PORT_A}[[:space:]]"; then
    log "OK: xray-A снова работает, PID $PID_A"
    bare "    Прокси доступен: socks5 127.0.0.1:${PORT_A} / http 127.0.0.1:${HTTP_A}"
    bare "    Выключить вручную:  kill $PID_A      (или: kill \$(cat '$PWD/xray-A.pid'))"
    bare "    Проверить, что умер: ss -ltn | grep ${PORT_A}"
  else
    log "FAIL: не удалось поднять A заново, смотри $XLOG_A"
    PID_A=""
  fi
else
  log "Проверка, что ничего не осталось:"
  for p in "$PORT_A" "$HTTP_A" "$PORT_B" "$HTTP_B"; do
    if ss -ltnup 2>/dev/null | grep -q ":${p}[[:space:]]"; then
      log "FAIL: порт ${p} всё ещё занят:"
      ss -ltnup 2>/dev/null | grep ":${p}[[:space:]]" | pipe_out
    else
      log "OK: порт ${p} свободен"
    fi
  done
  # ищем только НАШИ инстансы (по именам конфигов), чужой xray/VPN не трогаем
  LEFT="$(ps -eo pid=,args= 2>/dev/null | grep -F 'xray run' | grep -E 'warp-xray\.json|warp-noobf\.json' || true)"
  if [ -n "$LEFT" ]; then
    log "FAIL: остались наши процессы xray:"
    printf '%s\n' "$LEFT" | pipe_out
  else
    log "OK: процессов 'xray run' в системе не осталось"
  fi
  rm -f "$XPID_A" "$XPID_B" 2>/dev/null || true
fi

# ---- 11. ИТОГ ------------------------------------------------------------
sect "ИТОГ"
if [ "$VPN_SUSPECT" = "1" ]; then
  bare "0) НЕДОСТОВЕРНО: VPN пользователя был активен ($VPN_WHY)."
  bare "   Любой вывод про обфускацию ниже считать НЕВАЛИДНЫМ."
fi

if [ "${A_WARP#OK}" != "$A_WARP" ]; then
  bare "1) ВАРИАНТ A (с обфускацией): РАБОТАЕТ — $A_WARP, внешний IPv4 $A_IP4."
  A_GOOD=1
else
  bare "1) ВАРИАНТ A (с обфускацией): НЕ РАБОТАЕТ — $A_WARP (IPv4: $A_IP4)."
  A_GOOD=0
fi

if [ "$A_STAB_FAIL" = "0" ] && [ "$A_STAB_OK" -gt 0 ]; then
  bare "2) A СТАБИЛЕН: ${A_STAB_TOTAL}s, ${A_STAB_OK}/${STAB_ATTEMPTS} успешных, разрывов нет"
  bare "   -> рехендшейк (хендшейков в логе A: отправлено $A_HS_SENT, ответов $A_HS_RECV) пережит."
else
  bare "2) A С РАЗРЫВАМИ: OK=${A_STAB_OK}, FAIL=${A_STAB_FAIL}, BAD=${A_STAB_BAD} из ${STAB_ATTEMPTS}."
  [ -n "$A_STAB_FIRST_FAIL" ] && bare "   Первый сбой: ${A_STAB_FIRST_FAIL}."
  bare "   Хендшейки A: отправлено $A_HS_SENT, ответов $A_HS_RECV, не завершено $A_HS_INCOMPLETE."
fi

bare "3) ВАРИАНТ B (контроль, чистый WireGuard без обфускации): $B_RESULT"
[ -n "$B_DETAIL" ] && bare "   $B_DETAIL"

bare "4) ВЫВОД ПРО ОБФУСКАЦИЮ:"
case "$B_RESULT" in
  ПРОВАЛ*)
    if [ "$A_GOOD" = "1" ]; then
      bare "   A работает, B (без обфускации) провалился ->"
      bare "   ТСПУ РЕЖЕТ ЧИСТЫЙ WIREGUARD. ОБФУСКАЦИЯ НЕОБХОДИМА, И ОНА РАБОТАЕТ."
      bare "   Ключевой признак: в логе B хендшейк уходил ($B_HS_SENT раз), ответа не было ($B_HS_RECV)."
    else
      bare "   Провалились ОБА варианта -> проблема, скорее всего, не в обфускации,"
      bare "   а в сети/endpoint/кредах. Вывод про необходимость обфускации СДЕЛАТЬ НЕЛЬЗЯ."
    fi
    ;;
  УСПЕХ*)
    if [ "$A_GOOD" = "1" ]; then
      bare "   Работают ОБА варианта -> ТСПУ в данный момент чистый WireGuard НЕ РЕЖЕТ."
      bare "   ТЕКУЩИЙ ТЕСТ НЕ ДОКАЗЫВАЕТ НЕОБХОДИМОСТЬ ОБФУСКАЦИИ: возможно,"
      bare "   блокировка применяется не всегда, или не к этому endpoint / порту 946,"
      bare "   или срабатывает позже по времени. Обфускация при этом не мешает (A работает)."
    else
      bare "   B работает, A НЕТ -> обфускация в текущем виде ЛОМАЕТ соединение."
      bare "   Надо разбирать конфиг noises/dialerProxy, а не ТСПУ."
    fi
    ;;
  *)
    bare "   Контроль B не состоялся ($B_RESULT) -> A/B-вывод не получен, перезапусти тест."
    ;;
esac

bare "5) Задержка A: $A_LAT.  Скорость A: $A_SPEED."
bare "6) UDP через прокси (A): $A_UDP.  IPv6 (A): $A_IP6."
bare "7) Файлы: отчёт $PWD/test-report.txt ; лог A $PWD/xray-A.log ; лог B $PWD/xray-B.log"
bare "   Конфиг B (временный): $CONFIG_B"
bare ""
log "Готово."
exit 0
