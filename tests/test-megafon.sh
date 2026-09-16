#!/usr/bin/env bash
# test-megafon.sh — автономный МАТРИЧНЫЙ тест WARP-через-Xray на мобильной сети (Мегафон).
#
# Контекст: четыре реальных AWG-конфига в ./awg-samples/ —
#   megafon-ok-1180.conf      РАБОТАЕТ  8.34.146.7:1180  MTU 1420 Jc=4   I1 = QUIC Initial, DCID 8 б
#   megafon-ok-903.conf       РАБОТАЕТ  8.34.70.4:903    MTU 1420 Jc=4   I1 = QUIC Initial, DCID 8 б
#   megafon-ok-500-jc120.conf РАБОТАЕТ  162.159.192.1:500 MTU 1280 Jc=120 I1 = QUIC Initial, DCID 20 б
#   megafon-fail-946-sip.conf НЕ РАБОТАЕТ 8.6.112.7:946  MTU 1420 Jc=4   I1/I2 = текстовый SIP (RFC 3261)
# У рабочих РАЗНЫЕ порты, MTU, Jc и даже креды — единственный инвариант это QUIC-подобный I1.
# У единственного нерабочего I1 текстовый. Рабочая гипотеза: решает ПРОФИЛЬ пакета, не порт.
# Матрица должна это ПРОВЕРИТЬ, а не принять на веру.
#
# Запуск (VPN пользователя выключить, сеть переключить на Мегафон):
#     ./tests/test-megafon.sh
# Длительность: ~5-6 мин матрица (10 вариантов) + ~2 мин фаза стабильности.
# Всё пишется в stdout и в ./results/megafon-report.txt (перезаписывается при каждом запуске).
# Без sudo. Маршруты / nft / iptables / ip rule НЕ трогаются.
#
# Креды, hex-пакеты и endpoint'ы в тексте скрипта НЕ хардкодятся — читаются программно
# (python3) из ./warp-xray.json, ./legacy/old-warp-xray.json и ./awg-samples/*.conf.

set -u

cd "$(dirname "$(readlink -f "$0")")/.." || exit 1   # корень репозитория: скрипты лежат в tests/, данные и конфиги — выше

# --- пути, порты, параметры -------------------------------------------------
CFG_NEW="./warp-xray.json"      # креды p1Fqp + статичные SIP-пакеты + 4 x rand 40-70
CFG_OLD="./legacy/old-warp-xray.json"  # профиль 8 x rand 23-911
AWGDIR="./awg-samples"          # QUIC-пакеты I1, endpoint'ы, вторые креды (IFkdR)

SCRATCH="${SCRATCH_DIR:-${TMPDIR:-/tmp}}"
GEN="$SCRATCH/mgf-gen.py"
STATEDIR="$SCRATCH/mgf-state"

REPORT="./results/megafon-report.txt"
PIDFILE="$SCRATCH/mgf-xray.pid"

SOCKS_HOST="127.0.0.1"
PORT="10808"
PROXY="socks5h://${SOCKS_HOST}:${PORT}"

# ВАЖНО: без завершающего слеша — на .../trace/ Cloudflare отдаёт 404.
TRACE_URL="https://www.cloudflare.com/cdn-cgi/trace"

START_WAIT=4      # сек на старт инстанса
CURL_MAXTIME=12   # таймаут одного запроса
CURL_TRIES=2      # попыток на вариант (максимум по бюджету времени)
STAB_ATTEMPTS=5   # фаза 2: 5 запросов
STAB_INTERVAL=20  # фаза 2: каждые 20 с (= ~100 с)

VARIANTS="1 2 3 4 5 6 7 8 9 10"

# --- ЛОГИРОВАНИЕ ------------------------------------------------------------
# По умолчанию loglevel=info: репозиторий публичный, а debug-лог xray пишет домены
# и адреса пользовательского трафика (app/dispatcher, app/dns, app/proxyman/outbound,
# proxy/socks) — их потом приходится вычищать вручную.
# ЦЕНА: строки WireGuard 'Sending handshake initiation' / 'Received handshake response' /
# 'Handshake did not complete' xray пишет ТОЛЬКО на debug (device-логгер wireguard-go
# завёрнут в LogDebug). На info счётчики хендшейков в таблице будут нулевыми, и
# отличить «UDP до endpoint режется» от «рвётся уже установленная сессия» будет нельзя.
# Если эта диагностика нужна — запускай:  ./tests/test-megafon.sh --log-debug
# Тогда СЫРОЙ debug-лог останется только в "$SCRATCH" (вне репозитория), а в рабочую
# папку попадёт ./results/megafon-<N>.log, отфильтрованный по белому списку: старт ядра плюс
# события wireguard, без единой строки с доменами и коннектами пользователя.
LOGLEVEL="info"
FILTER_RE='^#|^Xray [0-9]|^A unified platform|\] core: |\] app/log: |\] infra/conf/serial: |\] transport/internet/(tcp|udp): listening|\] proxy/wireguard: |\] (peer\(|Routine:|UAPI:|Device|Interface|Binding|Bind|Starting|Stopping|Sending|Receiving|Received|Handshake|Invalid|Failed|Retrying|Obtained|Zeroing|Resetting|Adding|Removing|Creating)'

# --- аргументы -------------------------------------------------------------
for a in "$@"; do
  case "$a" in
    --log-info) LOGLEVEL="info" ;;
    --log-debug) LOGLEVEL="debug" ;;
    -h|--help) sed -n '2,22p' "$0"; echo "Флаги: --log-debug (включить счётчики хендшейков; публикуемый лог всё равно фильтруется)"; exit 0 ;;
    *) echo "Неизвестный аргумент: $a (поддерживаются --log-debug, --log-info, --help)" >&2; exit 2 ;;
  esac
done

: > "$REPORT"

ts()   { date '+%H:%M:%S'; }
log()  { printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$REPORT"; }
bare() { printf '%s\n' "$*" | tee -a "$REPORT"; }
pipe_out() { sed 's/^/    /' | tee -a "$REPORT"; }
sect() {
  bare ""
  bare "============================================================"
  bare "  $*"
  bare "============================================================"
}

# --- описания вариантов ----------------------------------------------------
desc_of() {
  case "$1" in
     1) echo "QUIC I1 из ok-1180 + 4xrand40-70  | 8.34.146.7:1180  | MTU 1420 | ключ p1Fqp" ;;
     2) echo "QUIC I1 из ok-903 + 4xrand40-70   | 8.34.70.4:903    | MTU 1420 | ключ p1Fqp" ;;
     3) echo "QUIC I1 из ok-1180 + 4xrand40-70  | 8.6.112.7:946    | MTU 1420 | ключ p1Fqp  [КЛЮЧЕВОЙ]" ;;
     4) echo "SIP I1+I2 (RFC3261) + 4xrand40-70 | 8.34.146.7:1180  | MTU 1420 | ключ p1Fqp" ;;
     5) echo "SIP I1+I2 (RFC3261) + 4xrand40-70 | 8.6.112.7:946    | MTU 1420 | ключ p1Fqp  [ожидается FAIL]" ;;
     6) echo "БЕЗ обфускации (чистый WG)        | 8.34.146.7:1180  | MTU 1420 | ключ p1Fqp" ;;
     7) echo "СВОЙ QUIC Initial + 4xrand40-70   | 8.34.146.7:1180  | MTU 1420 | ключ p1Fqp" ;;
     8) echo "СВОЙ QUIC Initial + 4xrand40-70   | 8.6.112.7:946    | MTU 1420 | ключ p1Fqp" ;;
     9) echo "QUIC I1 из ok-500 + 8xrand23-911  | 162.159.192.1:500 | MTU 1280 | ключ IFkdR" ;;
    10) echo "8xrand23-911 БЕЗ hex              | 162.159.192.1:500 | MTU 1280 | ключ IFkdR" ;;
     *) echo "неизвестный вариант" ;;
  esac
}

# --- результаты ------------------------------------------------------------
declare -A R_ST R_HTTP R_WARP R_TIME R_MS R_HS_S R_HS_R R_HS_I R_NOTE R_KEY
for v in $VARIANTS; do
  R_ST[$v]="SKIP"; R_HTTP[$v]="-"; R_WARP[$v]="-"; R_TIME[$v]="-"
  R_MS[$v]="999999"; R_HS_S[$v]="-"; R_HS_R[$v]="-"; R_HS_I[$v]="-"
  R_NOTE[$v]=""; R_KEY[$v]="?"
done

# --- гашение ---------------------------------------------------------------
CUR_PID=""
stop_current() {
  local pid="${CUR_PID:-}"
  [ -z "$pid" ] && return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    local i=0
    while [ $i -lt 20 ] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.25; i=$((i+1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      sleep 0.5
    fi
  fi
  CUR_PID=""
  rm -f "$PIDFILE"
}

port_busy() { ss -ltn 2>/dev/null | grep -q ":${PORT}[[:space:]]"; }

wait_port_free() {
  local i=0
  while [ $i -lt 20 ] && port_busy; do sleep 0.25; i=$((i+1)); done
  port_busy && return 1 || return 0
}

on_exit() {
  local rc=$?
  stop_current
  exit $rc
}
trap on_exit EXIT
trap 'echo; echo "Прервано пользователем — гашу инстанс."; exit 130' INT TERM

# ===========================================================================
# 0. Шапка и предполётные проверки
# ===========================================================================
sect "МАТРИЧНЫЙ ТЕСТ WARP/XRAY НА МОБИЛЬНОЙ СЕТИ (МЕГАФОН) — 10 ВАРИАНТОВ"
bare "Дата/время   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
bare "Хост         : $(uname -srm) | $(hostname 2>/dev/null || echo '?')"
bare "xray         : $(xray version 2>/dev/null | head -1 || echo 'НЕ НАЙДЕН')"
bare "curl         : $(curl --version 2>/dev/null | head -1 || echo 'НЕ НАЙДЕН')"
bare "python3      : $(python3 --version 2>/dev/null || echo 'НЕ НАЙДЕН')"
bare "Источники    : $CFG_NEW (креды p1Fqp + SIP-пакеты + rand 40-70)"
bare "               $CFG_OLD (профиль 8 x rand 23-911)"
bare "               $AWGDIR/*.conf (QUIC I1, endpoint'ы, вторые креды IFkdR)"
bare "Отчёт        : $REPORT"
bare "Логи         : ./results/megafon-<N>.log (отфильтрованы), сырые — в $SCRATCH"
bare "Порт прокси  : $PORT (варианты идут последовательно, по одному инстансу)"
if [ "$LOGLEVEL" = "debug" ]; then
  bare "loglevel     : debug (флаг --log-debug). Сырой лог только в $SCRATCH,"
  bare "               в рабочую папку идёт отфильтрованный по белому списку лог"
  bare "               (старт ядра + wireguard; без доменов и коннектов пользователя)."
else
  bare "loglevel     : info (по умолчанию — репозиторий публичный, debug пишет домены юзера)."
  bare "               ВНИМАНИЕ: счётчики хендшейков будут НУЛЕВЫЕ — эти строки xray пишет"
  bare "               только на debug. Отличить 'режется UDP до endpoint' от 'рвётся уже"
  bare "               установленная сессия' в этом режиме НЕЛЬЗЯ. Нужна эта диагностика —"
  bare "               перезапусти: ./tests/test-megafon.sh --log-debug"
fi

for f in "$CFG_NEW" "$CFG_OLD"; do
  [ -r "$f" ] || { log "ФАТАЛЬНО: нет файла $f. Выход."; exit 2; }
done
for f in megafon-ok-1180.conf megafon-ok-903.conf megafon-ok-500-jc120.conf megafon-fail-946-sip.conf; do
  [ -r "$AWGDIR/$f" ] || { log "ФАТАЛЬНО: нет файла $AWGDIR/$f — из него берутся I1/endpoint/креды. Выход."; exit 2; }
done
command -v xray    >/dev/null || { log "ФАТАЛЬНО: xray не найден в PATH."; exit 2; }
command -v python3 >/dev/null || { log "ФАТАЛЬНО: python3 не найден в PATH."; exit 2; }

# ---------------------------------------------------------------------------
sect "1. СОСТОЯНИЕ СЕТИ (какая сеть сейчас активна)"

bare "ip -brief addr (только поднятые интерфейсы):"
ip -brief addr 2>/dev/null | grep -v 'DOWN' | pipe_out
bare ""
bare "ip route:"
ip route 2>/dev/null | pipe_out
bare ""

DEF_LINE="$(ip route show default 2>/dev/null | head -1)"
DEF_IF="$(printf '%s\n' "$DEF_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
DEF_GW="$(printf '%s\n' "$DEF_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)"
DEF_IF="${DEF_IF:-?}"; DEF_GW="${DEF_GW:-?}"
bare "Дефолтный маршрут : ${DEF_LINE:-НЕТ ДЕФОЛТНОГО МАРШРУТА}"
bare "  интерфейс : $DEF_IF"
bare "  шлюз      : $DEF_GW"

NET_KIND="неизвестно"
NET_WHY=""
case "$DEF_GW" in
  192.168.42.*) NET_KIND="мобильная (USB-тетеринг Android)"; NET_WHY="шлюз 192.168.42.x — типовой Android USB tethering" ;;
  192.168.43.*) NET_KIND="мобильная (WiFi-хотспот Android)"; NET_WHY="шлюз 192.168.43.x — типовой Android WiFi hotspot" ;;
  192.168.44.*) NET_KIND="мобильная (тетеринг Android)";     NET_WHY="шлюз 192.168.44.x — тетеринг Android" ;;
  192.168.49.*) NET_KIND="мобильная (WiFi Direct Android)";  NET_WHY="шлюз 192.168.49.x" ;;
  172.20.10.*)  NET_KIND="мобильная (тетеринг iPhone)";      NET_WHY="шлюз 172.20.10.x — типовой iPhone tethering" ;;
esac
if [ "$NET_KIND" = "неизвестно" ]; then
  case "$DEF_IF" in
    wwan*|ppp*|usb*|rmnet*|wwp*)        NET_KIND="мобильная (модем/ppp/wwan)"; NET_WHY="имя интерфейса $DEF_IF" ;;
    *u[0-9]|*u[0-9][a-z][0-9]|*u[0-9]*) NET_KIND="мобильная (USB-тетеринг)";   NET_WHY="в имени $DEF_IF есть USB-путь (enp..u..)" ;;
    wlo*|wlan*|wlp*)                    NET_KIND="WiFi";                       NET_WHY="имя интерфейса $DEF_IF" ;;
    enp*|eth*|eno*|ens*)                NET_KIND="проводная";                  NET_WHY="имя интерфейса $DEF_IF" ;;
  esac
fi
bare ""
bare "ВЫВОД ПО СЕТИ: $NET_KIND ${NET_WHY:+($NET_WHY)}"
case "$NET_KIND" in
  мобильная*) bare "  -> ПОХОЖЕ НА МОБИЛЬНУЮ СЕТЬ — тест по адресу." ;;
  WiFi|проводная)
    bare "  -> ПОХОЖЕ НА ${NET_KIND} — ЭТО ТЕСТ НЕ ПРО МЕГАФОН, на главный вопрос он не отвечает."
    bare "     (WiFi-хотспот телефона обычно даёт шлюз 192.168.43.x — здесь шлюз другой)" ;;
  *) bare "  -> тип сети определить не удалось, смотри 'ip route' выше вручную." ;;
esac

bare ""
if ip -brief link show 2>/dev/null | grep -q '^throne-tun'; then
  bare "ВНИМАНИЕ: есть интерфейс throne-tun — VPN пользователя, похоже, ВКЛЮЧЁН."
  bare "  Результаты будут недостоверны: трафик может уходить через чужой туннель."
  bare "  Лучше выключить VPN и перезапустить. Выполнение НЕ прерываю."
else
  bare "OK: интерфейса throne-tun нет (VPN пользователя выключен)."
fi
OTHER_TUN="$(ip -brief link show type tun 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
[ -n "${OTHER_TUN// /}" ] && bare "Прочие tun-интерфейсы: $OTHER_TUN"

bare ""
if port_busy; then
  bare "ВНИМАНИЕ: порт $PORT ЗАНЯТ ещё до старта теста:"
  ss -ltnp 2>/dev/null | grep ":${PORT}[[:space:]]" | pipe_out
  bare "  Погаси то, что его держит, иначе все варианты будут мерить чужой прокси."
else
  bare "OK: порт $PORT свободен."
fi

# ===========================================================================
# Генератор конфигов + разбор пакетов (python3)
# ===========================================================================
mkdir -p "$STATEDIR"
cat > "$GEN" <<'PYEOF'
#!/usr/bin/env python3
"""Генерация конфигов матрицы и разбор noise-пакетов.
Ничего не хардкодит: креды p1Fqp и SIP-пакеты берутся из warp-xray.json, профиль
8 x rand 23-911 — из old-warp-xray.json, QUIC-пакеты I1, все endpoint'ы и вторые
креды (IFkdR) — из awg-samples/*.conf.

usage: mgf-gen.py <mode> <out.json> <warp.json> <old.json> <awgdir> <statedir> <loglevel>
modes: 1..10 — собрать конфиг варианта; awginfo — разбор образцов; quicinfo — свой QUIC
"""
import binascii, hashlib, json, os, random, re, sys

PORT = 10808
OK1180 = "megafon-ok-1180.conf"
OK903 = "megafon-ok-903.conf"
OK500 = "megafon-ok-500-jc120.conf"
FAIL946 = "megafon-fail-946-sip.conf"
SAMPLES = (OK1180, OK903, OK500, FAIL946)
LONG_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}


# ---------- разбор AWG .conf ------------------------------------------------
def awg_parse(path):
    d = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$", line)
            if m:
                d[m.group(1)] = m.group(2)
    return d


def awg_hex(val):
    """I1 = <b 0x....>  ->  hex-строка"""
    m = re.match(r"^<b\s+0x([0-9a-fA-F]+)>$", (val or "").strip())
    return m.group(1).lower() if m else None


def awg_addr(val):
    """'172.16.0.2, 2606:...:9143' -> ['172.16.0.2/32', '2606:...:9143/128']"""
    out = []
    for a in (val or "").split(","):
        a = a.strip()
        if not a:
            continue
        if "/" not in a:
            a += "/128" if ":" in a else "/32"
        out.append(a)
    return out


def varint(b, off):
    first = b[off]
    n = 1 << (first >> 6)
    val = first & 0x3F
    for i in range(1, n):
        val = (val << 8) | b[off + i]
    return val, off + n


def quic_describe(raw):
    """Разбор QUIC long header. -> (строки отчёта, это_валидный_initial)"""
    out = []
    fb = raw[0]
    hf, fix, typ = (fb >> 7) & 1, (fb >> 6) & 1, (fb >> 4) & 3
    ver = int.from_bytes(raw[1:5], "big") if len(raw) >= 5 else -1
    out.append("первый байт 0x%02x: header_form=%d fixed_bit=%d long_packet_type=%d (%s), младшие 4 бита 0x%x"
               % (fb, hf, fix, typ, LONG_TYPES.get(typ, "?"), fb & 0x0F))
    out.append("version = 0x%08x %s" % (ver, "(QUIC v1)" if ver == 1 else "(НЕ QUIC v1)"))
    if not (hf == 1 and fix == 1 and typ == 0 and ver == 1):
        out.append("ВЫВОД: это НЕ QUIC Initial v1.")
        return out, False
    try:
        off = 5
        dcl = raw[off]; off += 1
        dcid = raw[off:off + dcl]; off += dcl
        scl = raw[off]; off += 1
        scid = raw[off:off + scl]; off += scl
        tl, off = varint(raw, off)
        off += tl
        ln, after = varint(raw, off)
    except IndexError:
        out.append("ВЫВОД: заголовок обрывается, структура не бьётся.")
        return out, False
    rest = len(raw) - after
    good = (ln == rest)
    out.append("DCID (%d б) = %s" % (dcl, dcid.hex()))
    out.append("SCID (%d б) = %s, token_len = %d" % (scl, scid.hex() or "пусто", tl))
    out.append("length-varint = %d, фактически байт после него = %d -> %s"
               % (ln, rest, "СОВПАДАЕТ" if good else "НЕ совпадает (разница %d)" % (ln - rest)))
    out.append("итого пакет = %d байт%s" % (len(raw), " — типичный размер QUIC Initial от браузера"
                                            if 1200 <= len(raw) <= 1400 else ""))
    out.append("ВЫВОД: структурно ВАЛИДНЫЙ QUIC Initial v1%s" % ("" if good else ", но длина не сходится"))
    out.append("(младшие биты первого байта у реального QUIC скрыты header protection, поэтому"
               " ненулевой «reserved» — норма, а жёсткие нули как раз были бы аномалией)")
    return out, good


# ---------- генерация своего QUIC Initial -----------------------------------
def make_quic_initial():
    """Свой QUIC Initial v1 по структуре рабочих образцов:
    long header + fixed bit + type Initial (как c2/c7/ce — младшие биты случайны),
    version 1, случайный DCID длиной 8 ИЛИ 20 байт (обе длины есть в рабочих образцах),
    SCID длины 0, token длины 0, 2-байтовый length-varint, случайный payload.
    Итог 1250 б при DCID 8 и 1252 б при DCID 20 — ровно как у образцов."""
    first = 0xC0 | random.getrandbits(4)
    dcl = random.choice((8, 20))
    dcid = bytes(random.getrandbits(8) for _ in range(dcl))
    hdr = bytes([first]) + (1).to_bytes(4, "big") + bytes([dcl]) + dcid + bytes([0]) + bytes([0])
    payload_len = 1232 if dcl == 8 else 1222
    length_varint = (0x4000 | payload_len).to_bytes(2, "big")
    payload = bytes(random.getrandbits(8) for _ in range(payload_len))
    return hdr + length_varint + payload


def load_quic(statedir):
    """Генерируется один раз на запуск скрипта и переиспользуется вариантами 7 и 8."""
    p = os.path.join(statedir, "quic.hex")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(make_quic_initial().hex())
    with open(p) as f:
        return bytes.fromhex(f.read().strip())


# ---------- сборка конфига --------------------------------------------------
def hexpkt(raw, delay="1-2"):
    if isinstance(raw, str):
        raw = bytes.fromhex(raw)
    return {"type": "hex", "packet": binascii.hexlify(raw).decode(), "delay": delay}


def wg_of(cfg):
    for o in cfg.get("outbounds", []):
        if o.get("protocol") == "wireguard":
            return o
    raise SystemExit("в конфиге нет wireguard-аутбаунда")


def noises_of(cfg, tag):
    for o in cfg.get("outbounds", []):
        if o.get("tag") == tag:
            return o.get("settings", {}).get("noises", [])
    return []


def build(sk, addr, pub, endpoint, mtu, noises, loglevel, keepalive=5):
    peer = {"publicKey": pub, "endpoint": endpoint}
    if keepalive:
        peer["keepAlive"] = keepalive
    peer["allowedIPs"] = ["0.0.0.0/0", "::/0"]
    wg = {"tag": "warp", "protocol": "wireguard",
          "settings": {"secretKey": sk, "address": addr, "mtu": mtu, "peers": [peer]}}
    outs = [wg]
    if noises:
        wg["streamSettings"] = {"sockopt": {"dialerProxy": "noise-out"}}
        outs.append({"tag": "noise-out", "protocol": "freedom",
                     "settings": {"domainStrategy": "AsIs", "noises": noises}})
    return {
        "log": {"loglevel": loglevel},
        "dns": {"servers": ["1.1.1.1", "1.0.0.1"]},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": PORT, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True},
                      "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}],
        "outbounds": outs,
        "routing": {"domainStrategy": "AsIs",
                    "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "warp"}]},
    }


def main():
    mode, out, wpath, opath, awgdir, statedir, loglevel = sys.argv[1:8]
    with open(wpath) as f:
        new = json.load(f)
    with open(opath) as f:
        old = json.load(f)
    smp = {n: awg_parse(os.path.join(awgdir, n)) for n in SAMPLES}

    nwg = wg_of(new)["settings"]
    sk_new, addr_new = nwg["secretKey"], nwg["address"]
    pub = nwg["peers"][0]["publicKey"]

    # --- режим: разбор образцов -------------------------------------------
    if mode == "awginfo":
        print("Креды по файлам (первые 5 символов приватного ключа + sha256[:8]):")
        print("  %-26s: %s… / %s | peer %s… | %s"
              % ("warp-xray.json", sk_new[:5], hashlib.sha256(sk_new.encode()).hexdigest()[:8],
                 pub[:12], ", ".join(a.split("/")[0] for a in addr_new)))
        for n in SAMPLES:
            d = smp[n]
            pk = d.get("PrivateKey", "")
            print("  %-26s: %s… / %s | peer %s… | %s%s"
                  % (n, pk[:5], hashlib.sha256(pk.encode()).hexdigest()[:8],
                     (d.get("PublicKey") or "")[:12], d.get("Address", "?"),
                     "   <- те же креды, что в warp-xray.json" if pk == sk_new else "   <- ДРУГАЯ регистрация"))
        print("")
        print("Структура noise-пакетов в образцах (главная проверка гипотезы «I1 = QUIC Initial»):")
        for n in SAMPLES:
            d = smp[n]
            print("")
            print("--- %s" % n)
            print("    Endpoint %s | MTU %s | Jc=%s Jmin=%s Jmax=%s | S1..S4=%s,%s,%s,%s | H1..H4=%s,%s,%s,%s"
                  % (d.get("Endpoint"), d.get("MTU"), d.get("Jc"), d.get("Jmin"), d.get("Jmax"),
                     d.get("S1", "-"), d.get("S2", "-"), d.get("S3", "-"), d.get("S4", "-"),
                     d.get("H1", "-"), d.get("H2", "-"), d.get("H3", "-"), d.get("H4", "-")))
            for key in ("I1", "I2", "I3", "I4", "I5"):
                if key not in d:
                    continue
                h = awg_hex(d[key])
                if h is None:
                    print("    %s: не в формате <b 0x...>: %s" % (key, d[key][:50]))
                    continue
                raw = bytes.fromhex(h)
                txt = ""
                if all(32 <= c < 127 or c in (13, 10) for c in raw[:24]):
                    txt = "   ASCII: %r" % raw[:32].decode("latin1")
                print("    %s: %d байт, первые 16: %s%s" % (key, len(raw), raw[:16].hex(), txt))
                for ln_ in quic_describe(raw)[0]:
                    print("        " + ln_)
            if "I2" not in d:
                print("    I2: отсутствует")
        return

    # --- режим: свой QUIC-пакет -------------------------------------------
    if mode == "quicinfo":
        raw = load_quic(statedir)
        print("Сгенерирован свой QUIC Initial: %d байт" % len(raw))
        print("первые 32 байта: %s" % raw[:32].hex())
        for ln_ in quic_describe(raw)[0]:
            print("  " + ln_)
        print("Новый при каждом запуске скрипта: случайные DCID (8 или 20 байт, как в образцах),"
              " случайный payload, случайные младшие биты первого байта.")
        print("Зачем: копировать чужой I1 вечно нельзя — фиксированный DCID сам станет статичной"
              " сигнатурой, ровно как случилось с SIP-пакетом из RFC 3261.")
        return

    # --- сборка вариантов --------------------------------------------------
    ntag = wg_of(new).get("streamSettings", {}).get("sockopt", {}).get("dialerProxy", "noise-out")
    nn = noises_of(new, ntag)
    sip_hex = [n for n in nn if n.get("type") == "hex"]     # 2 статичных SIP-пакета (RFC 3261)
    rand4 = [n for n in nn if n.get("type") == "rand"]      # 4 x rand 40-70
    otag = wg_of(old).get("streamSettings", {}).get("sockopt", {}).get("dialerProxy", "MMMnoise")
    rand8 = [n for n in noises_of(old, otag) if n.get("type") == "rand"]   # 8 x rand 23-911

    ep = {n: smp[n].get("Endpoint") for n in SAMPLES}
    i1 = {n: awg_hex(smp[n].get("I1")) for n in SAMPLES}
    sk_500 = smp[OK500].get("PrivateKey")
    addr_500 = awg_addr(smp[OK500].get("Address"))

    for n in (OK1180, OK903, OK500):
        if not ep[n] or not i1[n]:
            raise SystemExit("не удалось прочитать Endpoint/I1 из %s" % n)
    if not ep[FAIL946]:
        raise SystemExit("не удалось прочитать Endpoint из %s" % FAIL946)
    if not sk_500 or not addr_500:
        raise SystemExit("не удалось прочитать PrivateKey/Address из %s" % OK500)
    if not rand4:
        raise SystemExit("в %s не нашлось rand-пакетов 40-70" % wpath)
    if not sip_hex:
        raise SystemExit("в %s не нашлось hex(SIP)-пакетов" % wpath)
    if not rand8:
        raise SystemExit("в %s не нашлось rand-пакетов 23-911" % opath)

    q1180 = [hexpkt(i1[OK1180])]
    q903 = [hexpkt(i1[OK903])]
    q500 = [hexpkt(i1[OK500])]
    qown = [hexpkt(load_quic(statedir))]

    # вариант: (endpoint, mtu, noises, secretKey, address)
    table = {
        1:  (ep[OK1180],  1420, q1180 + rand4,  sk_new, addr_new),
        2:  (ep[OK903],   1420, q903 + rand4,   sk_new, addr_new),
        3:  (ep[FAIL946], 1420, q1180 + rand4,  sk_new, addr_new),
        4:  (ep[OK1180],  1420, sip_hex + rand4, sk_new, addr_new),
        5:  (ep[FAIL946], 1420, sip_hex + rand4, sk_new, addr_new),
        6:  (ep[OK1180],  1420, [],             sk_new, addr_new),
        7:  (ep[OK1180],  1420, qown + rand4,   sk_new, addr_new),
        8:  (ep[FAIL946], 1420, qown + rand4,   sk_new, addr_new),
        9:  (ep[OK500],   1280, q500 + rand8,   sk_500, addr_500),
        10: (ep[OK500],   1280, rand8,          sk_500, addr_500),
    }
    v = int(mode)
    if v not in table:
        raise SystemExit("нет такого варианта: %d" % v)
    endpoint, mtu, noises, sk, addr = table[v]
    cfg = build(sk, addr, pub, endpoint, mtu, noises, loglevel)
    with open(out, "w") as f:
        json.dump(cfg, f, indent=2)

    # сводка в stderr: чем именно этот вариант отличается (первая строка — для таблицы)
    wgs = wg_of(cfg)["settings"]
    tag = wg_of(cfg).get("streamSettings", {}).get("sockopt", {}).get("dialerProxy", "")
    ns = noises_of(cfg, tag) if tag else []
    parts = []
    for n in ns:
        if n.get("type") == "rand":
            parts.append("rand %s (delay %s)" % (n.get("packet"), n.get("delay")))
        else:
            parts.append("hex %d б (delay %s)" % (len(n.get("packet", "")) // 2, n.get("delay")))
    cnt = {}
    for p in parts:
        cnt[p] = cnt.get(p, 0) + 1
    agg = ["%dx %s" % (cnt[p], p) if cnt[p] > 1 else p for p in dict.fromkeys(parts)]
    sys.stderr.write("KEY=%s\n" % sk[:5])
    sys.stderr.write("endpoint=%s mtu=%s keepAlive=%s key=%s… (sha256:%s) addr=%s noises=%d [%s]\n" % (
        wgs["peers"][0]["endpoint"], wgs.get("mtu"), wgs["peers"][0].get("keepAlive", "нет"),
        sk[:5], hashlib.sha256(sk.encode()).hexdigest()[:8],
        ", ".join(a.split("/")[0] for a in wgs["address"]), len(ns), "; ".join(agg) or "нет"))


main()
PYEOF
chmod +x "$GEN"

rm -f "$STATEDIR/quic.hex"   # свой QUIC-пакет — новый на каждый запуск

# ---------------------------------------------------------------------------
sect "2. РАЗБОР РЕАЛЬНЫХ AWG-ОБРАЗЦОВ (гипотеза «I1 = QUIC Initial»)"
python3 "$GEN" awginfo /dev/null "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" 2>&1 | pipe_out

sect "3. СВОЙ QUIC INITIAL для вариантов 7 и 8 (генерируется заново каждый запуск)"
python3 "$GEN" quicinfo /dev/null "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" 2>&1 | pipe_out

# ===========================================================================
# 4. Матрица
# ===========================================================================
sect "4. ПРОГОН МАТРИЦЫ (10 вариантов, порт $PORT, последовательно)"

run_variant() {
  local v="$1"
  local cfg="$SCRATCH/mgf-${v}.json"
  local raw="$SCRATCH/mgf-${v}.rawlog"
  local pub="./results/megafon-${v}.log"
  local gout facts

  bare ""
  bare "------------------------------------------------------------"
  log "ВАРИАНТ $v: $(desc_of "$v")"

  rm -f "$cfg" "$raw"
  if ! gout="$(python3 "$GEN" "$v" "$cfg" "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" 2>&1 >/dev/null)"; then
    bare "  ОШИБКА генерации конфига: $gout"
    R_ST[$v]="GENERR"; R_NOTE[$v]="конфиг не сгенерился"
    return 0
  fi
  R_KEY[$v]="$(printf '%s\n' "$gout" | sed -n 's/^KEY=//p' | head -1)"
  [ -z "${R_KEY[$v]}" ] && R_KEY[$v]="?"
  facts="$(printf '%s\n' "$gout" | grep -v '^KEY=' | head -1)"
  bare "  Конфиг : $cfg"
  bare "  Факты  : $facts"
  bare "  Ключ   : ${R_KEY[$v]}… (первые 5 символов secretKey)"

  if ! xray run -test -c "$cfg" >"$SCRATCH/mgf-${v}.test" 2>&1; then
    bare "  xray run -test: НЕВАЛИДЕН, пропускаю вариант:"
    tail -3 "$SCRATCH/mgf-${v}.test" | pipe_out
    R_ST[$v]="INVALID"; R_NOTE[$v]="xray run -test не прошёл"
    return 0
  fi
  bare "  xray run -test: OK"

  if port_busy; then
    bare "  ВНИМАНИЕ: порт $PORT занят перед стартом варианта — жду освобождения"
    wait_port_free || { bare "  порт всё ещё занят, пропускаю вариант"; R_ST[$v]="PORTBUSY"; return 0; }
  fi
  : > "$raw"
  nohup xray run -c "$cfg" >>"$raw" 2>&1 &
  CUR_PID="$!"
  echo "$CUR_PID" > "$PIDFILE"
  bare "  Запущен: pid=$CUR_PID (сырой лог: $raw)"
  sleep "$START_WAIT"

  if ! kill -0 "$CUR_PID" 2>/dev/null; then
    bare "  ПРОЦЕСС УМЕР на старте, последние строки лога:"
    tail -5 "$raw" | pipe_out
    R_ST[$v]="DEAD"; R_NOTE[$v]="процесс не выжил ${START_WAIT}с"
    CUR_PID=""
  elif ! port_busy; then
    bare "  ВНИМАНИЕ: процесс жив, но порт $PORT не слушается — прокси не поднялся"
    R_ST[$v]="NOPORT"; R_NOTE[$v]="порт не слушается"
  else
    bare "  Процесс жив, порт $PORT слушается. Запросы к $TRACE_URL:"
    local i out body last http tt wv rc
    for i in $(seq 1 "$CURL_TRIES"); do
      out="$(curl -s --max-time "$CURL_MAXTIME" -x "$PROXY" -w $'\n%{http_code} %{time_total}' "$TRACE_URL" 2>/dev/null)"
      rc=$?
      last="$(printf '%s\n' "$out" | tail -1)"
      body="$(printf '%s\n' "$out" | sed '$d')"
      http="$(printf '%s\n' "$last" | awk '{print $1}')"; [ -z "${http:-}" ] && http="000"
      tt="$(printf '%s\n' "$last" | awk '{print $2}')";   [ -z "${tt:-}" ] && tt="-"
      wv="$(printf '%s\n' "$body" | grep -o 'warp=[a-z+]*' | head -1)"
      bare "    попытка $i: rc=$rc http=$http time=${tt}s ${wv:+[$wv]}"
      R_HTTP[$v]="$http"; R_TIME[$v]="$tt"; R_WARP[$v]="${wv:-нет}"
      if [ "$http" = "200" ] && { [ "$wv" = "warp=on" ] || [ "$wv" = "warp=plus" ]; }; then
        R_ST[$v]="OK"; R_NOTE[$v]=""
        R_MS[$v]="$(awk -v t="$tt" 'BEGIN{printf "%d", t*1000}' 2>/dev/null || echo 999999)"
        printf '%s\n' "$body" | grep -E '^(warp|loc|ip|colo)=' | pipe_out
        break
      elif [ "$http" = "200" ]; then
        R_ST[$v]="BAD"; R_NOTE[$v]="http 200, но warp=${wv:-?} — трафик пошёл НЕ через WARP"
      elif [ "$http" != "000" ]; then
        R_ST[$v]="BAD"; R_NOTE[$v]="http $http — проблема самого теста, не канала"
      else
        R_ST[$v]="FAIL"; R_NOTE[$v]="нет ответа (curl rc=$rc, таймаут ${CURL_MAXTIME}с)"
      fi
    done
  fi

  stop_current
  wait_port_free || bare "  ВНИМАНИЕ: порт $PORT не освободился после варианта $v"

  R_HS_S[$v]="$(grep -c 'Sending handshake initiation' "$raw" 2>/dev/null || true)"
  R_HS_R[$v]="$(grep -c 'Received handshake response' "$raw" 2>/dev/null || true)"
  R_HS_I[$v]="$(grep -ci 'handshake did not complete' "$raw" 2>/dev/null || true)"
  [ -z "${R_HS_S[$v]}" ] && R_HS_S[$v]=0
  [ -z "${R_HS_R[$v]}" ] && R_HS_R[$v]=0
  [ -z "${R_HS_I[$v]}" ] && R_HS_I[$v]=0
  bare "  Хендшейки: initiation=${R_HS_S[$v]} response=${R_HS_R[$v]} 'did not complete'=${R_HS_I[$v]}"
  if [ "$LOGLEVEL" != "debug" ]; then
    bare "    (loglevel=$LOGLEVEL — xray этих строк не пишет, нули здесь ничего не значат)"
  elif [ "${R_HS_S[$v]}" -gt 0 ] 2>/dev/null && [ "${R_HS_R[$v]}" = "0" ]; then
    bare "    -> инициации уходят, ответов НЕТ: UDP до endpoint режется по пути (или пир молчит)"
  elif [ "${R_HS_R[$v]}" != "0" ] && [ "${R_ST[$v]}" != "OK" ]; then
    bare "    -> хендшейк ПРОШЁЛ, но данные не идут: рвётся уже установленная сессия"
  fi

  {
    echo "# NOTE: log filtered for publication — only Xray startup and WireGuard transport/handshake events are kept."
    echo "# Variant $v: $(desc_of "$v")"
    grep -E "$FILTER_RE" "$raw" 2>/dev/null
  } > "$pub"
  bare "  Публикуемый лог: $pub ($(wc -l <"$pub" 2>/dev/null || echo 0) строк)"
  log "ВАРИАНТ $v ИТОГ: ${R_ST[$v]}${R_NOTE[$v]:+ — ${R_NOTE[$v]}}"
  return 0
}

for v in $VARIANTS; do
  run_variant "$v"
done

# ===========================================================================
# 5. Фаза 2 — стабильность победителя
# ===========================================================================
sect "5. ФАЗА 2: СТАБИЛЬНОСТЬ ПОБЕДИТЕЛЯ (${STAB_ATTEMPTS} запросов каждые ${STAB_INTERVAL}с ≈ 100 с)"

WIN=""
for v in $VARIANTS; do
  if [ "${R_ST[$v]}" = "OK" ]; then
    if [ -z "$WIN" ] || [ "${R_MS[$v]}" -lt "${R_MS[$WIN]}" ] 2>/dev/null; then WIN="$v"; fi
  fi
done

STAB_OK=0; STAB_TOTAL=0
if [ -z "$WIN" ]; then
  bare "Ни один вариант не дал OK — фаза стабильности смысла не имеет, пропускаю."
else
  bare "Победитель: вариант $WIN (наименьшая задержка среди OK: ${R_TIME[$WIN]}s)"
  bare "  $(desc_of "$WIN")"
  cfg="$SCRATCH/mgf-${WIN}.json"
  raw="$SCRATCH/mgf-${WIN}-stab.rawlog"
  : > "$raw"
  nohup xray run -c "$cfg" >>"$raw" 2>&1 &
  CUR_PID="$!"
  echo "$CUR_PID" > "$PIDFILE"
  bare "Запущен pid=$CUR_PID, жду ${START_WAIT}с"
  sleep "$START_WAIT"
  bare ""
  bare "  #  время     http  warp      сек"
  bare "  -- --------  ----  --------  -----"
  for i in $(seq 1 "$STAB_ATTEMPTS"); do
    if ! kill -0 "$CUR_PID" 2>/dev/null; then
      bare "  процесс умер на попытке $i — прерываю фазу 2"
      break
    fi
    out="$(curl -s --max-time "$CURL_MAXTIME" -x "$PROXY" -w $'\n%{http_code} %{time_total}' "$TRACE_URL" 2>/dev/null)"
    last="$(printf '%s\n' "$out" | tail -1)"
    body="$(printf '%s\n' "$out" | sed '$d')"
    http="$(printf '%s\n' "$last" | awk '{print $1}')"; [ -z "${http:-}" ] && http="000"
    tt="$(printf '%s\n' "$last" | awk '{print $2}')";   [ -z "${tt:-}" ] && tt="-"
    wv="$(printf '%s\n' "$body" | grep -o 'warp=[a-z+]*' | head -1)"
    STAB_TOTAL=$((STAB_TOTAL+1))
    if [ "$http" = "200" ] && { [ "$wv" = "warp=on" ] || [ "$wv" = "warp=plus" ]; }; then
      STAB_OK=$((STAB_OK+1))
    fi
    bare "$(printf '  %2d  %s  %4s  %-8s  %s' "$i" "$(ts)" "$http" "${wv:-нет}" "$tt")"
    [ "$i" -lt "$STAB_ATTEMPTS" ] && sleep "$STAB_INTERVAL"
  done
  S_S="$(grep -c 'Sending handshake initiation' "$raw" 2>/dev/null || true)"; S_S="${S_S:-0}"
  S_R="$(grep -c 'Received handshake response' "$raw" 2>/dev/null || true)"; S_R="${S_R:-0}"
  S_I="$(grep -ci 'handshake did not complete' "$raw" 2>/dev/null || true)"; S_I="${S_I:-0}"
  stop_current
  wait_port_free || bare "ВНИМАНИЕ: порт $PORT не освободился после фазы 2"
  {
    echo "# NOTE: log filtered for publication — only Xray startup and WireGuard transport/handshake events are kept."
    echo "# Stability phase, winner variant $WIN: $(desc_of "$WIN")"
    grep -E "$FILTER_RE" "$raw" 2>/dev/null
  } > "./results/megafon-stability.log"
  bare ""
  bare "Стабильность: успешных $STAB_OK из $STAB_TOTAL"
  bare "Хендшейки за фазу 2: initiation=$S_S response=$S_R 'did not complete'=$S_I"
  bare "Публикуемый лог фазы 2: ./results/megafon-stability.log"
  if [ "$STAB_OK" = "$STAB_TOTAL" ] && [ "$STAB_TOTAL" -gt 0 ]; then
    bare "-> канал держится все ~100 с, отложенного среза не видно"
  elif [ "$STAB_OK" -gt 0 ]; then
    bare "-> канал ПЛАВАЕТ: часть запросов прошла, часть нет — похоже на срез/деградацию не сразу"
  else
    bare "-> в фазе 2 не прошло НИ ОДНОГО запроса, хотя в матрице вариант дал OK: срез с задержкой"
  fi
fi

# ===========================================================================
# 6. Итоги
# ===========================================================================
sect "6. ИТОГОВАЯ ТАБЛИЦА"
bare ""
bare "   #  статус    http  warp      сек    HS:отпр/отв/неуд  ключ    вариант"
bare "  --  --------  ----  --------  -----  ----------------  ------  --------------------------------"
for v in $VARIANTS; do
  bare "$(printf '  %2s  %-8s  %4s  %-8s  %-5s  %4s/%3s/%3s       %-6s  %s' \
      "$v" "${R_ST[$v]}" "${R_HTTP[$v]}" "${R_WARP[$v]}" "${R_TIME[$v]}" \
      "${R_HS_S[$v]}" "${R_HS_R[$v]}" "${R_HS_I[$v]}" "${R_KEY[$v]}" "$(desc_of "$v")")"
done
bare ""
bare "Легенда: OK = http 200 и warp=on/plus | BAD = ответ есть, но не 200 / не через WARP"
bare "         FAIL = нет ответа (таймаут) | INVALID = конфиг не прошёл xray run -test"
bare "         HS = строки лога 'Sending handshake initiation' / 'Received handshake response' /"
bare "              'Handshake did not complete' (пишутся только при loglevel=debug)"
for v in $VARIANTS; do
  [ -n "${R_NOTE[$v]}" ] && bare "  прим. $v: ${R_NOTE[$v]}"
done

sect "7. ВЫВОДЫ ПО ГИПОТЕЗАМ"

if [ "$LOGLEVEL" != "debug" ]; then
  bare ""
  bare "ВАЖНО: loglevel=$LOGLEVEL, поэтому все счётчики хендшейков ниже НУЛЕВЫЕ — xray пишет"
  bare "эти строки только на debug. Выводы строятся ТОЛЬКО по статусам OK/BAD/FAIL, а фразы"
  bare "вида «по логу судить нельзя» означают именно отсутствие debug-лога, а не поломку сети."
  bare "Нужна диагностика 'режется UDP' vs 'рвётся сессия' — перезапусти: ./tests/test-megafon.sh --log-debug"
fi

st() { echo "${R_ST[$1]}"; }
ok() { [ "${R_ST[$1]}" = "OK" ]; }
hs_resp() { [ "${R_HS_R[$1]}" != "0" ] && [ "${R_HS_R[$1]}" != "-" ]; }

bare ""
bare "ПРОФИЛЬ ПРОТИВ ПОРТА — прямые пары:"
bare "  QUIC-профиль     : вариант 1 (:1180) = $(st 1)   vs   вариант 3 (:946) = $(st 3)   <- ключевая пара"
bare "  SIP-профиль      : вариант 4 (:1180) = $(st 4)   vs   вариант 5 (:946) = $(st 5)"
bare "  свой QUIC        : вариант 7 (:1180) = $(st 7)   vs   вариант 8 (:946) = $(st 8)"
bare "  второй рабочий ep: вариант 2 (8.34.70.4:903)  = $(st 2)"
bare "  третий рабочий ep: вариант 9 (162.159.192.1:500, ключ IFkdR) = $(st 9)"
bare ""
bare "  на одном и том же порту :1180 — QUIC (1) = $(st 1), SIP (4) = $(st 4), без обфускации (6) = $(st 6)"
bare "  на одном и том же порту :946  — QUIC (3) = $(st 3), SIP (5) = $(st 5), свой QUIC (8) = $(st 8)"
bare "  на :500 (ключ IFkdR)          — QUIC+rand (9) = $(st 9), только rand без hex (10) = $(st 10)"

# --- контроль методики
bare ""
bare "КОНТРОЛЬ МЕТОДИКИ (вариант 5 = ровно нерабочий megafon-fail-946-sip: SIP + :946) = $(st 5)"
METH_OK=1
if [ "${R_ST[5]}" = "FAIL" ]; then
  bare "  -> известный провал ВОСПРОИЗВЁЛСЯ: методика ловит разницу, остальным строкам можно верить."
elif ok 5; then
  METH_OK=0
  bare "  -> ВНИМАНИЕ: то, что у пользователя НЕ работало, здесь ЗАРАБОТАЛО. Значит условия"
  bare "     изменились (другая сота / APN / время суток) либо прошлый провал был не про этот конфиг."
  bare "     ВСЕМУ ЭТОМУ ПРОГОНУ ВЕРИТЬ НЕЛЬЗЯ — выводы ниже считать недостоверными."
else
  bare "  -> вариант 5 дал ${R_ST[5]} (ни OK, ни чистого FAIL) — контроль методики неоднозначен."
fi

# --- контроль чистого WG
bare ""
bare "КОНТРОЛЬ «чистый WireGuard без обфускации» (вариант 6, :1180) = $(st 6)"
bare "  хендшейки: отправлено ${R_HS_S[6]}, получено ${R_HS_R[6]}"
if ok 6; then
  bare "  -> Мегафон НЕ режет чистый WG на этом порту: обфускация тут вообще не обязательна,"
  bare "     а провал исходного конфига — следствие самих noise-пакетов, а не WG как такового."
elif hs_resp 6; then
  bare "  -> ответ на хендшейк есть, но данные не идут: WG опознаётся и душится ПОСЛЕ установления."
elif [ "${R_HS_S[6]}" != "0" ] && [ "${R_HS_S[6]}" != "-" ]; then
  bare "  -> инициации уходят, ответов 0: чистый WG режется сразу, обфускация обязательна."
else
  bare "  -> по логу судить нельзя (нет строк хендшейка), контроль не состоялся."
fi

# --- креды IFkdR
bare ""
bare "КРЕДЫ IFkdR (вторая регистрация WARP, варианты 9 и 10): 9 = $(st 9), 10 = $(st 10)"
bare "  хендшейки варианта 9: отправлено ${R_HS_S[9]}, получено ${R_HS_R[9]}"
if hs_resp 9 || ok 9; then
  bare "  -> на хендшейк ПРИШЁЛ ответ: регистрация IFkdR ЖИВА (пир принял ключ)."
elif [ "${R_HS_S[9]}" != "0" ] && [ "${R_HS_S[9]}" != "-" ]; then
  bare "  -> ответа нет. Отличить «креды протухли» от «трафик режется» тут НЕЛЬЗЯ: WireGuard"
  bare "     на неизвестный ключ отвечает молчанием — ровно как ТСПУ при блокировке."
else
  bare "  -> вариант 9 не дошёл до хендшейка, про креды сказать нечего."
fi
if ok 9 && ! ok 10; then
  bare "  9 vs 10: с QUIC-пакетом работает, без него (только 8 x rand) — нет."
  bare "  -> Дело НЕ в объёме мусора, а именно в QUIC-пакете. Это же объясняет, почему июльский"
  bare "     old-warp-xray.json (конвертация, при которой I1 потеряли) вёл себя иначе."
elif ok 9 && ok 10; then
  bare "  9 vs 10: работает и с QUIC-пакетом, и без него -> на этом endpoint хватает объёма rand-мусора."
elif ! ok 9 && ok 10; then
  bare "  9 vs 10: неожиданно — без hex работает, с hex нет. Смотри логи, возможно 1252-байтный"
  bare "  noise-пакет ломается на пути (фрагментация/MTU мобильной сети)."
fi

# --- MTU
bare ""
bare "MTU: варианты 1-8 = 1420, варианты 9-10 = 1280 — ровно как в исходных AWG-образцах."
bare "  У рабочих образцов MTU РАЗНЫЙ (1420 и 1280), у нерабочего 1420 — значит MTU не может"
bare "  быть причиной провала. В этом прогоне MTU не изолированная переменная и выводов по нему нет."

# ===========================================================================
# ГЛАВНЫЕ ОТВЕТЫ
# ===========================================================================
sect "8. ТРИ ГЛАВНЫХ ОТВЕТА"

ANY_OK=0
for v in $VARIANTS; do ok "$v" && ANY_OK=$((ANY_OK+1)); done

bare ""
bare "(1) ЧТО РЕШАЕТ — ПРОФИЛЬ ПАКЕТА ИЛИ ПОРТ?"
if [ "$ANY_OK" = "0" ]; then
  bare "    ОТВЕТ НЕ ПОЛУЧЕН: не заработал ни один из 10 вариантов. Наблюдалось:"
  NOHS=0; SENT_NORESP=0; RESP_NODATA=0
  for v in $VARIANTS; do
    s="${R_HS_S[$v]}"; r="${R_HS_R[$v]}"
    case "$s" in ''|'-'|0) NOHS=$((NOHS+1)); continue ;; esac
    if [ "$r" = "0" ]; then SENT_NORESP=$((SENT_NORESP+1)); else RESP_NODATA=$((RESP_NODATA+1)); fi
  done
  bare "      - без отправленных хендшейков (не стартовали / невалидны): $NOHS"
  bare "      - инициации уходили, ответов 0 (UDP режется или пир молчит): $SENT_NORESP"
  bare "      - ответ на хендшейк был, но данные не пошли: $RESP_NODATA"
  bare "    Ни про профиль, ни про порт выводов НЕ делаю — данных нет. Что проверить дальше:"
  bare "      (а) жив ли мобильный интернет вообще: curl без -x,"
  bare "      (б) точно ли сеть мобильная (раздел 1 отчёта),"
  bare "      (в) работает ли на этом же телефоне сам megafon-ok-1180.conf в клиенте AmneziaWG —"
  bare "          если AWG работает, а xray нет, разница в реализации обфускации, а не в сети"
  bare "          (в AWG junk-пакеты Jc идут ПЕРЕД I1 и сам I1 привязан к handshake-сообщению,"
  bare "          в xray noises — это просто пачка UDP-датаграмм перед соединением)."
elif ok 3 || ok 8; then
  bare "    РЕШАЕТ ПРОФИЛЬ. QUIC-профиль прошёл на «плохом» порту 946 (вариант 3 = $(st 3),"
  bare "    вариант 8 = $(st 8)), где SIP-профиль = $(st 5). Порт 946 сам по себе не блокирован —"
  bare "    блокируется именно SIP-подобный noise. Прод-конфиг достаточно починить заменой noise,"
  bare "    endpoint менять не обязательно."
elif ok 1 && ! ok 3 && ! ok 5 && ! ok 4; then
  bare "    РЕШАЕТ ПОРТ (или порт + профиль вместе): на :946 не прошло НИЧЕГО (3=$(st 3), 5=$(st 5),"
  bare "    8=$(st 8)), а на :1180 прошёл хотя бы QUIC-профиль (1=$(st 1)). При этом на :1180"
  bare "    SIP = $(st 4) — если FAIL, то ФАКТОРА ДВА и менять надо и порт, и профиль."
elif ok 1 && ! ok 3 && ok 4; then
  bare "    РЕШАЕТ ПОРТ: на :1180 прошли оба профиля (1=$(st 1), 4=$(st 4)), на :946 ни один."
else
  bare "    Картина неоднозначная. OK получили варианты:"
  for v in $VARIANTS; do ok "$v" && bare "      - вариант $v: $(desc_of "$v")"; done
  bare "    Смотри таблицу и счётчики хендшейков выше."
fi
[ "$METH_OK" = "0" ] && bare "    NB: контроль методики (вариант 5) сломан — см. раздел 7, вывод ненадёжен."

bare ""
bare "(2) КАКОЙ ПРОФИЛЬ РЕКОМЕНДОВАТЬ ДЛЯ МЕГАФОНА?"
if [ -n "$WIN" ]; then
  bare "    Вариант $WIN: $(desc_of "$WIN")"
  bare "    Задержка ${R_TIME[$WIN]}s, стабильность $STAB_OK/$STAB_TOTAL за ~100 с."
  bare "    Готовый конфиг: $SCRATCH/mgf-${WIN}.json (скопировать в проект, если подходит)."
  if ok 1 || ok 2 || ok 3 || ok 9; then
    bare "    Профиль: hex-пакет QUIC Initial + rand-мусор. Статичный SIP из RFC 3261 — выбросить."
  fi
else
  bare "    Рекомендовать нечего: ни один вариант не дал OK."
fi

bare ""
bare "(3) РАБОТАЕТ ЛИ СВОЙ СГЕНЕРИРОВАННЫЙ QUIC (можно ли уйти от копирования чужого пакета)?"
bare "    вариант 7 (:1180) = $(st 7), вариант 8 (:946) = $(st 8)"
if ok 7 || ok 8; then
  bare "    ДА. Свой QUIC Initial со случайным DCID работает -> в прод можно генерировать пакет"
  bare "    на каждого клиента и не тащить чужой DCID, который со временем сам станет сигнатурой."
elif { ok 1 || ok 2 || ok 9; } && ! ok 7 && ! ok 8; then
  bare "    НЕТ. Копия чужого I1 проходит, а свой сгенерированный — нет. Значит важно не просто"
  bare "    «похоже на QUIC»: скорее всего проверяется валидность внутренностей (крипта/ClientHello)"
  bare "    или сам пакет должен быть от реального QUIC-клиента. Для прода это означает: либо"
  bare "    копировать рабочий I1, либо снимать свой дамп настоящего QUIC Initial (например,"
  bare "    из curl --http3 / браузера) и подставлять его."
else
  bare "    Ответа нет: ни свой QUIC, ни копия чужого не дали OK в этом прогоне."
fi

# ===========================================================================
# 9. Финальная зачистка
# ===========================================================================
sect "9. ЗАЧИСТКА"
stop_current
if port_busy; then
  bare "ВНИМАНИЕ: порт $PORT ВСЁ ЕЩЁ занят:"
  ss -ltnp 2>/dev/null | grep ":${PORT}[[:space:]]" | pipe_out
else
  bare "OK: порт $PORT свободен."
fi
LEFT="$(ps -eo pid=,args= 2>/dev/null | grep -F 'xray run' | grep -F 'mgf-' || true)"
if [ -n "$LEFT" ]; then
  bare "ВНИМАНИЕ: остались наши процессы xray (погаси по pid):"
  printf '%s\n' "$LEFT" | pipe_out
else
  bare "OK: наших процессов 'xray run ... mgf-*' не осталось."
fi
bare ""
bare "Читать: $REPORT (этот файл), ./results/megafon-<N>.log по вариантам, ./results/megafon-stability.log"
bare "Временные конфиги и СЫРЫЕ логи: $SCRATCH/mgf-*.json, $SCRATCH/mgf-*.rawlog"
bare "  (сырые логи в репозиторий не попадают, публиковать их не нужно)"
log "ГОТОВО."
exit 0
