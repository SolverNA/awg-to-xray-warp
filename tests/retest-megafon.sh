#!/usr/bin/env bash
# retest-megafon.sh — автономный ПЕРЕПРОВЕРОЧНЫЙ тест на мобильной сети (Мегафон).
#
# ЗАЧЕМ. Прошлый прогон (./results/megafon-report.txt) дал ровно один OK — вариант 9:
#   hex QUIC I1 из megafon-ok-500-jc120.conf + 8 x rand 23-911,
#   endpoint 162.159.192.1:500, MTU 1280, ключ IFkdR.
# Все варианты 1-8 (ключ p1Fqp, endpoint'ы 8.34.146.7:1180 / 8.34.70.4:903 / 8.6.112.7:946,
# MTU 1420) провалились независимо от профиля обфускации. Но вариант 9 отличается от них
# сразу по нескольким параметрам (подсеть endpoint, порт, MTU, ключ), поэтому сказать,
# что именно решило, нельзя. Этот скрипт разводит переменные по одной.
#
# ФАКТОР «КЛЮЧ» УЖЕ ИСКЛЮЧЁН вручную, до этого скрипта: на чистом WG без обфускации через
# 162.159.192.1:500 (каждый ключ со своим address v6) ВСЕ ТРИ регистрации WARP отдали
# warp=on — p1Fqp (legacy/warp-xray-sip-profile.json), IFkdR (awg-samples/megafon-ok-500-jc120.conf) и
# WE7c0 (old-warp-xray.json). Провал вариантов 1-8 точно НЕ из-за кредов, поэтому здесь
# на перебор ключей не тратится ни одного варианта: всё гоняется на IFkdR (единственный,
# давший OK на самом Мегафоне), плюс ОДНА контрольная точка на p1Fqp.
#
# ТРИ ЭТАПА, строго по порядку:
#   1. ДОСТУПНОСТЬ ENDPOINT'ОВ: чистый WG БЕЗ обфускации, один ключ IFkdR, MTU 1280,
#      пять адресов/портов подряд. Вопрос ровно один — какие endpoint'ы вообще проходят
#      с Мегафона на голом WireGuard, без всякой обфускации. Если пройдёт только
#      162.159.192.1, гипотеза «режутся подсети 8.34.x / 8.6.x целиком» подтверждена,
#      и дальше всё решает выбор endpoint, а не профиль пакета.
#   2. Нативный AmneziaWG (awg-quick) на исходных .conf — базовая истина: работают ли
#      сами конфиги ПРЯМО СЕЙЧАС в родном клиенте. Если нет — от их Xray-реплик ждать нечего.
#   3. Xray-матрица с изоляцией переменных: endpoint vs ключ vs MTU vs профиль.
#
# Запуск (VPN пользователя выключить, сеть переключить на Мегафон):
#     ./tests/retest-megafon.sh
# Длительность: ~1 мин этап 1 + ~2-3 мин этап 2 + ~4 мин этап 3 + ~2 мин стабильность.
# Всё пишется в stdout и в ./results/retest-report.txt (перезаписывается при каждом запуске).
#
# Креды, hex-пакеты и endpoint'ы в тексте скрипта НЕ хардкодятся — читаются программно
# (python3) из ./legacy/warp-xray-sip-profile.json, ./legacy/old-warp-xray.json и ./awg-samples/*.conf.
#
# ЭТАП 2 ТРЕБУЕТ sudo и поднимает туннель, через который идёт ВЕСЬ трафик. Защита:
# sudo запрашивается один раз в начале; без sudo этап 2 целиком пропускается; trap на
# EXIT/INT/TERM гасит поднятый интерфейс; после каждого down проверяется, что связь
# вернулась, иначе в отчёт пишется аварийная команда восстановления и этап 2 прекращается.

set -u

cd "$(dirname "$(readlink -f "$0")")/.." || exit 1   # корень репозитория: скрипты лежат в tests/, данные и конфиги — выше

# --- пути, порты, параметры -------------------------------------------------
CFG_NEW="./legacy/warp-xray-sip-profile.json"      # креды p1Fqp + статичные SIP-пакеты + 4 x rand 40-70
CFG_OLD="./legacy/old-warp-xray.json"  # профиль 8 x rand 23-911
AWGDIR="./awg-samples"          # QUIC-пакеты I1, endpoint'ы, вторые креды (IFkdR)

SCRATCH="${SCRATCH_DIR:-${TMPDIR:-/tmp}}"
GEN="$SCRATCH/rtm-gen.py"
STATEDIR="$SCRATCH/rtm-state"

REPORT="./results/retest-report.txt"
PIDFILE="$SCRATCH/rtm-xray.pid"

SOCKS_HOST="127.0.0.1"
PORT="10808"
PROXY="socks5h://${SOCKS_HOST}:${PORT}"

# ВАЖНО: без завершающего слеша — на .../trace/ Cloudflare отдаёт 404.
TRACE_URL="https://www.cloudflare.com/cdn-cgi/trace"

START_WAIT=4       # сек на старт инстанса xray
CURL_MAXTIME=12    # таймаут одного запроса через прокси
CURL_TRIES=2       # попыток на вариант
AWG_WAIT=5         # сек после awg-quick up до первого запроса
AWG_MAXTIME=15     # таймаут прямого запроса через нативный туннель
AWG_BACK_MAXTIME=10 # таймаут проверки «связь вернулась после down»
STAB_ATTEMPTS=5    # фаза стабильности: 5 запросов
STAB_INTERVAL=20   # каждые 20 с (= ~100 с)

IDS1="11 12 13 14 15"              # этап 1: перебор endpoint'ов на ключе IFkdR
ID_CTRL="16"                       # контрольная точка на втором ключе (endpoint решается в рантайме)
IDS3="31 32 33 34 35 36"           # этап 3
IDS_ALL="$IDS1 $ID_CTRL $IDS3"

# нативный интерфейс этапа 2: awg-quick берёт имя интерфейса из имени файла
AWG_IF="awgtest"
AWG_TMP="$SCRATCH/${AWG_IF}.conf"
AWG_FILES="megafon-ok-1180.conf megafon-ok-903.conf megafon-ok-500-jc120.conf"

# --- ЛОГИРОВАНИЕ ------------------------------------------------------------
# loglevel=debug нужен: строки WireGuard 'Sending handshake initiation' /
# 'Received handshake response' / 'Handshake did not complete' xray пишет ТОЛЬКО на debug
# (device-логгер wireguard-go завёрнут в LogDebug). Без них нельзя отличить
# «UDP до endpoint режется» от «рвётся уже установленная сессия».
# НО debug-лог пишет домены и коннекты пользователя, а репозиторий публичный, поэтому
# СЫРОЙ лог остаётся только в "$SCRATCH", а в рабочую папку идёт ./results/retest-<id>.log,
# отфильтрованный по белому списку: старт ядра + события wireguard/handshake/keepalive.
LOGLEVEL="debug"
FILTER_RE='^#|^Xray [0-9]|^A unified platform|\] core: |\] app/log: |\] infra/conf/serial: |\] transport/internet/(tcp|udp): listening|\] proxy/wireguard: |\] (peer\(|Routine:|UAPI:|Device|Interface|Binding|Bind|Starting|Stopping|Sending|Receiving|Received|Handshake|Invalid|Failed|Retrying|Obtained|Zeroing|Resetting|Adding|Removing|Creating|Keepalive|Sending keepalive)'

# --- аргументы -------------------------------------------------------------
SKIP_AWG=0
for a in "$@"; do
  case "$a" in
    --log-info)  LOGLEVEL="info" ;;
    --log-debug) LOGLEVEL="debug" ;;
    --no-awg)    SKIP_AWG=1 ;;
    -h|--help)
      sed -n '2,30p' "$0"
      echo "Флаги: --no-awg (пропустить этап 2), --log-info (без debug-счётчиков хендшейков)"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $a (поддерживаются --no-awg, --log-debug, --log-info, --help)" >&2; exit 2 ;;
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
hms() { printf '%dм %02dс' $(( $1 / 60 )) $(( $1 % 60 )); }

# --- описания вариантов ----------------------------------------------------
label_of() {
  case "$1" in
    11) echo "1.1" ;; 12) echo "1.2" ;; 13) echo "1.3" ;; 14) echo "1.4" ;; 15) echo "1.5" ;;
    16) echo "1.6" ;;
    31) echo "3.1" ;; 32) echo "3.2" ;; 33) echo "3.3" ;;
    34) echo "3.4" ;; 35) echo "3.5" ;; 36) echo "3.6" ;;
    *)  echo "$1" ;;
  esac
}
desc_of() {
  case "$1" in
    11) echo "чистый WG, БЕЗ обфускации           | 162.159.192.1:500  | MTU 1280 | IFkdR" ;;
    12) echo "чистый WG, БЕЗ обфускации           | 8.6.112.7:946      | MTU 1280 | IFkdR" ;;
    13) echo "чистый WG, БЕЗ обфускации           | 8.34.146.7:1180    | MTU 1280 | IFkdR" ;;
    14) echo "чистый WG, БЕЗ обфускации           | 8.34.70.4:903      | MTU 1280 | IFkdR" ;;
    15) echo "чистый WG, БЕЗ обфускации           | 162.159.192.1:2408 | MTU 1280 | IFkdR" ;;
    16) echo "чистый WG, БЕЗ обфускации           | ${EP_CTRL:-<лучший из этапа 1>} | MTU 1280 | p1Fqp  [контроль по 2-му ключу]" ;;
    31) echo "QUIC I1 из ok-500 + 8xrand23-911    | 162.159.192.1:500  | MTU 1280 | IFkdR  [БАЗА = вариант 9]" ;;
    32) echo "QUIC I1 из ok-500 + 8xrand23-911    | 162.159.192.1:2408 | MTU 1280 | IFkdR" ;;
    33) echo "QUIC I1 из ok-1180 + 4xrand40-70    | 8.34.146.7:1180    | MTU 1420 | IFkdR" ;;
    34) echo "СВОЙ QUIC Initial + 8xrand23-911    | 162.159.192.1:500  | MTU 1280 | IFkdR" ;;
    35) echo "SIP I1+I2 (RFC3261) + 8xrand23-911  | 162.159.192.1:500  | MTU 1280 | IFkdR" ;;
    36) echo "QUIC I1 из ok-500 + 8xrand23-911    | 162.159.192.1:500  | MTU 1420 | IFkdR" ;;
    *)  echo "неизвестный вариант" ;;
  esac
}

# Чем вариант этапа 3 отличается от БАЗЫ (3.1: IFkdR + 162.159.192.1:500 + MTU 1280 +
# hex QUIC I1 из ok-500 + 8 x rand 23-911). Печатается прямо в шапке варианта, чтобы
# вывод читался без сверки с таблицами.
diff_of() {
  case "$1" in
    31) echo "НИЧЕГО — это и есть база (контроль воспроизводимости варианта 9 прошлого прогона)" ;;
    32) echo "ТОЛЬКО ПОРТ endpoint: 500 -> 2408 (тот же адрес 162.159.192.1, классический порт WARP)" ;;
    33) echo "ENDPOINT 8.34.146.7:1180, плюс MTU 1420 и I1/rand из ok-1180 — это точная реплика нативного megafon-ok-1180.conf (несколько параметров сразу, читать в паре с этапом 2)" ;;
    34) echo "ТОЛЬКО hex-ПАКЕТ: чужой I1 из образца -> СВОЙ сгенерированный QUIC Initial" ;;
    35) echo "ТОЛЬКО hex-ПАКЕТ: QUIC Initial -> два текстовых SIP-пакета (RFC 3261)" ;;
    36) echo "ТОЛЬКО MTU: 1280 -> 1420" ;;
    *)  echo "-" ;;
  esac
}

# --- результаты ------------------------------------------------------------
declare -A R_ST R_HTTP R_WARP R_TIME R_MS R_HS_S R_HS_R R_HS_I R_NOTE R_KEY
for v in $IDS_ALL; do
  R_ST[$v]="SKIP"; R_HTTP[$v]="-"; R_WARP[$v]="-"; R_TIME[$v]="-"
  R_MS[$v]="999999"; R_HS_S[$v]="-"; R_HS_R[$v]="-"; R_HS_I[$v]="-"
  R_NOTE[$v]=""; R_KEY[$v]="?"
done

declare -A A_ST A_WARP A_IP A_NOTE
for f in $AWG_FILES; do A_ST[$f]="SKIP"; A_WARP[$f]="-"; A_IP[$f]="-"; A_NOTE[$f]=""; done

EP_CTRL=""        # endpoint контрольной точки 1.6 — определяется по итогам этапа 1
EP_OVERRIDE=""    # переопределение endpoint для генератора (только для 1.6)
SUDO_OK=0
S2_ABORT=0
S2_REASON=""
STAB_OK=0; STAB_TOTAL=0; WIN=""

# --- гашение xray ----------------------------------------------------------
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

# --- гашение нативного awg-интерфейса --------------------------------------
AWG_UP=0
awg_iface_present() { ip link show "$AWG_IF" >/dev/null 2>&1; }

# Безусловное гашение. Вызывается и из trap (в т.ч. по Ctrl+C и по ошибке curl).
# Сначала штатный awg-quick down по файлу, потом по имени интерфейса, потом
# грубое удаление линка — чтобы пользователь ни при каком раскладе не остался без сети.
awg_force_down() {
  if [ "$AWG_UP" != "1" ] && ! awg_iface_present; then
    AWG_UP=0
    return 0
  fi
  echo "[$(ts)] гашу нативный интерфейс $AWG_IF ..."
  if [ -r "$AWG_TMP" ]; then
    sudo awg-quick down "$AWG_TMP" >/dev/null 2>&1
  fi
  if awg_iface_present; then
    sudo awg-quick down "$AWG_IF" >/dev/null 2>&1
  fi
  if awg_iface_present; then
    sudo ip link del "$AWG_IF" >/dev/null 2>&1
    sudo resolvconf -d "$AWG_IF" >/dev/null 2>&1
  fi
  AWG_UP=0
  awg_iface_present && return 1 || return 0
}

on_exit() {
  local rc=$?
  stop_current
  awg_force_down
  exit $rc
}
trap on_exit EXIT
trap 'echo; echo "Прервано пользователем — гашу xray и нативный интерфейс."; exit 130' INT TERM

# ===========================================================================
# 0. Шапка и предполётные проверки
# ===========================================================================
T_START=$SECONDS
sect "ПЕРЕПРОВЕРКА НА МОБИЛЬНОЙ СЕТИ (МЕГАФОН): КРЕДЫ / НАТИВНЫЙ AWG / ИЗОЛЯЦИЯ ПЕРЕМЕННЫХ"
bare "Дата/время   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
bare "Хост         : $(uname -srm) | $(hostname 2>/dev/null || echo '?')"
bare "xray         : $(xray version 2>/dev/null | head -1 || echo 'НЕ НАЙДЕН')"
bare "awg          : $(awg --version 2>/dev/null | head -1 || echo 'НЕ НАЙДЕН')"
bare "awg-quick    : $(command -v awg-quick 2>/dev/null || echo 'НЕ НАЙДЕН')"
bare "curl         : $(curl --version 2>/dev/null | head -1 || echo 'НЕ НАЙДЕН')"
bare "python3      : $(python3 --version 2>/dev/null || echo 'НЕ НАЙДЕН')"
bare "resolvconf   : $(command -v resolvconf 2>/dev/null || echo 'НЕТ — awg-quick может споткнуться на строке DNS=')"
bare "Источники    : $CFG_NEW (креды p1Fqp + SIP-пакеты + rand 40-70)"
bare "               $CFG_OLD (профиль 8 x rand 23-911)"
bare "               $AWGDIR/*.conf (QUIC I1, endpoint'ы, вторые креды IFkdR)"
bare "Отчёт        : $REPORT"
bare "Логи xray    : ./results/retest-<id>.log (отфильтрованы), СЫРЫЕ — только в $SCRATCH"
bare "Порт прокси  : $PORT (варианты идут последовательно, по одному инстансу)"
bare "loglevel     : $LOGLEVEL"
if [ "$LOGLEVEL" = "debug" ]; then
  bare "               Сырой debug-лог остаётся в $SCRATCH (вне репозитория), в рабочую"
  bare "               папку идёт лог, отфильтрованный по белому списку (старт ядра +"
  bare "               wireguard/handshake/keepalive), без доменов и коннектов пользователя."
else
  bare "               ВНИМАНИЕ: счётчики хендшейков будут НУЛЕВЫЕ — эти строки xray пишет"
  bare "               только на debug. Отличить «режется UDP» от «душится сессия» нельзя."
fi

for f in "$CFG_NEW" "$CFG_OLD"; do
  [ -r "$f" ] || { log "ФАТАЛЬНО: нет файла $f. Выход."; exit 2; }
done
for f in $AWG_FILES megafon-fail-946-sip.conf; do
  [ -r "$AWGDIR/$f" ] || { log "ФАТАЛЬНО: нет файла $AWGDIR/$f — из него берутся I1/endpoint/креды. Выход."; exit 2; }
done
command -v xray    >/dev/null || { log "ФАТАЛЬНО: xray не найден в PATH."; exit 2; }
command -v python3 >/dev/null || { log "ФАТАЛЬНО: python3 не найден в PATH."; exit 2; }

# ---------------------------------------------------------------------------
sect "0. СОСТОЯНИЕ СЕТИ (какая сеть сейчас активна)"

bare "ip -brief addr (только поднятые интерфейсы):"
ip -brief addr 2>/dev/null | grep -v 'DOWN' | pipe_out
bare ""
bare "ip route:"
ip route 2>/dev/null | pipe_out
bare ""
bare "ip rule:"
ip rule 2>/dev/null | pipe_out
bare ""

DEF_LINE="$(ip route show default 2>/dev/null | head -1)"
DEF_ALL="$(ip route show default 2>/dev/null)"
DEF_IF="$(printf '%s\n' "$DEF_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
DEF_GW="$(printf '%s\n' "$DEF_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)"
DEF_IF="${DEF_IF:-?}"; DEF_GW="${DEF_GW:-?}"
ROUTE_GET_BEFORE="$(ip route get 1.1.1.1 2>/dev/null | head -1)"
bare "Дефолтный маршрут : ${DEF_LINE:-НЕТ ДЕФОЛТНОГО МАРШРУТА}"
bare "  интерфейс : $DEF_IF"
bare "  шлюз      : $DEF_GW"
bare "  ip route get 1.1.1.1 : ${ROUTE_GET_BEFORE:-?}"

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
    bare "  -> !!! ВНИМАНИЕ !!! ПОХОЖЕ НА ${NET_KIND}, А НЕ НА МОБИЛЬНУЮ СЕТЬ."
    bare "  -> !!! ЭТОТ ПРОГОН НА ГЛАВНЫЙ ВОПРОС (ЧТО РЕЖЕТ МЕГАФОН) НЕ ОТВЕЧАЕТ."
    bare "  -> !!! Переключись на Мегафон и перезапусти. Выполнение НЕ прерываю." ;;
  *) bare "  -> !!! Тип сети определить не удалось, смотри 'ip route' выше вручную." ;;
esac

bare ""
if ip -brief link show 2>/dev/null | grep -q '^throne-tun'; then
  bare "!!! ВНИМАНИЕ: есть интерфейс throne-tun — VPN пользователя, похоже, ВКЛЮЧЁН."
  bare "    Результаты будут недостоверны: трафик может уходить через чужой туннель."
  bare "    Лучше выключить VPN и перезапустить. Выполнение НЕ прерываю."
else
  bare "OK: интерфейса throne-tun нет (VPN пользователя выключен)."
fi
OTHER_TUN="$(ip -brief link show type tun 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
[ -n "${OTHER_TUN// /}" ] && bare "Прочие tun-интерфейсы: $OTHER_TUN"
if awg_iface_present; then
  bare "!!! ВНИМАНИЕ: интерфейс $AWG_IF уже существует до старта — остался от прошлого прогона."
  bare "    Гашу его сейчас, иначе этап 2 будет мерить непонятно что."
  awg_force_down && bare "    погашен." || bare "    ПОГАСИТЬ НЕ УДАЛОСЬ — разберись вручную: sudo ip link del $AWG_IF"
fi

bare ""
if port_busy; then
  bare "!!! ВНИМАНИЕ: порт $PORT ЗАНЯТ ещё до старта теста:"
  ss -ltnp 2>/dev/null | grep ":${PORT}[[:space:]]" | pipe_out
  bare "    Погаси то, что его держит, иначе все варианты будут мерить чужой прокси."
else
  bare "OK: порт $PORT свободен."
fi

# ---------------------------------------------------------------------------
sect "0b. ДОСТУП SUDO (нужен ТОЛЬКО для этапа 2 — нативный AmneziaWG)"
bare "Запрашиваю sudo один раз, чтобы дальше ничего не прерывалось на пароле."
if [ "$SKIP_AWG" = "1" ]; then
  SUDO_OK=0
  bare "Передан флаг --no-awg: этап 2 пропускается по явной просьбе, sudo не запрашиваю."
elif sudo -v 2>/dev/null; then
  SUDO_OK=1
  bare "SUDO: ПОЛУЧЕН. Этап 2 (нативный awg-quick) будет выполнен."
else
  SUDO_OK=0
  bare "SUDO: НЕ ПОЛУЧЕН (нет прав / отказ / пароль не введён)."
  bare "  -> ЭТАП 2 ЦЕЛИКОМ ПРОПУСКАЕТСЯ. Этапы 1 и 3 выполняются как обычно —"
  bare "     они sudo не требуют и маршруты не трогают."
  bare "  -> Без этапа 2 не будет ответа на вопрос «работают ли исходные AWG-конфиги"
  bare "     нативно прямо сейчас». Это надо будет проверить отдельно."
fi

# ===========================================================================
# Генератор конфигов (python3). Ничего не хардкодит.
# ===========================================================================
mkdir -p "$STATEDIR"
cat > "$GEN" <<'PYEOF'
#!/usr/bin/env python3
"""Генерация конфигов перепроверочной матрицы.
Креды p1Fqp и SIP-пакеты берутся из legacy/warp-xray-sip-profile.json, профиль 8 x rand 23-911 —
из old-warp-xray.json, QUIC-пакеты I1, endpoint'ы и вторые креды (IFkdR) —
из awg-samples/*.conf. В тексте скрипта не хардкодится ничего.

usage: rtm-gen.py <mode> <out.json> <warp.json> <old.json> <awgdir> <statedir> <loglevel>
modes: 11..14 (этап 1), 31..36 (этап 3), credinfo, quicinfo
"""
import binascii, hashlib, json, os, random, re, sys

PORT = 10808
ALT_PORT = 2408          # классический дефолтный порт WARP (проверяется на этапе 1 и в 3.2)
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
    """Генерируется один раз на запуск скрипта и переиспользуется вариантом 3.4."""
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

    sk_500 = smp[OK500].get("PrivateKey")
    addr_500 = awg_addr(smp[OK500].get("Address"))
    ep = {n: smp[n].get("Endpoint") for n in SAMPLES}
    i1 = {n: awg_hex(smp[n].get("I1")) for n in SAMPLES}

    # --- режим: сводка по кредам -------------------------------------------
    if mode == "credinfo":
        print("Ключ, на котором идёт ВЕСЬ тест — IFkdR (единственный, давший OK на Мегафоне).")
        print("Второй ключ p1Fqp используется РОВНО ОДИН РАЗ, в контрольной точке 1.6.")
        print("Перебор кредов не делается: все три регистрации проверены вручную до запуска")
        print("и передают данные (p1Fqp, IFkdR, WE7c0 — все дали warp=on на чистом WG).")
        print("")
        print("Креды, участвующие в тесте (первые 5 символов + sha256[:8]):")
        print("  p1Fqp из %-24s: %s… / %s | peer %s… | %s"
              % ("legacy/warp-xray-sip-profile.json", sk_new[:5], hashlib.sha256(sk_new.encode()).hexdigest()[:8],
                 pub[:12], ", ".join(a.split("/")[0] for a in addr_new)))
        print("  IFkdR из %-24s: %s… / %s | peer %s… | %s"
              % (OK500, (sk_500 or "")[:5], hashlib.sha256((sk_500 or "").encode()).hexdigest()[:8],
                 (smp[OK500].get("PublicKey") or "")[:12],
                 ", ".join(a.split("/")[0] for a in addr_500)))
        print("  publicKey пира одинаковый у обоих: %s"
              % ("ДА" if smp[OK500].get("PublicKey") == pub else "НЕТ — разные пиры!"))
        print("")
        print("Endpoint'ы, читаемые из образцов:")
        for n in SAMPLES:
            print("  %-26s -> %s" % (n, ep[n]))
        print("  %-26s -> %s:%d" % ("(тот же адрес, другой порт)",
                                    ep[OK500].rsplit(":", 1)[0], ALT_PORT))
        print("")
        print("КРИТЕРИЙ УСПЕХА варианта — получен ли warp=on (реальная передача данных),"
              " а НЕ «ответил ли пир на хендшейк»: ответ на хендшейк приходит и там, где"
              " сессию потом душат, поэтому сам по себе он ничего не доказывает.")
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
        print("В прошлый раз свой пакет тестировался ТОЛЬКО на ключе p1Fqp и endpoint'ах,"
              " которые проваливали вообще всё, поэтому вывод «свой QUIC не работает» был"
              " некорректен. Здесь он проверяется в условиях, где хоть что-то работает.")
        return

    # --- сборка вариантов --------------------------------------------------
    ntag = wg_of(new).get("streamSettings", {}).get("sockopt", {}).get("dialerProxy", "noise-out")
    nn = noises_of(new, ntag)
    sip_hex = [n for n in nn if n.get("type") == "hex"]     # 2 статичных SIP-пакета (RFC 3261)
    rand4 = [n for n in nn if n.get("type") == "rand"]      # 4 x rand 40-70
    otag = wg_of(old).get("streamSettings", {}).get("sockopt", {}).get("dialerProxy", "MMMnoise")
    rand8 = [n for n in noises_of(old, otag) if n.get("type") == "rand"]   # 8 x rand 23-911

    for n in (OK1180, OK500):
        if not ep[n] or not i1[n]:
            raise SystemExit("не удалось прочитать Endpoint/I1 из %s" % n)
    for n in (OK903, FAIL946):
        if not ep[n]:
            raise SystemExit("не удалось прочитать Endpoint из %s" % n)
    if not sk_500 or not addr_500:
        raise SystemExit("не удалось прочитать PrivateKey/Address из %s" % OK500)
    if not rand4:
        raise SystemExit("в %s не нашлось rand-пакетов 40-70" % wpath)
    if not sip_hex:
        raise SystemExit("в %s не нашлось hex(SIP)-пакетов" % wpath)
    if not rand8:
        raise SystemExit("в %s не нашлось rand-пакетов 23-911" % opath)

    q1180 = [hexpkt(i1[OK1180])]
    q500 = [hexpkt(i1[OK500])]
    qown = [hexpkt(load_quic(statedir))]

    # 162.159.192.1:2408 — классический дефолтный порт WARP. Адрес НЕ хардкодится:
    # берётся хост из Endpoint рабочего образца ok-500, меняется только порт.
    ep_alt = "%s:%d" % (ep[OK500].rsplit(":", 1)[0], ALT_PORT)

    # id: (endpoint, mtu, noises, secretKey, address)
    # ЭТАП 1 — ТЕСТ ДОСТУПНОСТИ ENDPOINT'ОВ. Один ключ IFkdR, MTU 1280, БЕЗ обфускации
    # (noises пустые -> build() не добавляет ни noise-аутбаунд, ни dialerProxy).
    # Фактор «ключ» из матрицы исключён заранее: все три регистрации проверены вручную
    # и передают данные, поэтому здесь перебираются ТОЛЬКО адреса и порты.
    # 16 — единственная контрольная точка на втором ключе (p1Fqp), endpoint приходит
    # снаружи параметром: скрипт подставляет тот, который сработал на этапе 1.
    table = {
        11: (ep[OK500],   1280, [],              sk_500, addr_500),
        12: (ep[FAIL946], 1280, [],              sk_500, addr_500),
        13: (ep[OK1180],  1280, [],              sk_500, addr_500),
        14: (ep[OK903],   1280, [],              sk_500, addr_500),
        15: (ep_alt,      1280, [],              sk_500, addr_500),
        16: (ep[OK500],   1280, [],              sk_new, addr_new),
        # ЭТАП 3 — изоляция переменных. БАЗА = 31 (ровно вариант 9 прошлого прогона):
        # IFkdR + 162.159.192.1:500 + MTU 1280 + hex QUIC I1 из ok-500 + 8 x rand 23-911.
        # Каждый следующий меняет относительно неё ОДИН параметр. Ключ везде IFkdR.
        31: (ep[OK500],   1280, q500 + rand8,    sk_500, addr_500),
        32: (ep_alt,      1280, q500 + rand8,    sk_500, addr_500),
        33: (ep[OK1180],  1420, q1180 + rand4,   sk_500, addr_500),
        34: (ep[OK500],   1280, qown + rand8,    sk_500, addr_500),
        35: (ep[OK500],   1280, sip_hex + rand8, sk_500, addr_500),
        36: (ep[OK500],   1420, q500 + rand8,    sk_500, addr_500),
    }
    v = int(mode)
    if v not in table:
        raise SystemExit("нет такого варианта: %d" % v)
    endpoint, mtu, noises, sk, addr = table[v]
    # необязательный 9-й аргумент — переопределение endpoint (нужно только варианту 16,
    # где адрес известен лишь в рантайме, по итогам этапа 1)
    if len(sys.argv) > 8 and sys.argv[8]:
        endpoint = sys.argv[8]
    cfg = build(sk, addr, pub, endpoint, mtu, noises, loglevel)
    with open(out, "w") as f:
        json.dump(cfg, f, indent=2)

    # сводка в stderr: KEY= для таблицы, дальше человекочитаемые факты
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

sect "0c. КРЕДЫ И ENDPOINT'Ы, ПРОЧИТАННЫЕ ИЗ ФАЙЛОВ"
python3 "$GEN" credinfo /dev/null "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" 2>&1 | pipe_out

sect "0d. СВОЙ QUIC INITIAL (для варианта 3.4, генерируется заново каждый запуск)"
python3 "$GEN" quicinfo /dev/null "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" 2>&1 | pipe_out

# ===========================================================================
# Общий прогон одного Xray-варианта
# ===========================================================================
run_variant() {
  local v="$1"
  local lbl; lbl="$(label_of "$v")"
  local cfg="$SCRATCH/rtm-${v}.json"
  local raw="$SCRATCH/rtm-${v}.rawlog"
  local pub="./results/retest-${lbl}.log"
  local gout facts

  bare ""
  bare "------------------------------------------------------------"
  log "ВАРИАНТ $lbl: $(desc_of "$v")"
  case " $IDS3 " in
    *" $v "*) bare "  ОТЛИЧИЕ ОТ БАЗЫ (3.1): $(diff_of "$v")" ;;
  esac

  rm -f "$cfg" "$raw"
  if ! gout="$(python3 "$GEN" "$v" "$cfg" "$CFG_NEW" "$CFG_OLD" "$AWGDIR" "$STATEDIR" "$LOGLEVEL" "${EP_OVERRIDE:-}" 2>&1 >/dev/null)"; then
    bare "  ОШИБКА генерации конфига: $gout"
    R_ST[$v]="GENERR"; R_NOTE[$v]="конфиг не сгенерился"
    return 0
  fi
  R_KEY[$v]="$(printf '%s\n' "$gout" | sed -n 's/^KEY=//p' | head -1)"
  [ -z "${R_KEY[$v]}" ] && R_KEY[$v]="?"
  facts="$(printf '%s\n' "$gout" | grep -v '^KEY=' | head -1)"
  bare "  Конфиг : $cfg"
  bare "  Факты  : $facts"

  if ! xray run -test -c "$cfg" >"$SCRATCH/rtm-${v}.test" 2>&1; then
    bare "  xray run -test: НЕВАЛИДЕН, пропускаю вариант:"
    tail -3 "$SCRATCH/rtm-${v}.test" | pipe_out
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
  wait_port_free || bare "  ВНИМАНИЕ: порт $PORT не освободился после варианта $lbl"

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
    bare "    -> хендшейк ПРОШЁЛ, но данные не идут: душится уже установленная сессия"
  fi

  {
    echo "# NOTE: log filtered for publication — only Xray startup and WireGuard transport/handshake events are kept."
    echo "# Variant $lbl: $(desc_of "$v")"
    grep -E "$FILTER_RE" "$raw" 2>/dev/null
  } > "$pub"
  bare "  Публикуемый лог: $pub ($(wc -l <"$pub" 2>/dev/null || echo 0) строк)"
  log "ВАРИАНТ $lbl ИТОГ: ${R_ST[$v]}${R_NOTE[$v]:+ — ${R_NOTE[$v]}}"
  return 0
}

# ===========================================================================
# ЭТАП 1 — доступность endpoint'ов на голом WireGuard
# ===========================================================================
T1_START=$SECONDS
sect "ЭТАП 1. ДОСТУПНОСТЬ ENDPOINT'ОВ НА ГОЛОМ WG (БЕЗ ОБФУСКАЦИИ) — 5 адресов/портов"
bare "Фактор «ключ» из матрицы ИСКЛЮЧЁН заранее: все три регистрации WARP проверены"
bare "вручную на чистом WG и передают данные (p1Fqp, IFkdR, WE7c0 — все дали warp=on)."
bare "Поэтому здесь один и тот же ключ IFkdR и один и тот же MTU 1280, а меняется"
bare "ТОЛЬКО адрес и порт endpoint'а. Конфиги без noises и без dialerProxy — обфускация"
bare "полностью выведена из уравнения."
bare ""
bare "Вопрос этапа: какие endpoint'ы вообще проходят с Мегафона на голом WireGuard."
bare "Если пройдёт только 162.159.192.1 — гипотеза «подсети 8.34.x и 8.6.x режутся"
bare "целиком» подтверждена, и дальше всё решает выбор endpoint, а не профиль пакета."
for v in $IDS1; do
  run_variant "$v"
done

# --- контрольная точка по второму ключу ------------------------------------
bare ""
bare "------------------------------------------------------------"
bare "КОНТРОЛЬНАЯ ТОЧКА ПО ВТОРОМУ КЛЮЧУ (p1Fqp)"
EP_BEST=""
BEST1=""
for v in $IDS1; do
  if [ "${R_ST[$v]}" = "OK" ]; then
    if [ -z "$BEST1" ] || [ "${R_MS[$v]}" -lt "${R_MS[$BEST1]}" ] 2>/dev/null; then BEST1="$v"; fi
  fi
done
if [ -z "$BEST1" ]; then
  bare "Ни один endpoint на этапе 1 не дал OK — подставлять в контрольную точку нечего,"
  bare "она пропускается. Это само по себе сильный результат: на голом WG с этой сети не"
  bare "проходит НИ ОДИН из пяти endpoint'ов."
  R_ST[16]="SKIP"; R_NOTE[16]="на этапе 1 не было ни одного рабочего endpoint'а"
else
  EP_BEST="$(sed -n 's/.*"endpoint": *"\([^"]*\)".*/\1/p' "$SCRATCH/rtm-${BEST1}.json" | head -1)"
  if [ -z "$EP_BEST" ]; then
    bare "Не удалось вытащить endpoint из конфига варианта $(label_of "$BEST1") — пропускаю."
    R_ST[16]="SKIP"; R_NOTE[16]="не прочитался endpoint рабочего варианта"
  else
    EP_CTRL="$EP_BEST"
    bare "Лучший endpoint этапа 1 — $EP_BEST (вариант $(label_of "$BEST1"), ${R_TIME[$BEST1]}s)."
    bare "Гоняю его же с ключом p1Fqp, чтобы подтвердить: при рабочем endpoint оба ключа"
    bare "ведут себя одинаково. Больше p1Fqp нигде не используется."
    EP_OVERRIDE="$EP_BEST"
    run_variant "$ID_CTRL"
    EP_OVERRIDE=""
  fi
fi
T1_DUR=$(( SECONDS - T1_START ))

# ===========================================================================
# ЭТАП 2 — нативный AmneziaWG
# ===========================================================================
T2_START=$SECONDS
sect "ЭТАП 2. НАТИВНЫЙ AmneziaWG (awg-quick) НА ИСХОДНЫХ .conf — БАЗОВАЯ ИСТИНА"

# Проверка связи напрямую (без прокси, без туннеля). 0 = связь есть.
direct_ok() {
  local maxt="${1:-$AWG_BACK_MAXTIME}" body
  body="$(curl -s --max-time "$maxt" "$TRACE_URL" 2>/dev/null)"
  printf '%s\n' "$body" | grep -q '^fl=' && return 0
  printf '%s\n' "$body" | grep -q '^warp=' && return 0
  return 1
}

emergency_note() {
  bare ""
  bare "!!! АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ СЕТИ — ВЫПОЛНИ ВРУЧНУЮ:"
  bare "      sudo awg-quick down $AWG_TMP"
  bare "      sudo awg-quick down $AWG_IF"
  bare "      sudo ip link del $AWG_IF"
  bare "      sudo resolvconf -d $AWG_IF"
  bare "    Если дефолтный маршрут не вернулся:"
  bare "      sudo ip route add default via $DEF_GW dev $DEF_IF"
  bare "    Маршрут, который был ДО теста:"
  printf '%s\n' "${DEF_ALL:-(не удалось прочитать)}" | pipe_out
  bare "    Проверка: curl -s --max-time 10 $TRACE_URL"
  bare ""
}

awg_run_one() {
  local src="$1"
  local path="$AWGDIR/$src"
  local upout downout ep mtu body wv ipv

  bare ""
  bare "------------------------------------------------------------"
  ep="$(grep -E '^\s*Endpoint\s*=' "$path" | head -1 | sed 's/.*=\s*//')"
  mtu="$(grep -E '^\s*MTU\s*=' "$path" | head -1 | sed 's/.*=\s*//')"
  log "AWG-КОНФИГ $src (Endpoint $ep, MTU ${mtu:-по умолчанию})"

  bare "  Дефолтный маршрут ДО подъёма:"
  ip route show default 2>/dev/null | pipe_out
  bare "  ip route get 1.1.1.1 ДО: $(ip route get 1.1.1.1 2>/dev/null | head -1)"

  rm -f "$AWG_TMP"
  if ! cp "$path" "$AWG_TMP"; then
    bare "  ОШИБКА: не скопировать $path -> $AWG_TMP, пропускаю."
    A_ST[$src]="COPYERR"; A_NOTE[$src]="не удалось скопировать конфиг"
    return 0
  fi
  chmod 600 "$AWG_TMP"

  bare "  Поднимаю: sudo awg-quick up $AWG_TMP"
  if ! upout="$(sudo awg-quick up "$AWG_TMP" 2>&1)"; then
    bare "  awg-quick up НЕ СРАБОТАЛ:"
    printf '%s\n' "$upout" | tail -10 | pipe_out
    A_ST[$src]="UPERR"; A_NOTE[$src]="awg-quick up завершился с ошибкой"
    awg_force_down
    if ! direct_ok; then
      bare "  !!! СВЯЗЬ НЕ ВОССТАНОВИЛАСЬ после неудачного подъёма."
      emergency_note
      S2_ABORT=1; S2_REASON="связь не вернулась после неудачного awg-quick up на $src"
    fi
    return 0
  fi
  AWG_UP=1
  printf '%s\n' "$upout" | tail -8 | pipe_out

  if ! awg_iface_present; then
    bare "  ВНИМАНИЕ: awg-quick up отработал, но интерфейса $AWG_IF нет."
    A_ST[$src]="NOIFACE"; A_NOTE[$src]="интерфейс не появился"
  else
    bare "  Интерфейс $AWG_IF поднят. Жду ${AWG_WAIT}с и делаю ПРЯМОЙ запрос (без прокси)."
    bare "  ip route get 1.1.1.1 ПОСЛЕ подъёма: $(ip route get 1.1.1.1 2>/dev/null | head -1)"
    bare "  ip rule (первые строки):"
    ip rule 2>/dev/null | head -6 | pipe_out
    sleep "$AWG_WAIT"
    body="$(curl -s --max-time "$AWG_MAXTIME" "$TRACE_URL" 2>/dev/null)"
    wv="$(printf '%s\n' "$body" | grep -o 'warp=[a-z+]*' | head -1)"
    ipv="$(printf '%s\n' "$body" | grep -o '^ip=[^ ]*' | head -1)"
    A_WARP[$src]="${wv:-нет}"; A_IP[$src]="${ipv:-нет}"
    if [ -n "$body" ]; then
      printf '%s\n' "$body" | grep -E '^(warp|loc|ip|colo)=' | pipe_out
    else
      bare "    (пустой ответ — таймаут ${AWG_MAXTIME}с)"
    fi
    if [ "$wv" = "warp=on" ] || [ "$wv" = "warp=plus" ]; then
      A_ST[$src]="OK"; A_NOTE[$src]=""
    elif [ -n "$wv" ]; then
      A_ST[$src]="BAD"; A_NOTE[$src]="ответ есть, но $wv — трафик идёт НЕ через WARP"
    else
      A_ST[$src]="FAIL"; A_NOTE[$src]="нет ответа через поднятый туннель (таймаут ${AWG_MAXTIME}с)"
    fi
    bare "  Показания awg show (кратко):"
    sudo awg show "$AWG_IF" 2>/dev/null | grep -E 'handshake|transfer|endpoint' | pipe_out
  fi

  bare "  Опускаю: sudo awg-quick down $AWG_TMP"
  downout="$(sudo awg-quick down "$AWG_TMP" 2>&1)"
  printf '%s\n' "$downout" | tail -6 | pipe_out
  AWG_UP=0
  if awg_iface_present; then
    bare "  ВНИМАНИЕ: интерфейс $AWG_IF всё ещё есть после down — добиваю принудительно."
    awg_force_down
  fi
  if awg_iface_present; then
    bare "  !!! ИНТЕРФЕЙС $AWG_IF НЕ УДАЛОСЬ УДАЛИТЬ."
    emergency_note
    S2_ABORT=1; S2_REASON="интерфейс $AWG_IF не гасится"
    return 0
  fi
  bare "  Интерфейс $AWG_IF исчез — OK."

  bare "  Дефолтный маршрут ПОСЛЕ гашения:"
  ip route show default 2>/dev/null | pipe_out
  bare "  ip route get 1.1.1.1 ПОСЛЕ: $(ip route get 1.1.1.1 2>/dev/null | head -1)"
  local now_if
  now_if="$(ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
  if [ -z "$now_if" ]; then
    bare "  !!! ДЕФОЛТНОГО МАРШРУТА НЕТ."
  elif [ "$now_if" != "$DEF_IF" ]; then
    bare "  !!! Дефолтный маршрут вернулся, но через ДРУГОЙ интерфейс: $now_if (до теста был $DEF_IF)"
  else
    bare "  Дефолтный маршрут снова через $now_if — как до теста."
  fi

  if direct_ok; then
    bare "  Связь восстановлена (прямой запрос к $TRACE_URL прошёл)."
  else
    bare "  !!! СВЯЗЬ НЕ ВЕРНУЛАСЬ после гашения $src. Дальше этап 2 НЕ ПРОДОЛЖАЮ."
    emergency_note
    S2_ABORT=1; S2_REASON="связь не вернулась после гашения $src"
  fi
  return 0
}

if [ "$SUDO_OK" != "1" ]; then
  bare "ЭТАП 2 ПРОПУЩЕН: sudo недоступен${SKIP_AWG:+ / передан --no-awg}."
  bare "  Поэтому на вопрос «работают ли исходные AWG-конфиги нативно на Мегафоне прямо"
  bare "  сейчас» этот прогон НЕ ОТВЕЧАЕТ. Проверь вручную, по одному:"
  for f in $AWG_FILES; do
    bare "      sudo awg-quick up   $AWGDIR/$f   # имя интерфейса = имя файла"
    bare "      curl -s --max-time 15 $TRACE_URL | grep -E '^(warp|ip)='"
    bare "      sudo awg-quick down $AWGDIR/$f"
  done
  for f in $AWG_FILES; do A_ST[$f]="NOSUDO"; A_NOTE[$f]="этап пропущен: нет sudo"; done
elif ! command -v awg-quick >/dev/null; then
  bare "ЭТАП 2 ПРОПУЩЕН: awg-quick не найден в PATH (пакет amneziawg-tools не установлен)."
  for f in $AWG_FILES; do A_ST[$f]="NOAWG"; A_NOTE[$f]="awg-quick не найден"; done
else
  bare "Каждый конфиг копируется в $AWG_TMP (awg-quick берёт имя интерфейса из имени файла,"
  bare "поэтому интерфейс всегда называется $AWG_IF), поднимается, проверяется ПРЯМЫМ"
  bare "запросом без прокси, затем ОБЯЗАТЕЛЬНО опускается с проверкой возврата связи."
  bare "trap на EXIT/INT/TERM гасит интерфейс даже при Ctrl+C или падении скрипта."
  bare ""
  bare "Маршрут ДО этапа 2 (эталон для восстановления):"
  printf '%s\n' "${DEF_ALL:-(нет)}" | pipe_out
  sudo -v 2>/dev/null || bare "ВНИМАНИЕ: не удалось обновить кэш sudo, возможен запрос пароля ниже."
  for f in $AWG_FILES; do
    if [ "$S2_ABORT" = "1" ]; then
      bare ""
      bare "ЭТАП 2 ПРЕРВАН ($S2_REASON) — $f и остальные конфиги НЕ проверялись."
      A_ST[$f]="ABORT"; A_NOTE[$f]="этап прерван по проблеме со связью"
      continue
    fi
    awg_run_one "$f"
  done
  rm -f "$AWG_TMP"
fi
T2_DUR=$(( SECONDS - T2_START ))

# ===========================================================================
# ЭТАП 3 — Xray-матрица с изоляцией переменных
# ===========================================================================
T3_START=$SECONDS
sect "ЭТАП 3. XRAY-МАТРИЦА С ИЗОЛЯЦИЕЙ ПЕРЕМЕННЫХ (endpoint / MTU / профиль пакета)"
bare "БАЗА (вариант 3.1) = ровно вариант 9 прошлого прогона, единственный давший OK:"
bare "  ключ IFkdR + endpoint 162.159.192.1:500 + MTU 1280 + hex QUIC I1 из ok-500 +"
bare "  8 x rand \"23-911\"."
bare "Ключ во ВСЕХ вариантах этапа один и тот же (IFkdR) — фактор кредов исключён заранее."
bare "Каждый вариант меняет относительно базы ровно один параметр:"
bare "  3.1 — ничего (контроль воспроизводимости)"
bare "  3.2 — только ПОРТ endpoint'а: 500 -> 2408"
bare "  3.3 — ENDPOINT 8.34.146.7:1180 (вместе с MTU 1420 и I1/rand из того же образца —"
bare "        это точная реплика нативного megafon-ok-1180.conf, читать в паре с этапом 2)"
bare "  3.4 — только hex-пакет: чужой I1 -> СВОЙ сгенерированный QUIC Initial"
bare "  3.5 — только hex-пакет: QUIC -> SIP из RFC 3261"
bare "  3.6 — только MTU: 1280 -> 1420"
for v in $IDS3; do
  run_variant "$v"
done

# --- фаза стабильности для успешного варианта этапа 3 ----------------------
bare ""
sect "ЭТАП 3b. СТАБИЛЬНОСТЬ УСПЕШНОГО ВАРИАНТА (${STAB_ATTEMPTS} запросов каждые ${STAB_INTERVAL}с ≈ 100 с)"
for v in $IDS3; do
  if [ "${R_ST[$v]}" = "OK" ]; then
    if [ -z "$WIN" ] || [ "${R_MS[$v]}" -lt "${R_MS[$WIN]}" ] 2>/dev/null; then WIN="$v"; fi
  fi
done

if [ -z "$WIN" ]; then
  bare "Ни один вариант этапа 3 не дал OK — фаза стабильности смысла не имеет, пропускаю."
else
  WIN_LBL="$(label_of "$WIN")"
  bare "Проверяю вариант $WIN_LBL (наименьшая задержка среди OK: ${R_TIME[$WIN]}s)"
  bare "  $(desc_of "$WIN")"
  cfg="$SCRATCH/rtm-${WIN}.json"
  raw="$SCRATCH/rtm-${WIN}-stab.rawlog"
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
      bare "  процесс умер на попытке $i — прерываю фазу стабильности"
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
  wait_port_free || bare "ВНИМАНИЕ: порт $PORT не освободился после фазы стабильности"
  {
    echo "# NOTE: log filtered for publication — only Xray startup and WireGuard transport/handshake events are kept."
    echo "# Stability phase, variant $WIN_LBL: $(desc_of "$WIN")"
    grep -E "$FILTER_RE" "$raw" 2>/dev/null
  } > "./results/retest-stability.log"
  bare ""
  bare "Стабильность: успешных $STAB_OK из $STAB_TOTAL"
  bare "Хендшейки за фазу стабильности: initiation=$S_S response=$S_R 'did not complete'=$S_I"
  bare "Публикуемый лог: ./results/retest-stability.log"
  if [ "$STAB_OK" = "$STAB_TOTAL" ] && [ "$STAB_TOTAL" -gt 0 ]; then
    bare "-> канал держится все ~100 с, отложенного среза не видно"
  elif [ "$STAB_OK" -gt 0 ]; then
    bare "-> канал ПЛАВАЕТ: часть запросов прошла, часть нет — похоже на срез не сразу"
  else
    bare "-> в фазе стабильности не прошло НИ ОДНОГО запроса, хотя в матрице был OK: срез с задержкой"
  fi
fi
T3_DUR=$(( SECONDS - T3_START ))
T_TOTAL=$(( SECONDS - T_START ))

# ===========================================================================
# ИТОГИ
# ===========================================================================
sect "ИТОГ 1. ТАБЛИЦА ЭТАПА 1 (доступность endpoint'ов, голый WG без обфускации)"
bare ""
bare "  id   статус    http  warp      сек    HS:отпр/отв/неуд  ключ    вариант"
bare "  ---  --------  ----  --------  -----  ----------------  ------  -----------------------------------"
for v in $IDS1 $ID_CTRL; do
  bare "$(printf '  %-3s  %-8s  %4s  %-8s  %-5s  %4s/%3s/%3s       %-6s  %s' \
      "$(label_of "$v")" "${R_ST[$v]}" "${R_HTTP[$v]}" "${R_WARP[$v]}" "${R_TIME[$v]}" \
      "${R_HS_S[$v]}" "${R_HS_R[$v]}" "${R_HS_I[$v]}" "${R_KEY[$v]}" "$(desc_of "$v")")"
done

sect "ИТОГ 2. ТАБЛИЦА ЭТАПА 2 (нативный AmneziaWG)"
bare ""
bare "  конфиг                      статус    warp      ip"
bare "  --------------------------  --------  --------  ---------------------"
for f in $AWG_FILES; do
  bare "$(printf '  %-26s  %-8s  %-8s  %s' "$f" "${A_ST[$f]}" "${A_WARP[$f]}" "${A_IP[$f]}")"
  [ -n "${A_NOTE[$f]}" ] && bare "      прим.: ${A_NOTE[$f]}"
done
[ "$S2_ABORT" = "1" ] && bare "  ЭТАП 2 БЫЛ ПРЕРВАН: $S2_REASON"

sect "ИТОГ 3. ТАБЛИЦА ЭТАПА 3 (Xray, изоляция переменных)"
bare ""
bare "  id   статус    http  warp      сек    HS:отпр/отв/неуд  ключ    вариант"
bare "  ---  --------  ----  --------  -----  ----------------  ------  -----------------------------------"
for v in $IDS3; do
  bare "$(printf '  %-3s  %-8s  %4s  %-8s  %-5s  %4s/%3s/%3s       %-6s  %s' \
      "$(label_of "$v")" "${R_ST[$v]}" "${R_HTTP[$v]}" "${R_WARP[$v]}" "${R_TIME[$v]}" \
      "${R_HS_S[$v]}" "${R_HS_R[$v]}" "${R_HS_I[$v]}" "${R_KEY[$v]}" "$(desc_of "$v")")"
done
bare ""
bare "Легенда: OK = http 200 и warp=on/plus | BAD = ответ есть, но не 200 / не через WARP"
bare "         FAIL = нет ответа (таймаут) | INVALID = конфиг не прошёл xray run -test"
bare "         NOSUDO/NOAWG/ABORT — этап 2 не выполнялся или был прерван"
for v in $IDS_ALL; do
  [ -n "${R_NOTE[$v]}" ] && bare "  прим. $(label_of "$v"): ${R_NOTE[$v]}"
done

# --- прямые ответы ---------------------------------------------------------
isok()   { [ "${R_ST[$1]}" = "OK" ]; }
isfail() { [ "${R_ST[$1]}" = "FAIL" ]; }
tested() { [ "${R_ST[$1]}" = "OK" ] || [ "${R_ST[$1]}" = "FAIL" ] || [ "${R_ST[$1]}" = "BAD" ]; }

sect "ИТОГ 4. ПРЯМЫЕ ОТВЕТЫ НА ПОСТАВЛЕННЫЕ ВОПРОСЫ"

bare ""
bare "(а) ЖИВЫ ЛИ КЛЮЧИ ПО КРИТЕРИЮ ПЕРЕДАЧИ ДАННЫХ?"
bare "    Этот вопрос ЗАКРЫТ ДО ЗАПУСКА СКРИПТА, вручную, на чистом WG без обфускации"
bare "    через 162.159.192.1:500: все три регистрации отдали warp=on —"
bare "      p1Fqp (legacy/warp-xray-sip-profile.json), IFkdR (awg-samples/megafon-ok-500-jc120.conf),"
bare "      WE7c0 (old-warp-xray.json)."
bare "    Поэтому фактор «ключ» из матрицы убран, и провал вариантов 1-8 прошлого прогона"
bare "    кредами НЕ объясняется."
if [ "${R_ST[$ID_CTRL]}" = "OK" ] && [ -n "$EP_CTRL" ]; then
  bare "    Контрольная точка 1.6 это подтверждает и на Мегафоне: на рабочем endpoint"
  bare "    $EP_CTRL ключ p1Fqp тоже дал warp=on — оба ключа ведут себя одинаково."
elif [ "${R_ST[$ID_CTRL]}" = "SKIP" ]; then
  bare "    Контрольная точка 1.6 не выполнялась: ${R_NOTE[$ID_CTRL]}."
elif [ -n "$EP_CTRL" ]; then
  bare "    !!! РАСХОЖДЕНИЕ: на endpoint $EP_CTRL ключ IFkdR дал OK, а p1Fqp — ${R_ST[$ID_CTRL]}."
  bare "    При одинаковых прочих условиях это значит, что на Мегафоне креды всё-таки"
  bare "    различаются по поведению, хотя на домашней сети обе регистрации живы."
  bare "    Это отдельный результат, его надо перепроверить повтором."
fi

bare ""
bare "(б) РАБОТАЮТ ЛИ ИСХОДНЫЕ AWG-КОНФИГИ НАТИВНО НА МЕГАФОНЕ ПРЯМО СЕЙЧАС?"
if [ "$SUDO_OK" != "1" ] || [ "${A_ST[megafon-ok-1180.conf]}" = "NOAWG" ]; then
  bare "    ДАННЫХ НЕТ: этап 2 не выполнялся (нет sudo или нет awg-quick)."
  bare "    Это ключевой пробел: без него нельзя сказать, виновата ли сеть или Xray-реплика."
else
  AWG_OK_N=0; AWG_FAIL_N=0
  for f in $AWG_FILES; do
    [ "${A_ST[$f]}" = "OK" ] && AWG_OK_N=$((AWG_OK_N+1))
    [ "${A_ST[$f]}" = "FAIL" ] && AWG_FAIL_N=$((AWG_FAIL_N+1))
  done
  bare "    Из $(set -- $AWG_FILES; echo $#) конфигов: OK = $AWG_OK_N, FAIL = $AWG_FAIL_N."
  if [ "${A_ST[megafon-ok-1180.conf]}" = "OK" ] || [ "${A_ST[megafon-ok-903.conf]}" = "OK" ]; then
    bare "    -> Конфиги на подсетях 8.34.x РАБОТАЮТ нативно. Значит гипотеза «Мегафон режет"
    bare "       подсети 8.34.x / 8.6.x целиком» НЕВЕРНА, и дело в РАЗНИЦЕ РЕАЛИЗАЦИЙ:"
    bare "       в AmneziaWG пакет I1 отправляется в привязке к хендшейку, а в Xray noises —"
    bare "       просто пачка датаграмм перед соединением. Тогда чинить надо перенос,"
    bare "       а не выбор endpoint."
  elif [ "$AWG_OK_N" = "0" ]; then
    bare "    -> НИ ОДИН исходный AWG-конфиг не работает нативно прямо сейчас. Значит от их"
    bare "       Xray-реплик ждать нечего, и провал вариантов 1-8 в прошлом прогоне объясняется"
    bare "       состоянием сети/endpoint'ов, а не качеством переноса обфускации."
  else
    bare "    -> Работает только часть конфигов, смотри таблицу ИТОГ 2 построчно."
  fi
  if [ "${A_ST[megafon-ok-1180.conf]}" = "OK" ] && [ "${R_ST[33]}" = "FAIL" ]; then
    bare "    -> ВАЖНАЯ ПАРА: нативный megafon-ok-1180.conf = OK, а его Xray-реплика 3.3 = FAIL."
    bare "       Один и тот же endpoint, MTU, I1 и креды — разница только в реализации"
    bare "       обфускации. Это прямо указывает на дефект переноса AWG -> Xray."
  fi
fi

bare ""
bare "(в) ЧТО РЕШАЕТ: ENDPOINT-ПОДСЕТЬ, КЛЮЧ, MTU ИЛИ ПРОФИЛЬ?"
VERDICT_ANY=0
bare "    КЛЮЧ: из рассмотрения исключён заранее (см. пункт «а»), в матрице не перебирался."
# --- endpoint по этапу 1 (голый WG) ---
EP_OK_LIST=""; EP_BAD_LIST=""
for v in $IDS1; do
  case "${R_ST[$v]}" in
    OK)   EP_OK_LIST="$EP_OK_LIST $(label_of "$v")" ;;
    FAIL) EP_BAD_LIST="$EP_BAD_LIST $(label_of "$v")" ;;
  esac
done
if [ -n "${EP_OK_LIST// /}" ] && [ -n "${EP_BAD_LIST// /}" ]; then
  bare "    ENDPOINT: РЕШАЕТ, и это видно уже на голом WG без всякой обфускации."
  bare "              Прошли:$EP_OK_LIST | не прошли:$EP_BAD_LIST (ключ и MTU везде одни)."
  if [ "${R_ST[11]}" = "OK" ] || [ "${R_ST[15]}" = "OK" ]; then
    if [ "${R_ST[12]}" != "OK" ] && [ "${R_ST[13]}" != "OK" ] && [ "${R_ST[14]}" != "OK" ]; then
      bare "              162.159.192.1 проходит, а ВСЕ адреса 8.34.x / 8.6.x — нет."
      bare "              ГИПОТЕЗА О БЛОКИРОВКЕ НОВЫХ ПОДСЕТЕЙ CLOUDFLARE ПОДТВЕРЖДЕНА."
      bare "              Обфускация к провалу вариантов 1-8 отношения не имеет."
    fi
  fi
  VERDICT_ANY=1
elif [ -n "${EP_OK_LIST// /}" ]; then
  bare "    ENDPOINT: не решает — на голом WG прошли ВСЕ проверенные endpoint'ы ($EP_OK_LIST)."
  bare "              Значит причину провала надо искать в слое обфускации, а не в адресах."
  VERDICT_ANY=1
elif [ -n "${EP_BAD_LIST// /}" ]; then
  bare "    ENDPOINT: на голом WG не прошёл НИ ОДИН из пяти ($EP_BAD_LIST)."
  bare "              Либо режется WireGuard как таковой, либо сеть/WARP сейчас не в порядке."
  bare "              Развести это по текущему прогону НЕЛЬЗЯ."
  VERDICT_ANY=1
fi
# --- порт 2408 vs 500 ---
if tested 11 && tested 15; then
  if isok 11 && ! isok 15; then
    bare "    ПОРТ: решает и он тоже — 162.159.192.1:500 = OK, тот же адрес на :2408 = ${R_ST[15]}."
    VERDICT_ANY=1
  elif isok 11 && isok 15; then
    bare "    ПОРТ: на 162.159.192.1 проходят оба порта (500 и 2408) — режется именно адрес/подсеть."
    VERDICT_ANY=1
  elif ! isok 11 && isok 15; then
    bare "    ПОРТ: проходит только :2408, а :500 = ${R_ST[11]} — неожиданно, стоит перепроверить."
    VERDICT_ANY=1
  fi
fi
if tested 31 && tested 32; then
  if isok 31 && isok 32; then
    bare "    ПОРТ (с обфускацией): 500 и 2408 оба дали OK — порт не критичен."
  elif isok 31 && ! isok 32; then
    bare "    ПОРТ (с обфускацией): 3.1 (:500) = OK, 3.2 (:2408) = ${R_ST[32]} — порт значим."
  fi
  VERDICT_ANY=1
fi
# --- MTU ---
if tested 31 && tested 36; then
  if isok 31 && ! isok 36; then
    bare "    MTU: РЕШАЕТ. 3.1 (MTU 1280) = OK, 3.6 (MTU 1420) = ${R_ST[36]} при всём прочем равном."
    bare "         Похоже на срез по размеру пакета или проблему фрагментации в мобильной сети."
  elif isok 31 && isok 36; then
    bare "    MTU: НЕ решает. 1280 и 1420 при прочем равном оба дали OK."
  elif ! isok 31 && isok 36; then
    bare "    MTU: 3.6 (1420) = OK, 3.1 (1280) = ${R_ST[31]} — инверсия, нужен повтор."
  fi
  VERDICT_ANY=1
fi
# --- профиль: обфускация вообще нужна? ---
if tested 11 && tested 31; then
  if isok 11 && isok 31; then
    bare "    ПРОФИЛЬ: на рабочем endpoint работает и БЕЗ обфускации (1.1=OK), и С ней (3.1=OK)."
    bare "             Значит обфускация ничего не чинит — она просто не мешает. Для Мегафона"
    bare "             решающим оказался выбор endpoint, а не пакет."
  elif ! isok 11 && isok 31; then
    bare "    ПРОФИЛЬ: РЕШАЕТ. На одном endpoint/ключе/MTU голый WG (1.1) = ${R_ST[11]},"
    bare "             а с QUIC-обфускацией (3.1) = OK. Обфускация действительно нужна."
  elif isok 11 && ! isok 31; then
    bare "    ПРОФИЛЬ: МЕШАЕТ. Голый WG (1.1) = OK, а с обфускацией (3.1) = ${R_ST[31]}."
    bare "             Это указывает на дефект самого слоя noises в Xray."
  fi
  VERDICT_ANY=1
fi
# --- SIP-сигнатура ---
if tested 31 && tested 35; then
  if isok 31 && ! isok 35; then
    bare "    SIP-СИГНАТУРА: СПАЛЕНА. В условиях, где QUIC-профиль работает (3.1=OK), тот же"
    bare "             конфиг с SIP-пакетами (3.5) = ${R_ST[35]}. Замена hex-пакета — единственное"
    bare "             отличие, так что дело именно в сигнатуре RFC 3261."
  elif isok 31 && isok 35; then
    bare "    SIP-СИГНАТУРА: НЕ спалена — 3.5 с SIP-пакетами тоже дал OK. Значит прошлый провал"
    bare "             SIP-конфигов объяснялся endpoint'ом, а не самой сигнатурой."
  fi
  VERDICT_ANY=1
fi
[ "$VERDICT_ANY" = "0" ] && bare "    ДАННЫХ НА ВЫВОД НЕ ХВАТАЕТ: слишком мало вариантов отработало (см. таблицы выше)."

bare ""
bare "(г) РАБОТАЕТ ЛИ СВОЙ СГЕНЕРИРОВАННЫЙ QUIC INITIAL?"
if isok 34 && isok 31; then
  bare "    ДА. 3.4 (свой пакет) = OK там же, где 3.1 (чужой I1 из образца) = OK."
  bare "    -> Можно уходить от копирования чужого I1: фиксированный DCID сам со временем"
  bare "       становится статичной сигнатурой, ровно как это случилось с SIP-пакетом."
elif ! isok 34 && isok 31; then
  bare "    НЕТ. 3.1 (чужой I1) = OK, а 3.4 (свой пакет) = ${R_ST[34]} при прочем равном."
  bare "    -> Значит важен не «похожий на QUIC» пакет вообще, а именно конкретный образец."
  bare "       Проверить длину, DCID и валидность length-varint (разбор в секции 0d)."
elif isok 34 && ! isok 31; then
  bare "    Свой пакет дал OK, а контрольный 3.1 — нет. Результат нестабилен, нужен повтор."
else
  bare "    ДАННЫХ НЕТ: ни 3.1, ни 3.4 не дали OK — сравнивать нечего."
fi

bare ""
bare "(д) КАКОЙ КОНФИГ РЕКОМЕНДУЕТСЯ ДЛЯ МЕГАФОНА?"
if [ -n "$WIN" ]; then
  bare "    Вариант $(label_of "$WIN"): $(desc_of "$WIN")"
  bare "    Готовый JSON лежит в $SCRATCH/rtm-${WIN}.json (задержка ${R_TIME[$WIN]}s,"
  bare "    стабильность $STAB_OK/$STAB_TOTAL за ~100 с)."
  if [ "$STAB_TOTAL" -gt 0 ] && [ "$STAB_OK" != "$STAB_TOTAL" ]; then
    bare "    ОГОВОРКА: стабильность НЕПОЛНАЯ ($STAB_OK/$STAB_TOTAL) — канал плавает,"
    bare "    как постоянный этот конфиг брать рано."
  fi
  if isok 34; then
    bare "    Рекомендация на будущее: в боевом конфиге заменить чужой hex-I1 на СВОЙ"
    bare "    сгенерированный QUIC Initial (вариант 3.4 подтвердил, что он работает)."
  fi
  if isok 11 && isok 31; then
    bare "    Замечание: обфускация на этом endpoint не обязательна (1.1 прошёл голым WG),"
    bare "    но и не вредит — оставить её как страховку на случай ужесточения ТСПУ разумно."
  fi
else
  bare "    РЕКОМЕНДОВАТЬ НЕЧЕГО: ни один вариант этапа 3 не дал OK."
  if [ -n "${EP_OK_LIST// /}" ]; then
    bare "    При этом голый WG на endpoint'ах$EP_OK_LIST работает (этап 1) — значит проблема"
    bare "    именно в слое noises Xray, а не в кредах и не в доступности адреса."
    bare "    Следующий шаг: взять минимальный конфиг БЕЗ обфускации с рабочего endpoint'а."
  else
    bare "    Не работает вообще ничего, включая голый WG. Проверь, та ли сеть, выключен ли"
    bare "    VPN пользователя, и не лежит ли сам WARP."
  fi
fi

sect "ДЛИТЕЛЬНОСТЬ"
bare "  Этап 1 (креды, чистый WG)        : $(hms "$T1_DUR")"
bare "  Этап 2 (нативный AmneziaWG)      : $(hms "$T2_DUR")$([ "$SUDO_OK" != "1" ] && echo '  (пропущен)')"
bare "  Этап 3 (Xray-матрица + стабильн.): $(hms "$T3_DUR")"
bare "  ИТОГО                            : $(hms "$T_TOTAL")"
bare ""
bare "Отчёт целиком: $REPORT"
bare "Отфильтрованные логи xray: ./results/retest-*.log"
bare "Сырые debug-логи (НЕ для репозитория, содержат домены пользователя): $SCRATCH/rtm-*.rawlog"
log "ГОТОВО."
