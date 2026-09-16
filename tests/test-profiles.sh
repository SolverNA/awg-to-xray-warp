#!/usr/bin/env bash
# Сравнение noise-профилей на одной базе (162.159.192.1:500, MTU 1280).
# У всех вариантов одинаковая база и 8 x rand 23-911; отличается ТОЛЬКО hex-часть noises.
set -u
cd "$(dirname "$0")/.." || exit 1

mkdir -p results

# Тип сети определяем ДО открытия отчёта: от него зависят имена ВСЕХ выходных файлов.
DEF=$(ip route show default 2>/dev/null | head -1)
case "$DEF" in
  *172.20.10.*) NET=mobile;;
  *)            NET=wifi;;
esac
TAG="$NET"                 # короткий тег сети для имён файлов: mobile | wifi
STAMP=$(date +%Y%m%d-%H%M) # метка для архивации прошлого прогона

R="./results/profiles-report-$TAG.txt"
SUMOUT="./results/profiles-summary-$TAG.tsv"

# --- защита от перезаписи ---
# Прошлый комплект ЭТОГО ЖЕ тега не затираем, а переименовываем в *-<тег>-<дата-время>.<расш>.
# Файлы чужого тега не трогаем вообще.
rotate_old(){
  local f
  local base
  local ext
  local new
  local k
  f="$1"
  [ -e "$f" ] || return 0
  base="${f%.*}"
  ext="${f##*.}"
  new="$base-$STAMP.$ext"
  # на случай двух прогонов в одну и ту же минуту — не затираем уже лежащий архив
  k=1
  while [ -e "$new" ]; do
    new="$base-$STAMP-$k.$ext"
    k=$((k+1))
  done
  mv -f "$f" "$new" 2>/dev/null || return 0
  echo "[!] Найден прошлый прогон для сети $TAG — сохранён как $(basename "$new")"
  return 0
}
rotate_old "$R"
rotate_old "$SUMOUT"
for f in ./results/profiles-"$TAG"-*.log; do
  [ -e "$f" ] || continue
  # уже заархивированные (…-ГГГГММДД-ЧЧММ.log) повторно не трогаем
  case "$f" in
    *-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9].log) continue;;
  esac
  rotate_old "$f"
done
unset f

: > "$R"
S="${TMPDIR:-/tmp}"; export S
PID=""
TRACE="https://www.cloudflare.com/cdn-cgi/trace"
SPEED="https://speed.cloudflare.com/__down?bytes=5000000"
SUM="$S/profiles-summary.tsv"; : > "$SUM"
SKIPPED=""

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
bare(){ echo "$*" | tee -a "$R"; }
FILTER='core: Xray|Reading config|app/log|peer\(|handshake|keepalive|Routine:|UAPI|UDP bind|proxy/wireguard|transport/internet/udp|listening|started'
cleanup(){ [ -n "${PID:-}" ] && { kill "$PID" 2>/dev/null; sleep 1; kill -9 "$PID" 2>/dev/null; }; return 0; }
trap cleanup EXIT; trap 'cleanup; exit 130' INT TERM

# ---------- зависимости ----------
for dep in python3 xray curl grep awk; do
  command -v "$dep" >/dev/null 2>&1 || { echo "НЕТ ЗАВИСИМОСТИ: $dep"; exit 1; }
done
# bc не обязателен: вся арифметика с плавающей точкой идёт через awk.

# ---------- шапка ----------
bare "=============================================================="
bare "  СРАВНЕНИЕ NOISE-ПРОФИЛЕЙ   $(date '+%F %T %z')"
bare "  База у всех: 162.159.192.1:500, MTU 1280, ключ p1Fqp,"
bare "  8 x rand 23-911. Отличается ТОЛЬКО hex-часть noises."
bare "  Сеть: $TAG | отчёт пишется в: $R"
bare "=============================================================="
ip -brief addr 2>/dev/null | grep -v DOWN | sed 's/^/  /' | tee -a "$R"
bare "Дефолт: ${DEF:-<нет маршрута по умолчанию>}"
case "$NET" in
  mobile) bare "-> МОБИЛЬНАЯ (тетеринг iPhone)";;
  *)      bare "-> проводной/WiFi";;
esac
if ip link show throne-tun >/dev/null 2>&1; then
  bare "!!! throne-tun ПОДНЯТ — VPN не выключен, результат недостоверен"
else
  bare "OK: VPN выключен"
fi

bare ""
bare "--------------------------------------------------------------"
bare "  ВАЖНО ПРО ИНТЕРПРЕТАЦИЮ ПРОФИЛЯ old-sip"
bare "--------------------------------------------------------------"
bare "  Статичный SIP из RFC 3261 на проводном/WiFi РАБОТАЕТ — это"
bare "  проверено ранее. Он НЕ работает только на мобильной сети"
bare "  Мегафон (там DPI режет именно этот известный образец)."
if [ "$NET" = "wifi" ]; then
bare "  СЕЙЧАС СЕТЬ: проводной/WiFi. Значит old-sip здесь ОЖИДАЕМО"
bare "  даст OK, и это НЕ означает провала методики и НЕ означает,"
bare "  что рандомизация бесполезна. Этот прогон — только проверка"
bare "  работоспособности всех пяти профилей на чистом канале."
bare "  РЕШАЮЩИЙ ПРОГОН — на мобильной сети (шлюз 172.20.10.x)."
else
bare "  СЕЙЧАС СЕТЬ: МОБИЛЬНАЯ. Это и есть решающий прогон:"
bare "  здесь old-sip ожидаемо должен УПАСТЬ, а рандомизированные"
bare "  и сгенерированные профили — выжить. Именно это сравнение"
bare "  и имеет смысл."
fi

# ---------- сборка конфигов ----------
# build <имя> <json-массив hex-элементов>  -> $S/prof-<имя>.json
build(){
  python3 - "$1" "$2" <<'PY'
import json,sys,os
name,hexjson=sys.argv[1],sys.argv[2]
hexes=json.loads(hexjson)
if not isinstance(hexes,list) or not hexes:
    sys.stderr.write("пустой или неверный список hex-элементов\n"); sys.exit(2)
for x in hexes:
    if x.get("type")!="hex" or not x.get("packet"):
        sys.stderr.write("элемент не является корректным hex-noise\n"); sys.exit(2)
    bytes.fromhex(x["packet"])
d=json.load(open("warp-xray.json"))
d["log"]={"loglevel":"debug"}
rands=[{"type":"rand","packet":"23-911","delay":"1-3"} for _ in range(8)]
patched=False
for o in d["outbounds"]:
    if o.get("protocol")=="freedom" and "noises" in o.get("settings",{}):
        o["settings"]["noises"]=hexes+rands; patched=True
if not patched:
    sys.stderr.write("в warp-xray.json не найден freedom-outbound с noises\n"); sys.exit(3)
json.dump(d,open(os.path.join(os.environ["S"],"prof-"+name+".json"),"w"),indent=1)
PY
}

skip_profile(){ # имя, причина
  bare "  [-] $1: ПРОПУЩЕН — $2"
  SKIPPED="$SKIPPED $1"
  printf '%s\t-\tПРОПУЩЕН (%s)\t-\t-\t-\t-\t-\n' "$1" "$2" >> "$SUM"
  rm -f "$S/prof-$1.json"
}

# try_build <имя> <описание источника> <json-массив или пусто>
try_build(){
  local nm src hj err
  nm="$1"; src="$2"; hj="${3:-}"
  if [ -z "$hj" ]; then skip_profile "$nm" "источник не дал данных: $src"; return 0; fi
  err=$(build "$nm" "$hj" 2>&1)
  if [ $? -ne 0 ] || [ ! -s "$S/prof-$nm.json" ]; then
    skip_profile "$nm" "сборка не удалась: ${err:-неизвестная ошибка}"; return 0
  fi
  bare "  [+] $nm: собран — $(describe "$S/prof-$nm.json")"
  return 0
}

describe(){ # печатает сводку по собранному конфигу
  python3 - "$1" <<'PY' 2>/dev/null || echo "не удалось разобрать конфиг"
import json,sys
d=json.load(open(sys.argv[1]))
fo=[o for o in d["outbounds"] if o.get("protocol")=="freedom" and "noises" in o.get("settings",{})][0]
n=fo["settings"]["noises"]
h=[x for x in n if x.get("type")=="hex"]
r=[x for x in n if x.get("type")=="rand"]
wg=[o for o in d["outbounds"] if o.get("protocol")=="wireguard"][0]["settings"]
p=wg["peers"][0]
print("hex: %d шт %s байт | rand: %d | endpoint %s:%s | mtu %s | key %s..." % (
    len(h), [len(bytes.fromhex(x["packet"])) for x in h], len(r),
    p.get("endpoint","?").rsplit(":",1)[0], p.get("endpoint","?").rsplit(":",1)[-1],
    wg.get("mtu","?"), wg.get("secretKey","")[:5]))
PY
}

# извлечь hex-элементы noises из готового xray-конфига
hex_from_json(){ # путь
  [ -f "$1" ] || return 0
  python3 - "$1" <<'PY' 2>/dev/null
import json,sys
d=json.load(open(sys.argv[1]))
c=[o for o in d.get("outbounds",[]) if o.get("protocol")=="freedom" and "noises" in o.get("settings",{})]
if not c: sys.exit(1)
h=[x for x in c[0]["settings"]["noises"] if x.get("type")=="hex"]
if not h: sys.exit(1)
print(json.dumps(h))
PY
}

bare ""
bare "--------------------------------------------------------------"
bare "  СБОРКА КОНФИГОВ"
bare "--------------------------------------------------------------"

# 1) ref-quic — эталонный QUIC Initial из рабочего AWG-конфига
QCONF=awg-samples/megafon-ok-500-jc120.conf
I1REF=""
[ -f "$QCONF" ] && I1REF=$(grep -oP 'I1 = <b 0x\K[0-9a-f]+' "$QCONF" 2>/dev/null | head -1)
if [ -n "$I1REF" ]; then
  try_build ref-quic "$QCONF" "[{\"type\":\"hex\",\"packet\":\"$I1REF\"}]"
else
  skip_profile ref-quic "нет поля I1 = <b 0x...> в $QCONF"
fi

# 2) peer-sip — рандомизированный SIP из готового профиля
try_build peer-sip "awg-samples/peer-sip-randomized.json" \
  "$(hex_from_json awg-samples/peer-sip-randomized.json)"

# 3) gen-sip — пара SIP-пакетов от нашего генератора
GS=""
if [ -x tests/gen-sip-invite.py ]; then
  GS=$(./tests/gen-sip-invite.py --pair --out json 2>/dev/null)
  case "$GS" in \[*) ;; *) GS="";; esac
fi
try_build gen-sip "tests/gen-sip-invite.py --pair --out json" "$GS"

# 4) gen-quic — один QUIC Initial от нашего генератора (выдаёт ОДИН элемент, не массив)
GQ=""
if [ -x tests/gen-quic-initial.py ]; then
  GQ=$(./tests/gen-quic-initial.py --out json 2>/dev/null)
  case "$GQ" in \{*) GQ="[$GQ]";; \[*) ;; *) GQ="";; esac
fi
try_build gen-quic "tests/gen-quic-initial.py --out json" "$GQ"

# 5) old-sip — статичный SIP из RFC 3261 (старый профиль)
try_build old-sip "legacy/warp-xray-sip-profile.json" \
  "$(hex_from_json legacy/warp-xray-sip-profile.json)"

# ---------- прогон ----------
# run <имя> <секунд стабильности>
run(){
  local name stab cfg cfgdesc T W RC sum n t avg sp hs_s hs_r lat spd status phase ok fail i w2 logf outlog
  name="$1"
  stab="${2:-0}"
  cfg="$S/prof-$name.json"
  phase="1"; [ "$stab" -gt 0 ] && phase="2(стаб)"
  lat="-"; spd="-"; hs_s="-"; hs_r="-"; status="?"

  if [ ! -f "$cfg" ]; then
    bare ""; bare "--- $name: конфиг не собран, пропуск"
    return 0
  fi

  bare ""; bare "--------------------------------------------------------------"
  log "ПРОФИЛЬ: $name   (фаза $phase)"
  cfgdesc=$(describe "$cfg"); bare "  $cfgdesc"

  if ! xray run -test -c "$cfg" >/dev/null 2>&1; then
    bare "  КОНФИГ НЕ ВАЛИДЕН (xray run -test)"
    status="КОНФИГ НЕ ВАЛИДЕН"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$phase" "$status" "$lat" "$spd" "$hs_s" "$hs_r" "-" >> "$SUM"
    return 0
  fi

  logf="$S/prof-$name.log"
  nohup xray run -c "$cfg" > "$logf" 2>&1 & PID=$!
  sleep 5

  T=$(curl -s --max-time 15 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?
  T="${T:-}"
  if [ -z "$T" ]; then
    sleep 2
    T=$(curl -s --max-time 15 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null); RC=$?
    T="${T:-}"
  fi
  W=$(printf '%s\n' "$T" | grep -oP '^warp=\K.*' || true)
  W="${W:-}"

  hs_s=$(grep -ac 'Sending handshake initiation' "$logf" 2>/dev/null || true); hs_s="${hs_s:-0}"
  hs_r=$(grep -ac 'Received handshake response' "$logf" 2>/dev/null || true); hs_r="${hs_r:-0}"

  if [ "$W" != "on" ] && [ "$W" != "plus" ]; then
    bare "  РЕЗУЛЬТАТ: FAIL (curl rc=$RC, warp='${W:-нет ответа}')"
    bare "  хендшейк: отправлено=$hs_s получено=$hs_r"
    status="FAIL"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$phase" "$status" "$lat" "$spd" "$hs_s" "$hs_r" "-" >> "$SUM"
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; sleep 2
    outlog="./results/profiles-$TAG-$name.log"
    [ "$stab" -gt 0 ] && outlog="./results/profiles-$TAG-$name-stability.log"
    grep -aE "$FILTER" "$logf" > "$outlog" 2>/dev/null || true
    return 0
  fi

  status="OK"
  bare "  РЕЗУЛЬТАТ: OK — warp=$W ip=$(printf '%s\n' "$T" | grep -oP '^ip=\K.*' || echo '?')"

  # задержка: 3 запроса, среднее (через awk, без bc)
  sum=0; n=0
  for i in 1 2 3; do
    t=$(curl -s -o /dev/null -w '%{time_total}' --max-time 15 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null || true)
    t="${t:-}"
    case "$t" in
      ''|*[!0-9.]*) ;;
      *) sum=$(awk -v a="$sum" -v b="$t" 'BEGIN{printf "%.6f", a+b}'); n=$((n+1));;
    esac
  done
  if [ "$n" -gt 0 ]; then
    avg=$(awk -v s="$sum" -v k="$n" 'BEGIN{printf "%.3f", s/k}')
    lat="${avg}s"
    bare "  задержка: $avg с (среднее по $n)"
  else
    bare "  задержка: не измерена"
  fi

  # скорость
  sp=$(curl -s -o /dev/null -w '%{speed_download} %{time_total}' --max-time 60 -x socks5h://127.0.0.1:10808 "$SPEED" 2>/dev/null || true)
  sp="${sp:-}"
  if [ -n "$sp" ]; then
    spd=$(printf '%s\n' "$sp" | awk '{printf "%.2f MB/s", $1/1048576}')
    bare "  скорость: $(printf '%s\n' "$sp" | awk '{printf "%.2f MB/s (%.1f Мбит/с) за %.2f с", $1/1048576, $1*8/1000000, $2}')"
  else
    bare "  скорость: не измерена"
  fi

  # стабильность
  local stabres="-"
  if [ "$stab" -gt 0 ]; then
    bare "  стабильность $stab с (запрос каждые 20 с) — ловим рехендшейк WireGuard (~раз в 2 мин):"
    ok=0; fail=0; i=0
    while [ $((i*20)) -lt "$stab" ]; do
      i=$((i+1)); sleep 20
      w2=$(curl -s --max-time 12 -x socks5h://127.0.0.1:10808 "$TRACE" 2>/dev/null | grep -oP '^warp=\K.*' || true)
      w2="${w2:-}"
      if [ "$w2" = "on" ] || [ "$w2" = "plus" ]; then
        ok=$((ok+1)); bare "    +$((i*20))s OK"
      else
        fail=$((fail+1)); bare "    +$((i*20))s FAIL"
      fi
    done
    bare "  итог стабильности: OK=$ok FAIL=$fail"
    stabres="OK=$ok/FAIL=$fail"
    [ "$fail" -gt 0 ] && status="OK(нестабилен)"
  fi

  hs_s=$(grep -ac 'Sending handshake initiation' "$logf" 2>/dev/null || true); hs_s="${hs_s:-0}"
  hs_r=$(grep -ac 'Received handshake response' "$logf" 2>/dev/null || true); hs_r="${hs_r:-0}"
  bare "  хендшейков: отправлено=$hs_s получено=$hs_r"
  [ "$stab" -gt 0 ] && [ "$hs_s" -gt 1 ] && bare "  -> рехендшейк ЗАХВАЧЕН (отправлено больше одного)"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$phase" "$status" "$lat" "$spd" "$hs_s" "$hs_r" "$stabres" >> "$SUM"

  kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; sleep 2
  outlog="./results/profiles-$TAG-$name.log"
  [ "$stab" -gt 0 ] && outlog="./results/profiles-$TAG-$name-stability.log"
  grep -aE "$FILTER" "$logf" > "$outlog" 2>/dev/null || true
  return 0
}

run ref-quic 0
run peer-sip 0
run gen-sip  0
run gen-quic 0
run old-sip  0

bare ""; bare "=============================================================="
bare "  ФАЗА 2: стабильность 160 с для двух ключевых профилей"
bare "  (рехендшейк WireGuard идёт примерно раз в 2 минуты —"
bare "   короткие прогоны его не захватывают)"
bare "=============================================================="
run ref-quic 160
run peer-sip 160

# ---------- итоговая таблица ----------
bare ""; bare "=============================================================="
bare "  ИТОГОВАЯ ТАБЛИЦА"
bare "=============================================================="
python3 - "$SUM" <<'PY' | tee -a "$R"
import sys
hdr=("профиль","фаза","статус","задержка","скорость","hs отпр","hs получ","стабильность")
rows=[hdr]
try:
    with open(sys.argv[1],encoding="utf-8") as f:
        for line in f:
            line=line.rstrip("\n")
            if not line.strip(): continue
            p=line.split("\t")
            p=(p+["-"]*8)[:8]
            rows.append(tuple(p))
except FileNotFoundError:
    pass
if len(rows)==1:
    print("  (нет данных — ни один профиль не отработал)")
else:
    w=[max(len(r[i]) for r in rows) for i in range(8)]
    for idx,r in enumerate(rows):
        print("  "+"  ".join(r[i].ljust(w[i]) for i in range(8)))
        if idx==0: print("  "+"  ".join("-"*w[i] for i in range(8)))
PY

bare ""
bare "--------------------------------------------------------------"
bare "  ВЫВОДЫ"
bare "--------------------------------------------------------------"
if [ -n "${SKIPPED// /}" ]; then
  bare "  Пропущенные профили (источник/сборка):$SKIPPED"
else
  bare "  Все пять профилей собраны и проверены."
fi
if [ "$NET" = "wifi" ]; then
  bare "  Сеть: проводной/WiFi — здесь канал чистый."
  bare "  * old-sip = OK ОЖИДАЕМО и НИЧЕГО не опровергает: статичный"
  bare "    SIP из RFC 3261 на WiFi работал и раньше, падает он только"
  bare "    на мобильной сети Мегафон."
  bare "  * Смысл этого прогона: убедиться, что все пять профилей"
  bare "    вообще поднимают туннель и дают сопоставимые задержку/скорость."
  bare "  * РЕШАЮЩИЙ ПРОГОН — повторить этот же скрипт на мобильной сети"
  bare "    (тетеринг iPhone, шлюз 172.20.10.x). Только там разница между"
  bare "    old-sip и рандомизированными профилями что-то значит."
else
  bare "  Сеть: МОБИЛЬНАЯ — это решающий прогон."
  bare "  * Ожидание: old-sip падает (известный образец режется DPI),"
  bare "    ref-quic / peer-sip / gen-sip / gen-quic должны выживать."
  bare "  * Если old-sip тоже OK — DPI на этой соте не срабатывает,"
  bare "    прогон неинформативен, надо повторить."
  bare "  * Если падают ВСЕ — проблема не в noise, а в самой сети/эндпоинте."
fi
cp -f "$SUM" "$SUMOUT" 2>/dev/null || true

bare ""
bare "ГОТОВО."
bare "  отчёт:  $R"
bare "  сводка: $SUMOUT"
bare "  логи:   ./results/profiles-$TAG-<профиль>.log (и -stability.log)"
