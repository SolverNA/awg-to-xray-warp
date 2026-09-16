#!/usr/bin/env python3
"""
Генератор готового к импорту конфига Xray (WARP + обфускация noises).

Собирает конфиг на ЭКСПЕРИМЕНТАЛЬНО ПРОВЕРЕННОЙ базе (results/profiles-report-mobile.txt):
эндпоинт 162.159.192.1:500, MTU 1280, keepAlive 5, 8 шумов `rand` 23-911 с задержкой 1-3,
а в качестве пакета-обманки — СВЕЖИЙ QUIC Initial, генерируемый заново при каждом запуске
через tests/gen-quic-initial.py. Захардкоженный пакет больше не используется: на мобильной
сети Мегафон сгенерированный QUIC показал те же результаты, что и перехваченный чужой
(OK, 0.238 с против 0.227 с), поэтому ротация безопасна.

SIP (`--noise sip`) оставлен как опция для проводных сетей и НЕ рекомендуется: на мобильной
сети он падает в любом виде — и статичный из RFC 3261, и рандомизированный.

Примеры:
  ./gen-warp-config.py                                  # клиентский конфиг в stdout
  ./gen-warp-config.py --out warp-client.json           # он же в файл
  ./gen-warp-config.py --full --out warp-xray.json      # с inbounds socks/http для десктопа
  ./gen-warp-config.py --sni mail.ru --seed 42          # воспроизводимая сборка
  ./gen-warp-config.py --creds my-warp.conf             # свои креды из WireGuard-конфига
"""

import argparse
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

# Не оставляем __pycache__ в репозитории: генераторы из tests/ грузятся как модули.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))

# --- проверенная рабочая база (см. results/profiles-report-mobile.txt) -----
DEF_ENDPOINT = "162.159.192.1:500"
DEF_MTU = 1280
DEF_KEEPALIVE = 5
DEF_RAND_COUNT = 8
DEF_RAND_SIZE = "23-911"
DEF_RAND_DELAY = "1-3"
DEF_QUIC_SIZE = 1252
DEF_QUIC_DELAY = "1-2"
DEF_DNS = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
DEF_PEER_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # публичный ключ Cloudflare WARP

# Xray валидирует поле type в noises — допустимы только эти четыре значения.
NOISE_TYPES = ("rand", "str", "hex", "base64")


def die(msg):
    print(f"ОШИБКА: {msg}", file=sys.stderr)
    sys.exit(1)


def info(msg):
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Подключение уже готовых генераторов пакетов из tests/ (не дублируем крипто)
# --------------------------------------------------------------------------
def load_module(filename, human_name):
    path = os.path.join(HERE, "tests", filename)
    if not os.path.exists(path):
        die(f"не найден {path} — {human_name} лежит в tests/ рядом с этим скриптом")
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_")[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except ImportError as e:
        die(f"не удалось загрузить {path}: {e}\n"
            f"Похоже, не хватает python3-зависимости. Поставьте её:\n"
            f"  pip install cryptography      (или: sudo pacman -S python-cryptography)")
    return mod


# --------------------------------------------------------------------------
# Чтение кредов
# --------------------------------------------------------------------------
def norm_address(addr):
    """Добавляет префикс, если в исходнике он опущен (WireGuard-конфиги часто без него)."""
    addr = addr.strip()
    if not addr:
        return None
    if "/" in addr:
        return addr
    return addr + ("/128" if ":" in addr else "/32")


def creds_from_xray_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        die(f"{path}: не разбирается как JSON ({e})")
    except OSError as e:
        die(f"{path}: не читается ({e})")

    for ob in data.get("outbounds", []):
        if ob.get("protocol") != "wireguard":
            continue
        s = ob.get("settings", {})
        peers = s.get("peers") or [{}]
        return {
            "secretKey": s.get("secretKey"),
            "address": [a for a in (norm_address(a) for a in s.get("address", [])) if a],
            "publicKey": peers[0].get("publicKey"),
            "endpoint": peers[0].get("endpoint"),
            "mtu": s.get("mtu"),
            "reserved": s.get("reserved"),
        }
    die(f"{path}: не найден outbound с protocol=wireguard")


def creds_from_wg_conf(path):
    """Читает WireGuard/AmneziaWG .conf. Поля AmneziaWG (Jc, S1, H1, I1...) игнорируются:
    в Xray их аналогов нет вообще, писать их в конфиг нельзя."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        die(f"{path}: не читается ({e})")

    section = None
    out = {"secretKey": None, "address": [], "publicKey": None,
           "endpoint": None, "mtu": None, "reserved": None}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if section == "interface":
            if key == "privatekey":
                out["secretKey"] = val
            elif key == "address":
                out["address"] = [a for a in (norm_address(x) for x in val.split(",")) if a]
            elif key == "mtu":
                out["mtu"] = int(val) if val.isdigit() else None
        elif section == "peer":
            if key == "publickey":
                out["publicKey"] = val
            elif key == "endpoint":
                out["endpoint"] = val
    if not out["secretKey"]:
        die(f"{path}: не найден PrivateKey в секции [Interface]")
    return out


def load_creds(path):
    if not os.path.exists(path):
        die(f"файл с кредами не найден: {path}\n"
            f"Укажите свой через --creds или задайте ключ напрямую: "
            f"--private-key ... --address ...")
    with open(path, "rb") as f:
        head = f.read(64).lstrip()
    if head.startswith(b"{"):
        return creds_from_xray_json(path)
    return creds_from_wg_conf(path)


# --------------------------------------------------------------------------
# Сборка noises
# --------------------------------------------------------------------------
def build_noises(args):
    noises = []
    описание = []

    if args.noise == "quic":
        quic = load_module("gen-quic-initial.py", "генератор QUIC Initial")
        sni = args.sni or random.choice(quic.DEFAULT_SNIS)
        try:
            pkt = quic.build_initial(sni, args.quic_size)
        except SystemExit as e:
            die(str(e).replace("--size", "--quic-size"))
        noises.append({"type": "hex", "packet": pkt.hex(), "delay": args.quic_delay})
        описание.append(f"QUIC Initial {len(pkt)} байт, SNI={sni}, ALPN=h3")
    else:
        info("ВНИМАНИЕ: --noise sip. На МОБИЛЬНЫХ сетях этот профиль НЕ РАБОТАЕТ.")
        info("  Проверено на Мегафоне: и статичный SIP из RFC 3261, и рандомизированный,")
        info("  и перехваченный у рабочего пира — все три дают FAIL, поток режется сразу")
        info("  (хендшейков отправлено=7, получено=0). Рандомизация не спасает.")
        info("  SIP имеет смысл только на проводном/WiFi, где фильтрации нет вообще.")
        info("  Для мобильной сети используйте профиль по умолчанию (--noise quic).")
        sip = load_module("gen-sip-invite.py", "генератор SIP INVITE")
        inv, trying = sip.make_pair()
        for p in (inv, trying):
            noises.append({"type": "hex", "packet": p.hex(), "delay": args.quic_delay})
        описание.append(f"SIP INVITE + 100 Trying, {len(inv)} и {len(trying)} байт")

    for _ in range(args.rand_count):
        noises.append({"type": "rand", "packet": args.rand_size, "delay": args.rand_delay})
    if args.rand_count:
        описание.append(f"{args.rand_count} x rand {args.rand_size} (delay {args.rand_delay})")

    for n in noises:
        if n["type"] not in NOISE_TYPES:
            die(f"недопустимый type в noises: {n['type']!r} (Xray принимает только {NOISE_TYPES})")
    return noises, описание


# --------------------------------------------------------------------------
# Сборка конфига
# --------------------------------------------------------------------------
def build_config(args, creds, noises):
    warp = {
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": creds["secretKey"],
            "address": creds["address"],
            "mtu": args.mtu,
            "peers": [{
                "publicKey": creds["publicKey"],
                "endpoint": args.endpoint,
                "keepAlive": args.keepalive,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
            }],
        },
        "streamSettings": {"sockopt": {"dialerProxy": "noise-out"}},
    }
    if creds.get("reserved"):
        warp["settings"]["reserved"] = creds["reserved"]

    noise_out = {
        "tag": "noise-out",
        "protocol": "freedom",
        "settings": {"domainStrategy": "AsIs", "noises": noises},
    }

    cfg = {"log": {"loglevel": args.loglevel}, "dns": {"servers": args.dns}}
    if args.full:
        cfg["inbounds"] = [
            {
                "tag": "socks-in",
                "listen": args.listen,
                "port": args.socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "http-in",
                "listen": args.listen,
                "port": args.http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
        ]
    cfg["outbounds"] = [warp, noise_out]
    cfg["routing"] = {
        "domainStrategy": "AsIs",
        "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "warp"}],
    }
    return cfg


# --------------------------------------------------------------------------
# Проверка через xray run -test
# --------------------------------------------------------------------------
def xray_test(text, xray_bin):
    exe = shutil.which(xray_bin)
    if not exe:
        info(f"ПРОВЕРКА ПРОПУЩЕНА: не найден исполняемый файл {xray_bin!r} в PATH.")
        info("  Поставьте Xray или укажите путь через --xray, либо отключите проверку --no-test.")
        return None

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        tmp.write(text)
        tmp.close()
        r = subprocess.run([exe, "run", "-test", "-c", tmp.name],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        info("ПРОВЕРКА: xray run -test не ответил за 30 с")
        return False
    finally:
        os.unlink(tmp.name)

    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        info("ПРОВЕРКА: xray run -test — Configuration OK")
        info("  ВНИМАНИЕ: парсер Xray нестрогий и молча проглатывает неизвестные ключи.")
        info("  Этот результат значит ТОЛЬКО «синтаксис не сломан», а не «все поля поддержаны».")
        return True
    info(f"ПРОВЕРКА: xray run -test ПРОВАЛЕН (код {r.returncode})")
    for line in out.splitlines()[-12:]:
        info(f"  {line}")
    return False


# --------------------------------------------------------------------------
def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="gen-warp-config.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Генератор готового конфига Xray: WARP через WireGuard + обфускация noises.\n"
            "База проверена экспериментально на мобильной сети (см. results/profiles-report-mobile.txt):\n"
            f"  эндпоинт {DEF_ENDPOINT}, MTU {DEF_MTU}, keepAlive {DEF_KEEPALIVE},\n"
            f"  свежий QUIC Initial + {DEF_RAND_COUNT} x rand {DEF_RAND_SIZE}.\n"
            "Пакет-обманка генерируется заново при каждом запуске — ничего не захардкожено."),
        epilog=(
            "Примеры:\n"
            "  ./gen-warp-config.py                             клиентский конфиг в stdout\n"
            "  ./gen-warp-config.py --out warp-client.json      он же в файл\n"
            "  ./gen-warp-config.py --full --out warp-xray.json конфиг с inbounds для десктопа\n"
            "  ./gen-warp-config.py --sni mail.ru --seed 42     воспроизводимая сборка\n"
            "  ./gen-warp-config.py --creds my-warp.conf        свои креды из WireGuard-конфига\n"))

    g = ap.add_argument_group("креды WARP")
    g.add_argument("--creds", metavar="ФАЙЛ", default=os.path.join(HERE, "warp-xray.json"),
                   help="откуда брать креды: конфиг Xray (.json) или WireGuard/AmneziaWG (.conf). "
                        "По умолчанию warp-xray.json рядом со скриптом")
    g.add_argument("--private-key", metavar="КЛЮЧ",
                   help="приватный ключ интерфейса в base64 (перекрывает --creds)")
    g.add_argument("--address", metavar="A,B",
                   help="внутренние адреса через запятую, например 172.16.0.2/32,2606:...::1/128")
    g.add_argument("--peer-key", metavar="КЛЮЧ", default=None,
                   help="публичный ключ пира (по умолчанию из --creds, иначе ключ Cloudflare WARP)")

    g = ap.add_argument_group("параметры туннеля")
    g.add_argument("--endpoint", metavar="ХОСТ:ПОРТ", default=DEF_ENDPOINT,
                   help=f"эндпоинт пира (по умолчанию {DEF_ENDPOINT} — проверенный рабочий)")
    g.add_argument("--mtu", type=int, default=DEF_MTU,
                   help=f"MTU туннеля (по умолчанию {DEF_MTU})")
    g.add_argument("--keepalive", type=int, default=DEF_KEEPALIVE,
                   help=f"keepAlive в секундах (по умолчанию {DEF_KEEPALIVE})")
    g.add_argument("--dns", metavar="A,B", default=",".join(DEF_DNS),
                   help="DNS-серверы через запятую")

    g = ap.add_argument_group("обфускация")
    g.add_argument("--noise", choices=["quic", "sip"], default="quic",
                   help="пакет-обманка: quic — свежий QUIC Initial (по умолчанию, работает везде); "
                        "sip — SIP INVITE (НЕ работает на мобильных сетях)")
    g.add_argument("--sni", metavar="ДОМЕН",
                   help="домен в ClientHello внутри QUIC Initial (по умолчанию случайный популярный)")
    g.add_argument("--quic-size", type=int, default=DEF_QUIC_SIZE,
                   help=f"размер QUIC Initial в байтах (по умолчанию {DEF_QUIC_SIZE})")
    g.add_argument("--quic-delay", metavar="A-B", default=DEF_QUIC_DELAY,
                   help=f"задержка после пакета-обманки (по умолчанию {DEF_QUIC_DELAY})")
    g.add_argument("--rand-count", type=int, default=DEF_RAND_COUNT,
                   help=f"сколько шумов rand добавить (по умолчанию {DEF_RAND_COUNT})")
    g.add_argument("--rand-size", metavar="A-B", default=DEF_RAND_SIZE,
                   help=f"размер шумов rand (по умолчанию {DEF_RAND_SIZE})")
    g.add_argument("--rand-delay", metavar="A-B", default=DEF_RAND_DELAY,
                   help=f"задержка между шумами rand (по умолчанию {DEF_RAND_DELAY})")

    g = ap.add_argument_group("вид конфига и вывод")
    m = g.add_mutually_exclusive_group()
    m.add_argument("--client", dest="full", action="store_false", default=False,
                   help="клиентский конфиг БЕЗ inbounds — для импорта в v2rayTun, Throne, "
                        "Happ, Hiddify (режим по умолчанию)")
    m.add_argument("--full", dest="full", action="store_true",
                   help="полный конфиг с inbounds socks/http — для `xray run -c` на десктопе")
    g.add_argument("--socks-port", type=int, default=10808, help="порт socks для --full")
    g.add_argument("--http-port", type=int, default=10809, help="порт http для --full")
    g.add_argument("--listen", default="127.0.0.1", help="адрес прослушивания для --full")
    g.add_argument("--loglevel", default="warning",
                   choices=["debug", "info", "warning", "error", "none"])
    g.add_argument("--out", metavar="ПУТЬ", default="-",
                   help="куда писать конфиг: путь к файлу или '-' для stdout (по умолчанию)")
    g.add_argument("--seed", type=int,
                   help="зерно ГСЧ — одинаковый seed даёт побайтово одинаковый конфиг")
    g.add_argument("--no-test", action="store_true",
                   help="не прогонять готовый конфиг через `xray run -test`")
    g.add_argument("--xray", default="xray", help="имя или путь исполняемого файла Xray")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.seed is not None:
        random.seed(args.seed)

    if not re.match(r"^\S+:\d+$", args.endpoint):
        die(f"--endpoint должен быть в виде ХОСТ:ПОРТ, получено {args.endpoint!r}")
    if not 576 <= args.mtu <= 1500:
        die(f"--mtu {args.mtu} вне разумного диапазона 576..1500")
    if args.rand_count < 0:
        die("--rand-count не может быть отрицательным")
    args.dns = [d.strip() for d in args.dns.split(",") if d.strip()]

    # креды: файл, поверх которого ложатся явные флаги
    if args.private_key and args.address:
        creds = {"secretKey": args.private_key, "address": [], "publicKey": None,
                 "endpoint": None, "mtu": None, "reserved": None}
    else:
        creds = load_creds(args.creds)
        info(f"Креды: {args.creds}")
    if args.private_key:
        creds["secretKey"] = args.private_key
    if args.address:
        creds["address"] = [a for a in (norm_address(x) for x in args.address.split(",")) if a]
    if args.private_key and not args.address:
        info("ВНИМАНИЕ: задан --private-key без --address — адреса взяты из --creds.")
        info("  У WARP внутренние адреса привязаны к ключу, так что укажите и --address.")
    if args.peer_key:
        creds["publicKey"] = args.peer_key
    if not creds.get("publicKey"):
        creds["publicKey"] = DEF_PEER_PUBKEY

    if not creds.get("secretKey"):
        die("не найден приватный ключ. Задайте --private-key или укажите --creds с рабочим файлом")
    if not creds.get("address"):
        die("не найдены внутренние адреса. Задайте --address или укажите --creds с рабочим файлом")

    noises, описание = build_noises(args)
    cfg = build_config(args, creds, noises)
    text = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"

    вид = "полный (с inbounds socks/http)" if args.full else "клиентский (без inbounds)"
    info(f"Конфиг: {вид}")
    info(f"Туннель: {args.endpoint}, MTU {args.mtu}, keepAlive {args.keepalive}, "
         f"ключ {creds['secretKey'][:5]}...")
    for d in описание:
        info(f"Шум: {d}")
    if args.seed is not None:
        info(f"Зерно ГСЧ: {args.seed} (результат воспроизводим)")

    ok = None
    if not args.no_test:
        ok = xray_test(text, args.xray)

    if args.out == "-":
        sys.stdout.write(text)
    else:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            die(f"не удалось записать {args.out}: {e}")
        info(f"Записано: {args.out} ({len(text)} байт)")
        if args.full:
            info(f"Запуск: xray run -c {args.out}")

    return 0 if ok is not False else 1


if __name__ == "__main__":
    sys.exit(main())
