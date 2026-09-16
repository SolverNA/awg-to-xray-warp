#!/usr/bin/env python3
"""
Генератор пары SIP-пакетов (INVITE + 100 Trying) для `noises` типа `hex`.

Зачем: старый рабочий профиль использовал в качестве I1/I2 пример из RFC 3261
§24.2 БАЙТ-В-БАЙТ (bob@biloxi.com / alice@atlanta.com,
branch=z9hG4bK776asdhds, tag=1928301774, Call-ID a84b4c76e66710@pc33.atlanta.com).
Этот текст растиражирован по гистам и конфигам, так что как сигнатура он
сгорает первым. Профиль работал на проводном и перестал работать на мобильной.

Здесь генерируются синтаксически корректные по RFC 3261 сообщения, но со
СЛУЧАЙНЫМИ идентификаторами: свои домены, user-части, Call-ID, branch-суффикс
(обязательный магический префикс z9hG4bK сохранён — RFC 3261 §8.1.1.7), tag,
CSeq. Размеры подогнаны под оригинал (~348 и ~245 байт).

Примеры:
  ./gen-sip-invite.py                      # текст INVITE
  ./gen-sip-invite.py --pair --out text    # оба пакета
  ./gen-sip-invite.py --pair --out hex     # две hex-строки (I1, затем I2)
  ./gen-sip-invite.py --pair --out json    # готовые элементы noises
"""

import argparse
import json
import random
import string

# Правдоподобные слова для доменов второго уровня — ни biloxi, ни atlanta.
WORDS = [
    "nordvale", "kestrel", "lumenix", "corvina", "aldermere", "ravel",
    "pinehurst", "quaystone", "vertana", "millbrook", "orinoco", "sableton",
    "stelvio", "granmere", "ravenwood", "calderon", "tessara", "vinta",
    "windover", "brambly", "solvaris", "northgate", "clearford", "maribel",
    "olva", "brix", "kavo", "lunet", "arda", "seln", "morix", "talvi",
    "ferro", "nubo", "veld", "cima", "orba", "ketu", "nyra", "solu",
]
TLDS = ["net", "com", "org", "io", "net", "com"]
NAMES = [
    "Anna", "Mark", "Dana", "Peter", "Julia", "Oliver", "Nina", "Victor",
    "Clara", "Simon", "Helen", "Lukas", "Maya", "Felix", "Iris", "Roman",
]
USERS = [
    "support", "sales", "desk", "office", "reception", "ops", "line1",
    "conf", "helpdesk", "dispatch", "front", "billing",
]
PRODUCTS = [
    "Softphone", "VoipClient", "SIPPhone", "CallMate", "LineDesk",
    "TeleBridge", "PhoneCore", "VoiceLink",
]
TRANSPORTS = ["UDP", "UDP", "UDP", "TCP"]


def tok(n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))


def sip_domain():
    return "sip.%s.%s" % (random.choice(WORDS), random.choice(TLDS))


def _identity():
    """Случайный, но согласованный набор идентификаторов диалога."""
    to_dom = sip_domain()
    from_dom = sip_domain()
    while from_dom == to_dom:
        from_dom = sip_domain()
    to_name = random.choice(NAMES)
    from_name = random.choice(NAMES)
    while from_name == to_name:
        from_name = random.choice(NAMES)
    return {
        "to_dom": to_dom,
        "from_dom": from_dom,
        "to_user": random.choice(USERS + [n.lower() for n in NAMES]),
        "from_user": random.choice(USERS + [n.lower() for n in NAMES]),
        "to_name": to_name,
        "from_name": from_name,
        "host": "%s%d.%s" % (random.choice(["pc", "ua", "ws", "host", "client"]),
                             random.randint(2, 99), from_dom.split(".", 1)[1]),
        "transport": random.choice(TRANSPORTS),
        # магический префикс z9hG4bK обязателен по RFC 3261 §8.1.1.7
        "branch": "z9hG4bK" + tok(random.randint(8, 14)),
        "tag": tok(random.randint(8, 10), string.digits + string.ascii_lowercase),
        "cseq": random.randint(1, 999999),
        "maxfwd": random.choice([70, 70, 70, 69, 68]),
        "callid": tok(random.randint(12, 16), string.hexdigits.lower()[:16]),
    }


def _render(idt, resp, ua_value=None):
    """Собрать сообщение по RFC 3261 §7. resp=False -> INVITE, True -> 100 Trying."""
    common = [
        "Via: SIP/2.0/%s %s;branch=%s" % (idt["transport"], idt["host"], idt["branch"]),
        "To: %s <sip:%s@%s>" % (idt["to_name"], idt["to_user"], idt["to_dom"]),
        "From: %s <sip:%s@%s>;tag=%s" % (idt["from_name"], idt["from_user"],
                                         idt["from_dom"], idt["tag"]),
        "Call-ID: %s@%s" % (idt["callid"], idt["host"]),
        "CSeq: %d INVITE" % idt["cseq"],
    ]
    if resp:
        lines = ["SIP/2.0 100 Trying"] + common
        if ua_value is not None:
            lines.append("Server: %s" % ua_value)
    else:
        lines = ["INVITE sip:%s@%s SIP/2.0" % (idt["to_user"], idt["to_dom"]),
                 common[0],
                 "Max-Forwards: %d" % idt["maxfwd"]] + common[1:] + [
            "Contact: <sip:%s@%s>" % (idt["from_user"], idt["host"]),
            "Content-Type: application/sdp",
        ]
        if ua_value is not None:
            lines.append("User-Agent: %s" % ua_value)
    lines.append("Content-Length: 0")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _pad_to(idt, target, resp):
    """Добить размер до target за счёт длины User-Agent / Server."""
    hdr_len = len("Server: " if resp else "User-Agent: ") + 2   # +2 = CRLF
    base = len(_render(idt, resp))
    need = target - base - hdr_len
    if need < 8:
        return _render(idt, resp)                                # уже близко к цели
    product = "%s/%d.%d.%d" % (random.choice(PRODUCTS), random.randint(1, 9),
                               random.randint(0, 9), random.randint(0, 20))
    if need >= len(product) + 9:
        ua = product + " (build %s)" % tok(need - len(product) - 9, string.digits)
    elif need >= len(product):
        ua = product + tok(need - len(product), string.digits)
    else:
        ua = product[:need] if need >= 8 else product
    return _render(idt, resp, ua)


def make_pair(size_invite=348, size_trying=245, attempts=400):
    """Согласованная пара (INVITE, 100 Trying) нужного размера."""
    slack_i = len("User-Agent: ") + 2
    slack_t = len("Server: ") + 2
    best = None
    for _ in range(attempts):
        idt = _identity()
        bi = len(_render(idt, False))
        bt = len(_render(idt, True))
        # годится, если оба базовых сообщения помещаются под цель с запасом на padding
        if bi <= size_invite - slack_i and bt <= size_trying - slack_t:
            best = idt
            break
        score = max(bi - size_invite, 0) + max(bt - size_trying, 0)
        if best is None or score < best[0]:
            best = (score, idt)
    idt = best if isinstance(best, dict) else best[1]
    return _pad_to(idt, size_invite, False), _pad_to(idt, size_trying, True)


def main():
    ap = argparse.ArgumentParser(description="Генератор SIP INVITE / 100 Trying для noises")
    ap.add_argument("--out", choices=["hex", "text", "json"], default="text")
    ap.add_argument("--pair", action="store_true",
                    help="выдать оба пакета (INVITE и 100 Trying), а не только INVITE")
    ap.add_argument("--size", type=int, default=348, help="целевой размер INVITE (байт)")
    ap.add_argument("--size2", type=int, default=245, help="целевой размер 100 Trying (байт)")
    ap.add_argument("--delay", default="1-2", help="поле delay для json-вывода")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    inv, tr = make_pair(args.size, args.size2)
    pkts = [inv, tr] if args.pair else [inv]

    if args.out == "hex":
        for p in pkts:
            print(p.hex())
    elif args.out == "json":
        print(json.dumps([{"type": "hex", "packet": p.hex(), "delay": args.delay}
                          for p in pkts], ensure_ascii=False))
    else:
        for i, p in enumerate(pkts):
            if i:
                print("-" * 60)
            print("# %d байт" % len(p))
            print(p.decode("ascii"), end="")


if __name__ == "__main__":
    main()
