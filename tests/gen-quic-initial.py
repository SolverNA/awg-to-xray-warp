#!/usr/bin/env python3
"""
Генератор НАСТОЯЩЕГО QUIC Initial-пакета (RFC 9000 / RFC 9001, QUIC v1).

Зачем: у freedom-аутбаунда Xray в `noises` можно отправить произвольный пакет
типом `hex`. Рабочие профили AmneziaWG (`I1` в awg-samples/*.conf) содержат
НАСТОЯЩИЙ QUIC Initial: его payload расшифровывается Initial-ключами,
выведенными из DCID, и внутри лежит валидный TLS ClientHello с SNI и ALPN=h3.
Пакет из случайных байт под видом QUIC не работает — ТСПУ (или что-то по пути)
явно проверяет расшифровку.

Этот скрипт собирает такой пакет с нуля, КАЖДЫЙ РАЗ НОВЫЙ:
  случайный DCID -> Initial-ключи по RFC 9001 §5.2 -> TLS ClientHello
  (с настраиваемым SNI) -> CRYPTO-фрейм -> PADDING -> AES-128-GCM ->
  header protection.

Проверить результат можно тем же анализатором, что разбирает образцы.

Примеры:
  ./gen-quic-initial.py                                   # hex в stdout
  ./gen-quic-initial.py --sni mail.ru --size 1250
  ./gen-quic-initial.py --out json                        # готовый элемент noises
  ./gen-quic-initial.py --self-test                       # сгенерировать и разобрать обратно
"""

import argparse
import json
import random
import struct
import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# RFC 9001 §5.2
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def rand_bytes(n: int) -> bytes:
    """Случайные байты. Через random, чтобы --seed делал результат воспроизводимым."""
    return random.randbytes(n)


DEFAULT_SNIS = [
    "www.google.com", "mail.ru", "www.youtube.com", "yandex.ru",
    "vk.com", "cloudflare.com", "www.cloudflare.com", "ok.ru",
]


# --------------------------------------------------------------------------
# HKDF / TLS 1.3 key schedule (RFC 5869, RFC 8446 §7.1)
# --------------------------------------------------------------------------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        h = hmac.HMAC(prk, hashes.SHA256())
        h.update(t + info + bytes([i]))
        t = h.finalize()
        out += t
        i += 1
    return out[:length]


def expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    return hkdf_expand(secret, info, length)


def initial_keys(dcid: bytes) -> dict:
    """Клиентские Initial-ключи, выведенные из DCID (RFC 9001 §5.2)."""
    initial_secret = hkdf_extract(INITIAL_SALT_V1, dcid)
    client_secret = expand_label(initial_secret, "client in", 32)
    return {
        "key": expand_label(client_secret, "quic key", 16),
        "iv": expand_label(client_secret, "quic iv", 12),
        "hp": expand_label(client_secret, "quic hp", 16),
    }


# --------------------------------------------------------------------------
# varint (RFC 9000 §16)
# --------------------------------------------------------------------------
def varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return (0x4000 | v).to_bytes(2, "big")
    if v < 0x40000000:
        return (0x80000000 | v).to_bytes(4, "big")
    return (0xC000000000000000 | v).to_bytes(8, "big")


def varint2(v: int) -> bytes:
    """Принудительно 2-байтовый varint — как в рабочих образцах поле length."""
    assert v < 0x4000
    return (0x4000 | v).to_bytes(2, "big")


# --------------------------------------------------------------------------
# TLS ClientHello
# --------------------------------------------------------------------------
def u16(v):
    return struct.pack(">H", v)


def ext(etype: int, body: bytes) -> bytes:
    return u16(etype) + u16(len(body)) + body


def quic_transport_parameters(scid: bytes) -> bytes:
    """RFC 9000 §18. Правдоподобный набор, как у браузера."""
    def tp(pid, value=b""):
        return varint(pid) + varint(len(value)) + value

    return b"".join([
        tp(0x0f, scid),                                   # initial_source_connection_id
        tp(0x01, varint(random.choice([30000, 60000]))),  # max_idle_timeout
        tp(0x03, varint(random.choice([1350, 1452, 1472]))),  # max_udp_payload_size
        tp(0x04, varint(15728640)),                       # initial_max_data
        tp(0x05, varint(6291456)),                        # initial_max_stream_data_bidi_local
        tp(0x06, varint(6291456)),                        # initial_max_stream_data_bidi_remote
        tp(0x07, varint(6291456)),                        # initial_max_stream_data_uni
        tp(0x08, varint(100)),                            # initial_max_streams_bidi
        tp(0x09, varint(103)),                            # initial_max_streams_uni
        tp(0x0b, varint(random.choice([20, 25, 26]))),    # max_ack_delay
        tp(0x0e, varint(random.choice([4, 8, 16]))),      # active_connection_id_limit
        tp(0x0c),                                         # disable_active_migration
    ])


def client_hello(sni: str, scid: bytes, alpn=("h3",)) -> bytes:
    """Валидный TLS 1.3 ClientHello для QUIC (RFC 8446 + RFC 9001 §8)."""
    priv = x25519.X25519PrivateKey.from_private_bytes(rand_bytes(32))
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    body = b""
    body += b"\x03\x03"                                   # legacy_version = TLS 1.2
    body += rand_bytes(32)                                # random
    body += b"\x00"                                       # legacy_session_id: пусто (RFC 9001 §8.4)
    suites = [0x1301, 0x1302, 0x1303]
    random.shuffle(suites)
    body += u16(len(suites) * 2) + b"".join(u16(s) for s in suites)
    body += b"\x01\x00"                                   # legacy_compression_methods = null

    # server_name
    sni_b = sni.encode()
    e_sni = ext(0x0000, u16(len(sni_b) + 3) + b"\x00" + u16(len(sni_b)) + sni_b)
    # supported_groups: x25519, secp256r1, secp384r1
    e_grp = ext(0x000a, u16(6) + u16(0x001d) + u16(0x0017) + u16(0x0018))
    # signature_algorithms
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    e_sig = ext(0x000d, u16(len(sigs) * 2) + b"".join(u16(s) for s in sigs))
    # ALPN
    a = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    e_alpn = ext(0x0010, u16(len(a)) + a)
    # supported_versions = TLS 1.3
    e_ver = ext(0x002b, b"\x02" + u16(0x0304))
    # psk_key_exchange_modes = psk_dhe_ke
    e_psk = ext(0x002d, b"\x01\x01")
    # key_share: x25519
    ks = u16(0x001d) + u16(32) + pub
    e_ks = ext(0x0033, u16(len(ks)) + ks)
    # quic_transport_parameters
    e_qtp = ext(0x0039, quic_transport_parameters(scid))
    # session_ticket (пустой) — обычный для браузера
    e_tkt = ext(0x0023, b"")

    exts = [e_sni, e_grp, e_sig, e_alpn, e_ver, e_psk, e_ks, e_qtp, e_tkt]
    random.shuffle(exts)
    ext_blob = b"".join(exts)
    body += u16(len(ext_blob)) + ext_blob

    return b"\x01" + len(body).to_bytes(3, "big") + body


# --------------------------------------------------------------------------
# Сборка QUIC Initial
# --------------------------------------------------------------------------
def build_initial(sni: str, size: int, dcid_len: int = None, pn: int = None,
                  pn_len: int = None, scid_len: int = 0) -> bytes:
    if dcid_len is None:
        dcid_len = random.choice([8, 8, 20])
    if pn is None:
        pn = random.choice([0, 0, 1])
    if pn_len is None:
        pn_len = random.choice([1, 2])
    dcid = rand_bytes(dcid_len)
    scid = rand_bytes(scid_len) if scid_len else b""
    keys = initial_keys(dcid)

    ch = client_hello(sni, scid)
    crypto = b"\x06" + varint(0) + varint(len(ch)) + ch

    hdr_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2  # token_len=1B, length=2B varint
    plain_len = size - hdr_len - pn_len - 16               # 16 = AEAD tag
    pad = plain_len - len(crypto)
    if pad < 0:
        raise SystemExit(
            f"--size {size} слишком мал: только ClientHello занимает "
            f"{len(crypto)} байт, нужно минимум {size - pad}")

    # PADDING до или после CRYPTO — в реальных образцах встречается и так, и так
    if random.random() < 0.5:
        plaintext = b"\x00" * pad + crypto
    else:
        plaintext = crypto + b"\x00" * pad

    first = 0xC0 | (pn_len - 1)                            # long|fixed|Initial|resv=00|pnlen
    pn_bytes = pn.to_bytes(pn_len, "big")
    header = (bytes([first]) + (1).to_bytes(4, "big")
              + bytes([dcid_len]) + dcid + bytes([scid_len]) + scid
              + varint(0)                                  # token length = 0
              + varint2(pn_len + len(plaintext) + 16))     # length
    aad = header + pn_bytes

    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    ct = AESGCM(keys["key"]).encrypt(nonce, plaintext, aad)

    # header protection (RFC 9001 §5.4)
    pn_off = len(header)
    protected = bytearray(header + pn_bytes + ct)
    sample = bytes(protected[pn_off + 4:pn_off + 20])
    enc = Cipher(algorithms.AES(keys["hp"]), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    protected[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        protected[pn_off + i] ^= mask[1 + i]

    out = bytes(protected)
    assert len(out) == size, (len(out), size)
    return out


def main():
    ap = argparse.ArgumentParser(description="Генератор настоящего QUIC Initial (RFC 9000/9001)")
    ap.add_argument("--sni", default=None,
                    help="SNI внутри ClientHello (по умолчанию случайный из списка популярных)")
    ap.add_argument("--size", type=int, default=1252,
                    help="общий размер пакета в байтах (по умолчанию 1252, как у рабочего образца)")
    ap.add_argument("--dcid-len", type=int, default=None, choices=[8, 20],
                    help="длина DCID: 8 или 20 (по умолчанию случайно)")
    ap.add_argument("--alpn", default="h3", help="ALPN, через запятую (по умолчанию h3)")
    ap.add_argument("--out", choices=["hex", "json"], default="hex",
                    help="hex — строка в stdout; json — готовый элемент noises")
    ap.add_argument("--delay", default="1-2", help="поле delay для json-вывода")
    ap.add_argument("--seed", type=int, default=None, help="зерно ГСЧ (для воспроизводимости)")
    ap.add_argument("--self-test", action="store_true",
                    help="сгенерировать и тут же разобрать обратно (проверка AEAD + ClientHello)")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    sni = args.sni or random.choice(DEFAULT_SNIS)

    pkt = build_initial(sni, args.size, dcid_len=args.dcid_len)

    if args.self_test:
        ok = self_test(pkt, sni)
        sys.exit(0 if ok else 1)

    if args.out == "json":
        print(json.dumps({"type": "hex", "packet": pkt.hex(), "delay": args.delay},
                         ensure_ascii=False))
    else:
        print(pkt.hex())


# --------------------------------------------------------------------------
# Самопроверка: разбираем собственный пакет как посторонний наблюдатель
# --------------------------------------------------------------------------
def self_test(pkt: bytes, expect_sni: str) -> bool:
    def rv(buf, off):
        b0 = buf[off]
        n = 1 << (b0 >> 6)
        v = b0 & 0x3F
        for i in range(1, n):
            v = (v << 8) | buf[off + i]
        return v, off + n

    o = 1
    ver = pkt[o:o + 4].hex(); o += 4
    dl = pkt[o]; o += 1
    dcid = pkt[o:o + dl]; o += dl
    sl = pkt[o]; o += 1
    o += sl
    tl, o = rv(pkt, o); o += tl
    ln, o = rv(pkt, o)
    pn_off = o
    print(f"размер={len(pkt)} version=0x{ver} dcid_len={dl} length={ln} "
          f"остаток={len(pkt) - o} -> {'длина СОВПАДАЕТ' if ln == len(pkt) - o else 'ДЛИНА НЕ СХОДИТСЯ'}")

    k = initial_keys(dcid)
    enc = Cipher(algorithms.AES(k["hp"]), modes.ECB()).encryptor()
    mask = enc.update(pkt[pn_off + 4:pn_off + 20]) + enc.finalize()
    fb = pkt[0] ^ (mask[0] & 0x0F)
    pl = (fb & 3) + 1
    pnb = bytes(pkt[pn_off + i] ^ mask[1 + i] for i in range(pl))
    pn = int.from_bytes(pnb, "big")
    print(f"после снятия HP: первый байт=0x{fb:02x} ({fb:08b}) type={(fb >> 4) & 3} "
          f"reserved={(fb >> 2) & 3} pn_len={pl} pn={pn}")
    if (fb & 0xF0) != 0xC0 or ((fb >> 2) & 3) != 0:
        print("  ОШИБКА: биты заголовка невалидны")
        return False

    hdr = bytearray(pkt[:pn_off + pl]); hdr[0] = fb
    hdr[pn_off:pn_off + pl] = pnb
    nonce = bytes(a ^ b for a, b in zip(k["iv"], pn.to_bytes(12, "big")))
    try:
        plain = AESGCM(k["key"]).decrypt(nonce, pkt[pn_off + pl:pn_off + ln], bytes(hdr))
    except Exception as e:
        print(f"  ОШИБКА: AEAD не сошёлся: {e}")
        return False
    print(f"AEAD: OK, plaintext={len(plain)} байт")

    i = 0
    ch = None
    while i < len(plain):
        if plain[i] == 0:
            i += 1
            continue
        if plain[i] == 0x06:
            i += 1
            _off, i = rv(plain, i)
            cl, i = rv(plain, i)
            ch = plain[i:i + cl]
            break
        print(f"  ОШИБКА: неожиданный фрейм 0x{plain[i]:02x}")
        return False
    if ch is None or ch[0] != 0x01:
        print("  ОШИБКА: CRYPTO/ClientHello не найден")
        return False

    j = 4 + 2 + 32
    j += 1 + ch[j]
    cs = struct.unpack(">H", ch[j:j + 2])[0]; j += 2 + cs
    j += 1 + ch[j]
    el = struct.unpack(">H", ch[j:j + 2])[0]; j += 2
    end = j + el
    sni = alpn = None
    names = []
    while j < end:
        et = struct.unpack(">H", ch[j:j + 2])[0]
        ln2 = struct.unpack(">H", ch[j + 2:j + 4])[0]
        d = ch[j + 4:j + 4 + ln2]
        j += 4 + ln2
        names.append(et)
        if et == 0:
            n = struct.unpack(">H", d[3:5])[0]
            sni = d[5:5 + n].decode()
        if et == 0x10:
            p, alpn = 2, []
            while p < len(d):
                alpn.append(d[p + 1:p + 1 + d[p]].decode())
                p += 1 + d[p]
    print(f"ClientHello: OK, SNI={sni!r} ALPN={alpn} extensions={names}")
    if sni != expect_sni:
        print(f"  ОШИБКА: SNI не совпал (ждали {expect_sni!r})")
        return False
    print("САМОПРОВЕРКА ПРОЙДЕНА")
    return True


if __name__ == "__main__":
    main()
