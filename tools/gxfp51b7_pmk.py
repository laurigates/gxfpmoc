#!/usr/bin/env python3
"""Build a GXFP51B7 (GF_9ELIBE_EC_19xxx firmware) PMK-write payload for command 0xE0.

Format reconstructed from gfspi.dll 1.1.151.18:
  _ProductionWritePmk (FUN_18003ed3c)   wire framing, data type 0xD -> wire type 0xF
  gdx_aes_decrypt     (FUN_180049938)   container (mbedTLS crypt_and_hash style)
  FUN_180049274                         static key from ASCII "Goodix"
  tls_get_pmk (WBDI_Enclave)            plaintext: type BE16, len BE32, PMK

Container = IV(16) | AES-128-CBC(plaintext, zero padded) | HMAC-SHA256(ciphertext)
  digest   = SHA256(IV || 48 zero bytes || goodix_key16)   (one round)
  aes key  = digest[:16]; hmac key = digest (32 bytes)
  IV[15] low nibble = plaintext length mod 16
Wire     = u32le(0xF) | u32le(len(container)) | container

The Windows host also RSA-verifies a 256-byte signature appended to the container,
but the signature is stripped before sending, so the MCU never sees it.

Usage:
  gxfp51b7_pmk.py build --pmk-out psk_raw32.bin [--pmk-in psk_raw32.bin]  -> prints payload hex
  gxfp51b7_pmk.py selftest
"""
import argparse
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PMK_TYPE_PLAIN = 0x000D
PMK_TYPE_WIRE = 0x0000000F


def _crc32_msb(data: bytes) -> int:
    """FUN_180049560: MSB-first CRC-32 (poly=0x04C11DB7, init=0xFFFFFFFF, no reflect/xorout)."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7 if (crc & 0x80000000) else (crc << 1)) & 0xFFFFFFFF
    return crc


def _aes_zero_block(mode: int, triple: bytes) -> bytes:
    """FUN_18004907c: AES-CBC with all-zero key/IV over (triple || 0xCC * 13), first 2 bytes."""
    key_len, is_enc = {0: (16, False), 1: (16, True), 2: (32, False), 3: (24, True)}[mode]
    c = Cipher(algorithms.AES(bytes(key_len)), modes.CBC(bytes(16)))
    ctx = c.encryptor() if is_enc else c.decryptor()
    return (ctx.update(triple + b"\xcc" * 13) + ctx.finalize())[:2]


def goodix_rortable() -> bytes:
    """FUN_180049274 stage 1: abStack_28[6i+j] = ROR8('Goodix'[j], 2i+1), i in 0..3 (24 bytes)."""
    out = bytearray()
    for i in range(4):
        rot = 2 * i + 1
        for c in b"Goodix":
            out.append(((c >> rot) | (c << (8 - rot))) & 0xFF)
    return bytes(out)


def goodix_key() -> bytes:
    """FUN_180049274 / FUN_180058ce0: transform 8x 3-byte triples of goodix_rortable() into 16B master key."""
    tab = goodix_rortable()
    t = [tab[3 * k : 3 * k + 3] for k in range(8)]
    crc = _crc32_msb(t[6])
    return b"".join([
        hashlib.sha256(t[0]).digest()[:2],                                  # T0: SHA-256
        _aes_zero_block(0, t[1]),                                           # T1: AES-128-CBC-Dec
        _aes_zero_block(1, t[2]),                                           # T2: AES-128-CBC-Enc
        _aes_zero_block(2, t[3]),                                           # T3: AES-256-CBC-Dec
        _aes_zero_block(3, t[4]),                                           # T4: AES-192-CBC-Enc
        hmac.new(b"123456" + bytes(10), t[5], hashlib.sha256).digest()[:2], # T5: HMAC-SHA256
        bytes([(crc >> 24) & 0xFF, (crc >> 16) & 0xFF]),                    # T6: CRC-32 MSB top 2B
        hashlib.sha256(t[7]).digest()[:2],                                  # T7: SHA-256
    ])


def default_iv(plain_len: int) -> bytes:
    """GoodixDataAesEncrypt (FUN_1800516a0): SHA256(u32le(len) || '123GOODIX')[:16], low nibble = len & 0xF."""
    raw = bytearray(hashlib.sha256(struct.pack("<I", plain_len) + b"123GOODIX").digest()[:16])
    raw[15] = (raw[15] & 0xF0) | (plain_len & 0x0F)
    return bytes(raw)


def _keys(iv: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(iv + bytes(48) + goodix_key()).digest()
    return digest[:16], digest


def encrypt(plain: bytes, iv_seed: bytes | None = None) -> bytes:
    if iv_seed is None:
        iv = default_iv(len(plain))
    else:
        raw = bytearray(iv_seed)
        raw[15] = (raw[15] & 0xF0) | (len(plain) & 0x0F)
        iv = bytes(raw)
    aes_key, mac_key = _keys(iv)
    pad_len = 16 - (len(plain) % 16)
    padded = plain + bytes(pad_len)
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct + hmac.new(mac_key, ct, hashlib.sha256).digest()


def decrypt(container: bytes) -> bytes:
    iv, ct, tag = container[:16], container[16:-32], container[-32:]
    aes_key, mac_key = _keys(iv)
    if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), tag):
        raise ValueError("HMAC check failed")
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    # mbedTLS MBEDTLS_PADDING_ZEROS (get_zeros_padding, FUN_180036e80) strips trailing zeros in final block
    head, tail = padded[:-16], padded[-16:].rstrip(b"\x00")
    return head + tail


def pmk_plaintext(pmk: bytes) -> bytes:
    return struct.pack(">HI", PMK_TYPE_PLAIN, len(pmk)) + pmk


def wire_payload(pmk: bytes) -> bytes:
    container = encrypt(pmk_plaintext(pmk))
    return struct.pack("<II", PMK_TYPE_WIRE, len(container)) + container


def selftest() -> None:
    # Stage 1: ROR8("Goodix", 2i+1) = 24-byte intermediate table
    assert goodix_rortable().hex() == "a3b7b732b43ce8eded8c2d0f3a7b7b234bc38ededec8d2f0"
    # Stage 2: 8 triple transforms -> 16-byte static master key
    assert goodix_key().hex() == "5cba6e25819518de2d53e96dc0347ab0", goodix_key().hex()
    while (pmk := os.urandom(32))[-1] == 0:
        pass
    pt = pmk_plaintext(pmk)
    assert decrypt(encrypt(pt)) == pt
    payload = wire_payload(pmk)
    wtype, wlen = struct.unpack_from("<II", payload)
    assert wtype == 0xF and wlen == len(payload) - 8 == 16 + 48 + 32
    print("selftest ok; goodix key", goodix_key().hex())


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--pmk-in", help="existing 32-byte PMK (default: random)")
    b.add_argument("--pmk-out", required=True, help="where to write the PMK")
    sub.add_parser("selftest")
    a = ap.parse_args()

    if a.cmd == "selftest":
        selftest()
        return

    if a.pmk_in:
        pmk = open(a.pmk_in, "rb").read()
    else:
        # The MCU may zero-unpad: avoid a trailing 0x00.
        while (pmk := os.urandom(32))[-1] == 0:
            pass
    if len(pmk) != 32:
        sys.exit("PMK must be 32 bytes")
    fd = os.open(a.pmk_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, pmk)
    os.close(fd)
    print(wire_payload(pmk).hex())
    print("sha256(pmk) =", hashlib.sha256(pmk).hexdigest(), file=sys.stderr)


if __name__ == "__main__":
    main()
