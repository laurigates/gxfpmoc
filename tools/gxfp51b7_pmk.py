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


def goodix_key() -> bytes:
    """FUN_180049274: key[6i+j] = ROR8('Goodix'[j], 2i+1), i in 0..3; first 16 bytes used."""
    out = bytearray()
    for i in range(4):
        rot = 2 * i + 1
        for c in b"Goodix":
            out.append(((c >> rot) | (c << (8 - rot))) & 0xFF)
    return bytes(out[:16])


def _keys(iv: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(iv + bytes(48) + goodix_key()).digest()
    return digest[:16], digest


def encrypt(plain: bytes, iv_seed: bytes | None = None) -> bytes:
    raw = bytearray(iv_seed if iv_seed is not None else os.urandom(16))
    raw[15] = (raw[15] & 0xF0) | (len(plain) & 0x0F)
    iv = bytes(raw)
    aes_key, mac_key = _keys(iv)
    padded = plain + bytes(-len(plain) % 16)
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
    lastn = iv[15] & 0x0F
    return padded[: len(padded) - (16 - lastn) % 16] if lastn else padded


def pmk_plaintext(pmk: bytes) -> bytes:
    return struct.pack(">HI", PMK_TYPE_PLAIN, len(pmk)) + pmk


def wire_payload(pmk: bytes) -> bytes:
    container = encrypt(pmk_plaintext(pmk))
    return struct.pack("<II", PMK_TYPE_WIRE, len(container)) + container


def selftest() -> None:
    # Hand-checked: ROR8("Goodix", 1) = a3 b7 b7 32 b4 3c; ROR8('G', 3) = e8.
    assert goodix_key()[:7].hex() == "a3b7b732b43ce8", goodix_key().hex()
    pmk = os.urandom(32)
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
