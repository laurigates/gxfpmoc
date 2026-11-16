#!/usr/bin/env python3
"""Send raw Goodix commands over /dev/gxfp (GXFP51B7 transport) and dump the replies.

No TLS: only commands the MCU answers in the clear (firmware version, register read).

Usage: sudo python3 -I tools/gxfp51b7_probe.py [--dev /dev/gxfp] [--timeout 2.0]
"""
import argparse
import fcntl
import os
import select
import struct
import time

GXFP_IOCTL_GET_INFO = 0x80103F01  # _IOR(0x3F, 0x01, struct gxfp_info)
REC_HDR = struct.Struct("<IIQ")  # len, reserved, timestamp_ns
MP_TYPE_CMD = 0x0A
CHECKSUM_SEED = 0xAA


def goodix_frame(cmd: int, payload: bytes) -> bytes:
    decl = 1 + len(payload)
    body = bytes([cmd, decl & 0xFF, decl >> 8]) + payload
    return body + bytes([(CHECKSUM_SEED - sum(body)) & 0xFF])


def mp_frame(mp_type: int, payload: bytes) -> bytes:
    h0, n = (mp_type & 0x0F) << 4, len(payload)
    hdr = bytes([h0, n & 0xFF, n >> 8])
    return hdr + bytes([sum(hdr) & 0xFF]) + payload


def get_info(fd: int):
    buf = bytearray(16)
    fcntl.ioctl(fd, GXFP_IOCTL_GET_INFO, buf)
    return struct.unpack("<IIII", buf)


def drain(fd: int, rec_size: int, timeout: float):
    end = time.monotonic() + timeout
    while (left := end - time.monotonic()) > 0:
        r, _, _ = select.select([fd], [], [], left)
        if not r:
            break
        rec = os.read(fd, rec_size)
        length, _, ts = REC_HDR.unpack_from(rec)
        data = rec[REC_HDR.size:REC_HDR.size + length]
        mp_type, mp_len = data[0] >> 4, data[1] | data[2] << 8
        body = data[4:4 + mp_len]
        cmd = body[0] if body else None
        print(f"  rx t={ts / 1e9:.3f} mp_type={mp_type:#x} len={mp_len} "
              f"cmd={cmd if cmd is None else hex(cmd)} body={body[:48].hex(' ')}")
        yield mp_type, body


def request(fd: int, rec_size: int, cmd: int, payload: bytes, timeout: float):
    tx = mp_frame(MP_TYPE_CMD, goodix_frame(cmd, payload))
    print(f"tx cmd={cmd:#x} {tx.hex(' ')}")
    os.write(fd, tx)
    return list(drain(fd, rec_size, timeout))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="/dev/gxfp")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--cmd", type=lambda s: int(s, 16),
                    help="send one raw command instead of the default probe (hex)")
    ap.add_argument("--payload", default="", help="payload for --cmd, hex")
    a = ap.parse_args()

    fd = os.open(a.dev, os.O_RDWR)
    variant, tx_max, rx_max, _ = get_info(fd)
    rec_size = REC_HDR.size + rx_max
    print(f"variant={variant} tx_max={tx_max:#x} rx_max={rx_max:#x}")

    if a.cmd is not None:
        request(fd, rec_size, a.cmd, bytes.fromhex(a.payload), a.timeout)
    else:
        request(fd, rec_size, 0xA8, b"\x00\x00", a.timeout)               # firmware version
        request(fd, rec_size, 0x82, b"\x00\x00\x00\x04\x00", a.timeout)   # reg 0, 4 bytes: chip id
    os.close(fd)


if __name__ == "__main__":
    main()
