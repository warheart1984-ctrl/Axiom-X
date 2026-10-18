#!/usr/bin/env python3
"""Drive a running Axiom-X QEMU VM through its monitor socket.

Types a command on the emulated PS/2 keyboard (QEMU `sendkey`), then saves
a screenshot of the VGA screen (`screendump`, converted to PNG with only
the standard library). Used with `SHELL_INPUT=... sh qemu-boot.sh`.

    python3 vm-keys.py <monitor-socket> <wait-seconds> "<text to type>" <out.png>

Characters are mapped to QEMU key names (US layout; uppercase and shifted
symbols use shift-<key>); a final Enter is sent after the text.
"""
import socket
import struct
import sys
import time
import zlib

KEYS = {" ": "spc", "-": "minus", "=": "equal", ".": "dot", ",": "comma", "/": "slash",
        ";": "semicolon", "'": "apostrophe", "[": "bracket_left", "]": "bracket_right",
        "\\": "backslash", "`": "grave_accent"}
SHIFTED = {"+": "equal", "_": "minus", ":": "semicolon", "?": "slash", "!": "1", "\"": "apostrophe"}


def key_name(c):
    if c.isalpha():
        return ("shift-" if c.isupper() else "") + c.lower()
    if c.isdigit():
        return c
    if c in KEYS:
        return KEYS[c]
    if c in SHIFTED:
        return "shift-" + SHIFTED[c]
    raise ValueError("no key for %r" % c)


def monitor(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(100):
        try:
            s.connect(path)
            break
        except OSError:
            time.sleep(0.2)
    else:
        raise SystemExit("cannot connect to the QEMU monitor at " + path)
    s.settimeout(2)
    return s


def command(s, cmd):
    s.sendall((cmd + "\n").encode())
    time.sleep(0.15)
    try:
        s.recv(65536)
    except socket.timeout:
        pass


def ppm_to_png(ppm_path, png_path):
    data = open(ppm_path, "rb").read()
    # P6\n<w> <h>\n<max>\n<rgb...>
    parts = data.split(b"\n", 3)
    w, h = map(int, parts[1].split())
    rgb = parts[3]
    raw = b"".join(b"\x00" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    open(png_path, "wb").write(png)
    return w, h


def main():
    sock_path, wait_s, text, out_png = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
    s = monitor(sock_path)
    time.sleep(wait_s)
    for c in text:
        command(s, "sendkey " + key_name(c))
    command(s, "sendkey ret")
    time.sleep(3)
    ppm = out_png[:-4] + ".ppm"
    command(s, "screendump " + ppm)
    time.sleep(1)
    w, h = ppm_to_png(ppm, out_png)
    print("typed %r on the PS/2 keyboard; screenshot %dx%d -> %s" % (text, w, h, out_png))


if __name__ == "__main__":
    main()
