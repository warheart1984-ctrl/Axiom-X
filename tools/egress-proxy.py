#!/usr/bin/env python3
"""Axiom-X egress proxy: bridges the kernel's governed COM2 channel to
llm-gateway (or any HTTP endpoint).

Protocol (both directions, little-endian length):
  guest -> host:  b"AXEG" + u64 len + payload   (the HTTP request bytes)
  host -> guest:  b"RESP" + u64 len + payload   (the HTTP response bytes)

QEMU wiring: `-serial tcp:127.0.0.1:4445,server,nowait` (COM2).
Every petition the guest makes is a governed, ledgered action; this proxy
is the only door out, so policy (rate limits, allowlists) can live here.
"""

import os
import socket
import struct
import sys
import urllib.request

LISTEN = ("127.0.0.1", 4445)
UPSTREAM = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
# A guest declaring more than this in one frame is buggy or hostile —
# the protocol has no reason to go bigger.
MAX_FRAME = 64 * 1024
# Upstream bound: keep it under the guest's 10 s channel deadline so a
# slow upstream reads as a proxy error, not a hung petition.
UPSTREAM_TIMEOUT = 8


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("guest closed")
        buf += chunk
    return buf


# Path allowlist: petitions may only ask for these upstream prefixes.
# A right the guest holds (NET) should still buy a *bounded* reach.
ALLOWED_PREFIXES = ("GET /v1/", "POST /v1/", "GET /models", "POST /chat")


def allowed(payload: bytes) -> bool:
    first = payload.split(b"\r\n", 1)[0]
    return any(first.startswith(p.encode()) for p in ALLOWED_PREFIXES)


# Tenant credential stays host-side: the guest petitions without secrets,
# the proxy attaches `x-api-key` for the gateway's benchmark tenant.
GATEWAY_KEY = os.environ.get("EGRESS_GATEWAY_KEY", "")


def parse_request(payload: bytes):
    """Split 'METHOD PATH HTTP/1.1\\r\\nheaders\\r\\n\\r\\nbody' -> (method, path, body)."""
    try:
        head, _, body = payload.partition(b"\r\n\r\n")
        request_line = head.split(b"\r\n", 1)[0].decode()
        method, path, _ = request_line.split(" ", 2)
        return method, path, body
    except ValueError:
        return None, None, b""


def forward(payload: bytes) -> bytes:
    """Send the request to the upstream and return response bytes.

    The guest sends an HTTP-ish request; we translate it into a real HTTP
    call against the configured upstream, injecting the tenant credential.
    A non-200 or unreachable upstream still gets a framed reply: the
    petition was governed; the failure is evidence too.
    """
    if not allowed(payload):
        return b"HTTP/1.1 403 Proxy Denied\r\n\r\npath not in allowlist"
    method, path, body = parse_request(payload)
    if not method or not path.startswith("/"):
        return b"HTTP/1.1 400 Bad Request\r\n\r\nunparseable request line"
    url = UPSTREAM.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if GATEWAY_KEY:
        headers["x-api-key"] = GATEWAY_KEY
    try:
        req = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        # A real status from the gateway (401/402/429...) is data, not failure.
        return e.read() or f"HTTP {e.code}".encode()
    except Exception as e:
        return f"HTTP/1.1 503 Proxy Error\r\n\r\n{e}".encode()


import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def log_line(line: str):
    # The proxy injects the tenant key — it must never reach this log.
    # Redact rather than trust the call sites.
    if GATEWAY_KEY and GATEWAY_KEY in line:
        line = line.replace(GATEWAY_KEY, "***")
    print(line, flush=True)


def serve(conn: socket.socket):
    conn.settimeout(30)
    while True:
        magic = read_exact(conn, 4)
        if magic != b"AXEG":
            raise ValueError(f"bad magic {magic!r}")
        (n,) = struct.unpack("<Q", read_exact(conn, 8))
        if n == 0 or n > MAX_FRAME:
            raise ValueError(f"bad frame length {n}")
        payload = read_exact(conn, n)
        resp = forward(payload)
        log_line(
            f"[egress-proxy] petition sha256 {sha256_hex(payload)}.. "
            f"-> {len(resp)}B response sha256 {sha256_hex(resp)}.."
        )
        conn.sendall(b"RESP" + struct.pack("<Q", len(resp)) + resp)


def main():
    # QEMU's `-serial tcp:...,server` listens; the proxy connects as client.
    print(f"[egress-proxy] connecting to QEMU at {LISTEN}, upstream {UPSTREAM}", flush=True)
    while True:
        try:
            conn = socket.create_connection(LISTEN, timeout=10)
        except OSError:
            continue
        print("[egress-proxy] connected to guest COM2", flush=True)
        try:
            serve(conn)
        except Exception as e:
            print(f"[egress-proxy] session ended: {e}", flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
