#!/usr/bin/env python3
"""Fixed-body HTTP upstream for an egress evidence capture.

Every request gets the same short JSON body. The proxy hashes that body
(not the HTTP status line) and the kernel hashes the same bytes, so a
boot with no gateway and no API key still produces a comparable pair of
`response sha256` lines.

Usage: python3 tools/egress-stub.py [port]   (default 8081)
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b'{"stub":"axiom-x-egress","echo":true}\n'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._reply()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n:
            self.rfile.read(n)
        self._reply()

    def _reply(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        sys.stderr.write("[egress-stub] " + (fmt % args) + "\n")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
