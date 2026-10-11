#!/usr/bin/env python3
"""Serve a Retro folder (cores/ and roms/) to the box, read only.

The box (retro.go) lists /list.json and reads /cores/<file> and /roms/<file> from here when a file is not on the box itself. Put this computer's address in the box's
/data/proxy/retro/upstream, for example http://192.168.1.2:8765 . Only regular files with plain names in those two folders are served; there is no directory listing,
no symlink following, no other method than GET and HEAD.

Usage: pi-serve.py [--dir ~/retro-share] [--bind 192.168.1.2] [--port 8765]
"""
import argparse, json, os, re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()'+,&-]{0,120}$")  # the same shape retro.go accepts
SUBS = ("cores", "roms")


def files(root, sub):
    try:
        names = os.listdir(os.path.join(root, sub))
    except OSError:
        return []
    out = []
    for n in sorted(names):
        p = os.path.join(root, sub, n)
        if NAME.match(n) and ".." not in n and os.path.isfile(p) and not os.path.islink(p):
            out.append(n)
    return out


class Handler(BaseHTTPRequestHandler):
    root = "."
    server_version = "retro-share"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/plain", length=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body) if length is None else length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _serve(self, head):
        path = unquote(self.path.split("?", 1)[0])
        if path == "/list.json":
            body = json.dumps({"cores": files(self.root, "cores"), "roms": files(self.root, "roms")}).encode()
            self._send(200, body, "application/json")
            if not head:
                self.wfile.write(body)
            return
        parts = path.split("/")
        if len(parts) != 3 or parts[0] != "" or parts[1] not in SUBS or parts[2] not in files(self.root, parts[1]):
            self._send(404, b"not found\n")
            if not head:
                self.wfile.write(b"not found\n")
            return
        p = os.path.join(self.root, parts[1], parts[2])
        size = os.path.getsize(p)
        self._send(200, b"", "application/octet-stream", length=size)
        if head:
            return
        with open(p, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_GET(self):
        self._serve(False)

    def do_HEAD(self):
        self._serve(True)

    def _no(self):
        self._send(405, b"read only\n")
        self.wfile.write(b"read only\n")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _no


def make_server(root, bind, port):
    h = type("H", (Handler,), {"root": os.path.abspath(os.path.expanduser(root))})
    return ThreadingHTTPServer((bind, port), h)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="~/retro-share")
    ap.add_argument("--bind", default="192.168.1.2")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    for sub in SUBS:
        os.makedirs(os.path.join(os.path.expanduser(a.dir), sub), exist_ok=True)
    srv = make_server(a.dir, a.bind, a.port)
    print("serving %s on http://%s:%d" % (os.path.expanduser(a.dir), a.bind, a.port), flush=True)
    srv.serve_forever()
