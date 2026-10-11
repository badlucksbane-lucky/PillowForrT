#!/usr/bin/env python3
"""Tests scripts/retro/pi-serve.py: the listing, files, names that must not work, symlinks, methods. Usage: python3 -I scripts/dev/pi-serve-test.py (exit 1 on failure)"""
import http.client, importlib.util, json, os, sys, tempfile, threading
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("piserve", os.path.join(here, "../retro/pi-serve.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fails = []
def check(name, ok, got=None):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  got: %r" % (got,)))
    if not ok: fails.append(name)
d = tempfile.mkdtemp()
for sub in ("cores", "roms"): os.makedirs(os.path.join(d, sub))
def w(rel, data=b"x"): open(os.path.join(d, rel), "wb").write(data)
w("cores/fceumm.js", b"js"); w("cores/fceumm.wasm", b"\0asm"); w("roms/Zelda Test.nes", b"NES\x1a" * 1000); w("roms/notes txt/..", b"") if False else None
w("roms/.hidden.nes"); w("roms/bad;name.nes"); os.mkdir(os.path.join(d, "roms", "folder.nes"))
open(os.path.join(d, "secret.txt"), "w").write("SECRET"); os.symlink(os.path.join(d, "secret.txt"), os.path.join(d, "roms", "link.nes"))
srv = m.make_server(d, "127.0.0.1", 0); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
def req(method, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5); c.request(method, path); r = c.getresponse(); b = r.read(); c.close(); return r.status, b, r
s, b, r = req("GET", "/list.json"); l = json.loads(b)
check("the listing has cores and ROMs, only plain regular files", s == 200 and l == {"cores": ["fceumm.js", "fceumm.wasm"], "roms": ["Zelda Test.nes"]}, l)
s, b, r = req("GET", "/roms/Zelda%20Test.nes")
check("a ROM comes out whole, with its length", s == 200 and b == b"NES\x1a" * 1000 and r.getheader("Content-Length") == "4000", (s, len(b)))
check("a core comes out", req("GET", "/cores/fceumm.wasm")[1] == b"\0asm")
check("HEAD gives the length and no body", (lambda x: x[0] == 200 and x[1] == b"" and x[2].getheader("Content-Length") == "4000")(req("HEAD", "/roms/Zelda%20Test.nes")))
for p in ["/", "/roms/", "/roms", "/cores/nope.js", "/roms/.hidden.nes", "/roms/bad;name.nes", "/roms/folder.nes", "/roms/link.nes", "/roms/..%2fsecret.txt", "/roms/%2e%2e/secret.txt",
          "/secret.txt", "/roms/a/b.nes", "/other/x.nes", "/roms/Zelda%20Test.nes/", "/..%2f..%2fetc%2fpasswd", "/roms/../secret.txt"]:
    s, b, r = req("GET", p)
    check("%s is a 404 and leaks nothing" % p, s == 404 and b"SECRET" not in b, (s, b[:40]))
for meth in ("POST", "PUT", "DELETE"):
    check("%s is refused" % meth, req(meth, "/roms/Zelda%20Test.nes")[0] == 405)
srv.shutdown()
print("\n%d failed" % len(fails) if fails else "\nall ok"); sys.exit(1 if fails else 0)
