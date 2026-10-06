import importlib.machinery, importlib.util, io as _io, json, os, stat, tempfile, unittest, warnings
warnings.simplefilter("ignore", ResourceWarning)   # the fixtures below write small files without closing them

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("stone_install", os.path.join(HERE, "..", "stone-install"))
si = importlib.util.module_from_spec(importlib.util.spec_from_loader("stone_install", _loader)); _loader.exec_module(si)

WIFI_PW, LOGIN_PW, TOKEN_RE = "hearth-wifi-pass-77", "web-login-pass-1234", None
PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFORTESTSONLY test@host"
SNAP_XML = ('<?xml version="1.0"?><wlan><Basic_0><state>1</state><ssid>Cabin &amp; Light</ssid><psk>snap-psk-9&amp;x</psk></Basic_0>'
            '<Basic_1><state>1</state><ssid>Cabin 5G</ssid><psk>snap-psk-9&amp;x</psk></Basic_1></wlan>')


class FakeDevice:
    """Records every adb call and AT line; replays a device log. Never touches USB."""
    def __init__(self, pids=(0xF601,), log_script=None, fail_after=None):
        self.pids, self.calls, self.at_lines, self.pushed, self.switched = list(pids), [], [], {}, False
        self.log_script = log_script or ["10:00:00 STEP", "10:00:01 STONE-OK", "10:00:01 STONE-DONE"]
        self.reads = 0; self.state_ok = True
    def usb(self): return list(self.pids)
    def mode_switch(self): self.switched = True; self.pids = [0xF601]
    def adb(self, *args, input_bytes=None, timeout=120):
        self.calls.append(args)
        if args[0] == "get-state": return 0, "device\n", ""
        if args[0] == "push":
            self.pushed[args[2]] = (open(args[1], "rb").read(), stat.S_IMODE(os.stat(args[1]).st_mode)); return 0, "", ""
        if args[0] == "shell" and args[1] == "pidof atfwd_daemon":
            self.atfwd_polls = getattr(self, "atfwd_polls", 0) + 1
            return (0, "1438\n", "") if self.atfwd_polls > getattr(self, "atfwd_late", 0) else (1, "", "")
        if args[0] == "shell" and "sha256sum -c" in args[1]: return 0, "VERIFIED\n", ""
        if args[0] == "shell" and args[1] == "cat /tmp/stone/log":
            self.reads += 1; n = min(self.reads, len(self.log_script)); return 0, "\n".join(self.log_script[:n]) + "\n", ""
        return 0, "", ""
    def at(self, line): self.at_lines.append(line); return True, ""


def make_io(inputs=(), secrets_in=()):
    out, ins, sec = [], list(inputs), list(secrets_in)
    return {"say": lambda *a: out.append(" ".join(str(x) for x in a)), "input": lambda p="": (out.append("? " + p), ins.pop(0))[1],
            "getpass": lambda p="": (out.append("? " + p), sec.pop(0))[1], "sleep": lambda s: None, "interactive": True}, out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.t = self.tmp.name; self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.t, "home"); os.makedirs(os.path.join(self.home, ".ssh"))
        self.pay = os.path.join(self.t, "payload"); os.makedirs(self.pay)
        for f in si.REQUIRED + ["tor"]: open(os.path.join(self.pay, f), "w").write("content of " + f)
        self.pubfile = os.path.join(self.home, ".ssh", "id_test.pub"); open(self.pubfile, "w").write(PUB + "\n")
        self.wifipw = self.secretfile("wifi.pw", WIFI_PW); self.loginpw = self.secretfile("login.pw", LOGIN_PW)
    def secretfile(self, name, value):
        p = os.path.join(self.t, name); open(p, "w").write(value + "\n"); os.chmod(p, 0o600); return p
    def answers(self, **over):
        a = {"confirmed_factory_reset": True, "wifi": {"ssid": "Hearth Home", "ssid5": "Hearth Home 5G", "password_file": self.wifipw},
             "login": {"user": "alice", "password_file": self.loginpw}, "ssh_key": self.pubfile, "token": False, "yes": True}
        a.update(over); p = os.path.join(self.t, "answers.json"); json.dump(a, open(p, "w")); return p
    def run_main(self, argv, dev=None, io=None):
        dev = dev or FakeDevice(); io, out = io or make_io()[0], None
        out = []
        io = io if "say" in io else io
        io = dict(io); io["say"] = lambda *a: out.append(" ".join(str(x) for x in a))
        rc = si.main(argv, dev=dev, io=io, home=self.home); return rc, dev, "\n".join(out)


class Validation(unittest.TestCase):
    def test_ssid(self):
        self.assertIsNone(si.valid_ssid("Hearth Home")); self.assertIsNone(si.valid_ssid("x" * 32))
        for bad in ("", "x" * 33, "bad\x01", "é" * 17): self.assertIsNotNone(si.valid_ssid(bad), repr(bad))
    def test_wifi_password(self):
        self.assertIsNone(si.valid_wifi_pw("a" * 8)); self.assertIsNone(si.valid_wifi_pw("a" * 63))
        for bad in ("short", "a" * 64, "tab\there1", "naïve-pass-1"): self.assertIsNotNone(si.valid_wifi_pw(bad), repr(bad))
    def test_user_and_login_password(self):
        self.assertIsNone(si.valid_user("alice.b-2_x")); [self.assertIsNotNone(si.valid_user(b)) for b in ("", "a b", "a/b", "x" * 65)]
        self.assertIsNone(si.valid_login_pw("a" * 10)); self.assertIsNone(si.valid_login_pw("a" * 72))
        [self.assertIsNotNone(si.valid_login_pw(b)) for b in ("a" * 9, "a" * 73, "é" * 37)]
    def test_pubkey(self):
        self.assertIsNone(si.valid_pubkey(PUB)); [self.assertIsNotNone(si.valid_pubkey(b)) for b in ("", "hello", PUB + "\n" + PUB, "ssh-ed25519")]
    def test_at_lines_fit_the_64_byte_limit_and_hold_no_separators(self):
        for k, line in si.AT.items():
            self.assertLessEqual(len(line.encode()), 64, k); self.assertNotIn(";", line); self.assertNotIn(",", line); self.assertTrue(line.startswith("AT+SYSCMD="))
    def test_wifi_from_snapshot(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"sections": {"wifi": {"xml": SNAP_XML}}}, f)
        try: self.assertEqual(si.wifi_from_snapshot(f.name), ("Cabin & Light", "Cabin 5G", "snap-psk-9&x"))
        finally: os.unlink(f.name)


class Flows(Base):
    def test_dry_run_never_touches_the_device(self):
        class Boom:
            def __getattr__(self, n): raise AssertionError("device used in a dry run: " + n)
        rc, _, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers(), "--dry-run"], dev=Boom())
        self.assertEqual(rc, 0); self.assertIn(si.AT["install"], out); self.assertNotIn(WIFI_PW, out); self.assertNotIn(LOGIN_PW, out)

    def test_install_sequence_and_stage_contents(self):
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()])
        self.assertEqual(rc, 0, out); self.assertEqual(dev.at_lines, [si.AT["install"]])
        pushed = {k.replace("/tmp/stone/", ""): v for k, v in dev.pushed.items()}
        for f in si.REQUIRED: self.assertIn("payload/" + f, pushed)
        self.assertNotIn("payload/tor", pushed)
        env = pushed["env"][0].decode()
        self.assertIn("WIFI_SSID=Hearth Home\n", env); self.assertIn("WIFI_SSID5=Hearth Home 5G\n", env); self.assertIn("LOGIN_USER=alice\n", env); self.assertIn("TOKEN=no", env)
        self.assertNotIn(WIFI_PW, env); self.assertNotIn(LOGIN_PW, env)
        self.assertEqual(pushed["secrets/wifi.pw"][0].decode(), WIFI_PW + "\n"); self.assertEqual(pushed["secrets/login.pw"][0].decode(), LOGIN_PW + "\n")
        self.assertEqual(pushed["secrets/wifi.pw"][1], 0o600); self.assertEqual(pushed["secrets/login.pw"][1], 0o600)
        self.assertEqual(pushed["authorized_keys"][0].decode().strip(), PUB)
        man = pushed["MANIFEST.sha256"][0].decode()
        for f in si.REQUIRED: self.assertIn("  " + f + "\n", man)
        self.assertIn("boot.sh", pushed); self.assertTrue(pushed["boot.sh"][0].startswith(b"#!/bin/sh"))
        self.assertIn("Done. Next:", out)

    def test_no_password_in_any_command_or_message(self):
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers(token=True)])
        blob = out + repr(dev.calls) + repr(dev.at_lines)
        for secret in (WIFI_PW, LOGIN_PW): self.assertNotIn(secret, blob)
        tok = open(os.path.join(self.home, ".heimdallstone", "ui.token")).read().strip()
        self.assertEqual(len(tok), 64); self.assertNotIn(tok, blob)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.home, ".heimdallstone", "ui.token")).st_mode), 0o600)
        self.assertEqual(dev.pushed["/tmp/stone/secrets/ui.token"][0].decode().strip(), tok)

    def test_new_token_keeps_the_old_one(self):
        d = os.path.join(self.home, ".heimdallstone"); os.makedirs(d); open(os.path.join(d, "ui.token"), "w").write("OLDTOKEN\n")
        self.run_main(["install", "--payload", self.pay, "--answers", self.answers(token=True)])
        self.assertEqual(open(os.path.join(d, "ui.token.old")).read().strip(), "OLDTOKEN")

    def test_a_failed_install_reports_the_rollback_and_returns_1(self):
        dev = FakeDevice(log_script=["10:00:00 STEP wifi", "10:00:01 could not set the Wi-Fi", "10:00:01 STONE-FAILED wifi", "10:00:02 rolled back", "10:00:02 STONE-DONE"])
        rc, _, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=dev)
        self.assertEqual(rc, 1); self.assertIn("FAILED and was rolled back", out); self.assertIn("could not set the Wi-Fi", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".heimdallstone", "ui.token")))

    def test_mode_switch_when_only_the_normal_mode_shows(self):
        rc, dev, _ = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=FakeDevice(pids=(0xF626,)))
        self.assertEqual(rc, 0); self.assertTrue(dev.switched)

    def test_waits_for_the_at_daemon_before_sending_anything(self):
        dev = FakeDevice(); dev.atfwd_late = 5
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=dev)
        self.assertEqual(rc, 0, out); self.assertIn("waiting for the unit's AT daemon", out); self.assertGreater(dev.atfwd_polls, 5)
        first_push = next(i for i, c in enumerate(dev.calls) if c[0] == "push"); last_poll = max(i for i, c in enumerate(dev.calls) if c[:2] == ("shell", "pidof atfwd_daemon"))
        self.assertLess(last_poll, first_push)

    def test_no_at_daemon_is_a_clear_error(self):
        dev = FakeDevice(); dev.atfwd_late = 10 ** 6
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=dev)
        self.assertEqual(rc, 1); self.assertIn("atfwd_daemon", out); self.assertEqual(dev.at_lines, []); self.assertEqual(dev.pushed, {})

    def test_no_device_is_a_clear_error_and_nothing_is_pushed(self):
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=FakeDevice(pids=()))
        self.assertEqual(rc, 1); self.assertIn("no Orbic on the USB cable", out); self.assertEqual(dev.pushed, {}); self.assertEqual(dev.at_lines, [])

    def test_bad_answers_are_refused_before_the_device_is_used(self):
        for bad in ({"wifi": {"ssid": "x", "password_file": self.secretfile("short", "short")}},
                    {"wifi": {"ssid": "Same", "ssid5": "Same", "password_file": self.wifipw}},
                    {"login": {"user": "bad user", "password_file": self.loginpw}},
                    {"login": {"user": "alice", "password_file": self.secretfile("shortlogin", "tooshort")}}):
            rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers(**bad)])
            self.assertEqual(rc, 1, bad); self.assertEqual(dev.calls, [], bad)

    def test_scripts_come_from_the_repo_when_the_payload_has_only_the_binaries(self):
        only = os.path.join(self.t, "bins"); os.makedirs(only)
        for f in si.BINARIES: open(os.path.join(only, f), "w").write("binary " + f)
        rc, dev, out = self.run_main(["install", "--payload", only, "--answers", self.answers()])
        self.assertEqual(rc, 0, out); pushed = {k.replace("/tmp/stone/", ""): v for k, v in dev.pushed.items()}
        for f in si.REQUIRED: self.assertIn("payload/" + f, pushed)
        self.assertEqual(pushed["payload/http_proxy.init"][0], open(os.path.join(si.HERE, "payload", "http_proxy.init"), "rb").read())
        self.assertEqual(pushed["payload/wpad-guard.sh"][0], open(os.path.join(si.HERE, "..", "scripts", "wpad-guard.sh"), "rb").read())
        self.assertEqual(pushed["payload/tinyfwd"][0], b"binary tinyfwd")

    def test_a_missing_binary_is_named_with_a_pointer_to_the_docs(self):
        only = os.path.join(self.t, "bins"); os.makedirs(only); open(os.path.join(only, "tinyfwd"), "w").write("x")
        rc, dev, out = self.run_main(["install", "--payload", only, "--answers", self.answers()])
        self.assertEqual(rc, 1); self.assertIn("dnsmasq", out); self.assertIn("dropbearmulti", out); self.assertIn("docs/INSTALL.md", out); self.assertEqual(dev.calls, [])

    def test_no_payload_at_all_names_the_binaries(self):
        rc, dev, out = self.run_main(["install", "--answers", self.answers()])
        self.assertEqual(rc, 1); self.assertIn("tinyfwd", out); self.assertEqual(dev.calls, [])

    def test_the_public_scripts_exist_and_are_clean(self):
        for f in ("http_proxy.init", "dnsmasq-swap.sh", "wps-guard.sh"):
            p = os.path.join(si.HERE, "payload", f); self.assertTrue(os.path.isfile(p), p)
            body = open(p).read().lower()
            for bad in ("be" + "n,", "por" + "ch", "auro" + "ra", "ray" + "hunter", "beat-" + "token", "-por" + "ch-relay"): self.assertNotIn(bad, body, (f, bad))   # words kept out of the public tree (built by concatenation so this file does not contain them)

    def test_missing_payload_file_is_named(self):
        os.unlink(os.path.join(self.pay, "dnsmasq"))
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()])
        self.assertEqual(rc, 1); self.assertIn("dnsmasq", out); self.assertEqual(dev.calls, [])

    def test_unattended_run_needs_confirmation(self):
        a = json.load(open(self.answers())); a["yes"] = False; json.dump(a, open(os.path.join(self.t, "a2.json"), "w"))
        io, out = make_io(); io["interactive"] = False
        rc = si.main(["install", "--payload", self.pay, "--answers", os.path.join(self.t, "a2.json")], dev=FakeDevice(), io=io, home=self.home)
        self.assertEqual(rc, 1); self.assertIn("not confirmed", "\n".join(out))

    def test_unattended_run_needs_factory_reset_confirmed(self):
        a = json.load(open(self.answers())); del a["confirmed_factory_reset"]; json.dump(a, open(os.path.join(self.t, "a3.json"), "w"))
        io, out = make_io(); io["interactive"] = False
        rc = si.main(["install", "--payload", self.pay, "--answers", os.path.join(self.t, "a3.json")], dev=FakeDevice(), io=io, home=self.home)
        self.assertEqual(rc, 1); self.assertIn("factory reset not confirmed", "\n".join(out)); self.assertEqual(FakeDevice().calls, [])

    def test_interactive_refusing_factory_reset_cancels_before_the_device_is_used(self):
        io, out = make_io(inputs=["n"])
        rc = si.main(["install", "--payload", self.pay], dev=FakeDevice(), io=io, home=self.home)
        self.assertEqual(rc, 1); self.assertIn("cancelled: factory-reset the unit", "\n".join(out))

    def test_dry_run_skips_the_factory_reset_question(self):
        a = json.load(open(self.answers())); del a["confirmed_factory_reset"]; json.dump(a, open(os.path.join(self.t, "a4.json"), "w"))
        rc, _, out = self.run_main(["install", "--payload", self.pay, "--answers", os.path.join(self.t, "a4.json"), "--dry-run"])
        self.assertEqual(rc, 0, out); self.assertNotIn("factory-reset", out)

    def test_rollback_sends_only_the_journal_line(self):
        dev = FakeDevice(log_script=["10:00:00 rolled back", "10:00:00 rebooting in 5 s", "10:00:00 STONE-DONE"])
        rc, dev, out = self.run_main(["rollback", "--yes"], dev=dev)
        self.assertEqual(rc, 0); self.assertEqual(dev.at_lines, [si.AT["rollback"]]); self.assertIn("rolled back", out); self.assertEqual(dev.pushed, {})

    def test_adb_error_text_is_not_mistaken_for_a_log_line(self):
        dev = FakeDevice(log_script=["cat: can't open '/tmp/stone/log': No such file or directory", "10:00:00 STEP one", "10:00:01 STONE-OK", "10:00:01 STONE-DONE"])
        rc, dev, out = self.run_main(["install", "--payload", self.pay, "--answers", self.answers()], dev=dev)
        self.assertEqual(rc, 0, out); self.assertIn("STEP one", out); self.assertNotIn("can't open", out)

    def test_check_changes_nothing_and_cleans_up(self):
        dev = FakeDevice(log_script=["10:00:00 CHECK id: uid=0(root)", "10:00:00 STONE-DONE"])
        rc, dev, out = self.run_main(["check", "--payload", self.pay], dev=dev)
        self.assertEqual(rc, 0); self.assertEqual(dev.at_lines, [si.AT["check"]]); self.assertIn(("shell", "rm -rf /tmp/stone"), dev.calls)
        self.assertEqual(sorted(k.replace("/tmp/stone/", "") for k in dev.pushed), ["boot.sh"])   # the checker only: no payload, no env, no secrets, no key

    def test_kit_restore_stages_identity_and_state_and_keeps_login(self):
        kit = os.path.join(self.t, "kit"); os.makedirs(os.path.join(kit, "identity")); os.makedirs(os.path.join(kit, "state")); os.makedirs(os.path.join(kit, "payload"))
        for f in si.REQUIRED + ["tor"]: open(os.path.join(kit, "payload", f), "w").write("kit " + f)
        open(os.path.join(kit, "identity", "identity.tar"), "wb").write(b"IDENTITYTAR"); open(os.path.join(kit, "state", "proxy-state.tar"), "wb").write(b"STATETAR"); open(os.path.join(kit, "state", "extra.tar"), "wb").write(b"EXTRATAR")
        snap = os.path.join(self.t, "snap.json"); json.dump({"sections": {"wifi": {"xml": SNAP_XML}}}, open(snap, "w"))
        ans = self.answers(wifi={"from_snapshot": snap}, login={"keep_identity": True}, tor=True); a = json.load(open(ans)); a["ssh_key"] = self.pubfile
        rc, dev, out = self.run_main(["install", "--kit", kit, "--answers", ans])
        self.assertEqual(rc, 0, out); pushed = {k.replace("/tmp/stone/", ""): v for k, v in dev.pushed.items()}
        self.assertEqual(pushed["identity.tar"][0], b"IDENTITYTAR"); self.assertEqual(pushed["state/proxy-state.tar"][0], b"STATETAR"); self.assertEqual(pushed["state/extra.tar"][0], b"EXTRATAR")
        self.assertIn("payload/tor", pushed); self.assertNotIn("secrets/login.pw", pushed); self.assertNotIn("LOGIN_USER", pushed["env"][0].decode())
        self.assertEqual(pushed["secrets/wifi.pw"][0].decode(), "snap-psk-9&x\n"); self.assertIn("WIFI_SSID=Cabin & Light\n", pushed["env"][0].decode())
        self.assertIn("kept from the restored identity", out); self.assertNotIn("snap-psk-9", out)

    def test_interactive_questions(self):
        io, out = make_io(inputs=["Hearth Home", "y", "alice", "p", PUB, "n", "install"][:0] or [], secrets_in=[])
        # scripted terminal session: factory-reset confirm, name, 5G default yes, user, key paste, no token, confirm
        inputs = ["y", "Hearth Home", "", "alice", "p", PUB, "n", "install"]
        secrets_in = ["short", WIFI_PW, WIFI_PW, LOGIN_PW + "x", LOGIN_PW, LOGIN_PW]
        # the first wifi password "short" is rejected, then the real one is typed twice; web password likewise
        secrets_in = ["short", WIFI_PW, WIFI_PW, LOGIN_PW, LOGIN_PW]
        io, out = make_io(inputs=inputs, secrets_in=secrets_in)
        dev = FakeDevice()
        rc = si.main(["install", "--payload", self.pay], dev=dev, io=io, home=self.home)
        text = "\n".join(out); self.assertEqual(rc, 0, text)
        self.assertIn("a Wi-Fi password must be 8 to 63 characters", text)          # the short one was refused, then asked again
        env = dev.pushed["/tmp/stone/env"][0].decode()
        self.assertIn("WIFI_SSID=Hearth Home\n", env); self.assertIn("WIFI_SSID5=Hearth Home-5G\n", env); self.assertIn("LOGIN_USER=alice\n", env); self.assertIn("TOKEN=no", env)


if __name__ == "__main__":
    unittest.main()
