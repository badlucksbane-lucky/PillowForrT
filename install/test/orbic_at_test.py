import importlib.util, os, unittest
spec = importlib.util.spec_from_file_location("orbic_at", os.path.join(os.path.dirname(__file__), "..", "orbic-at.py"))
oa = importlib.util.module_from_spec(spec); spec.loader.exec_module(oa)


class Fake:
    """A transport that records what was sent and replays canned bulk reads."""
    def __init__(self, reads): self.reads, self.sent, self.ctl = list(reads), [], []
    def control_out(self, *a): self.ctl.append(a)
    def bulk_write(self, ep, data): self.sent.append((ep, data))
    def bulk_read(self, ep, size):
        if not self.reads: raise oa.AtError("timeout")
        return self.reads.pop(0)


class T(unittest.TestCase):
    def test_frame(self):
        self.assertEqual(oa.frame("AT+SYSCMD=id"), b"\r\nAT+SYSCMD=id\r\n")

    def test_frame_refuses_line_breaks_and_non_at(self):
        for bad in ("AT+SYSCMD=id\r\nAT+SYSCMD=reboot", "AT+SYSCMD=a\nb", "id", "ls /", ""):
            with self.assertRaises(oa.AtError): oa.frame(bad)

    def test_frame_refuses_huge(self):
        with self.assertRaises(oa.AtError): oa.frame("AT+SYSCMD=" + "x" * 2000)

    def test_line_limit_is_64(self):
        oa.frame("AT+SYSCMD=" + "x" * 54)                         # exactly 64 bytes: fine
        with self.assertRaises(oa.AtError): oa.frame("AT+SYSCMD=" + "x" * 55)
        oa.frame("AT+SYSCMD=mkdir -p /data/example/scripts /data/example/bin")   # a normal 58-byte line

    def test_separators_refused_in_syscmd(self):
        for bad in ("AT+SYSCMD=a;b", "AT+SYSCMD=a,b"):
            with self.assertRaises(oa.AtError): oa.frame(bad)

    def test_ok_in_second_read(self):
        c = "AT+SYSCMD=id > /tmp/t"
        f = Fake([b"\r\n" + c.encode() + b"\r\n", b"\r\nOK\r\n"])
        oa.exchange(f, c)
        self.assertEqual(f.ctl[0][:4], (0x21, 0x22, 3, 1))           # class/interface, DTR|RTS, interface 1
        self.assertEqual(f.sent, [(0x02, b"\r\n" + c.encode() + b"\r\n")])

    def test_ok_in_same_read_as_echo(self):
        c = "AT+SYSCMD=true"
        oa.exchange(Fake([b"\r\n" + c.encode() + b"\r\n\r\nOK\r\n"]), c)

    def test_echo_text_can_never_count_as_an_answer(self):
        c = "AT+SYSCMD=grep ERROR /x"                          # the echo contains the word ERROR
        with self.assertRaises(oa.AtError) as e:
            oa.exchange(Fake([b"\r\n" + c.encode() + b"\r\n", b""]), c)
        self.assertNotIn("answered ERROR", str(e.exception))      # an empty reply is "no OK", not a fake ERROR
        c2 = "AT+SYSCMD=echo \r\nOK\r\n".replace("\r\n", " ")      # and an OK-looking echo is not an OK either
        with self.assertRaises(oa.AtError):
            oa.exchange(Fake([b"\r\n" + c2.encode() + b"\r\n"] + [b""] * 4), c2)

    def test_error_reply(self):
        c = "AT+SYSCMD=x"
        with self.assertRaises(oa.AtError) as e:
            oa.exchange(Fake([b"\r\n" + c.encode() + b"\r\n", b"\r\nERROR\r\n"]), c)
        self.assertIn("ERROR", str(e.exception))

    def test_timeout_propagates(self):
        with self.assertRaises(oa.AtError): oa.exchange(Fake([]), "AT+SYSCMD=x")

    def test_real_libusb_enumerates(self):                         # read-only, no Orbic needed: proves the ctypes bindings
        try: u = oa.Usb()
        except oa.AtError as e: self.skipTest(str(e))
        try:
            devs = u.devices(); u.release()
            self.assertIsInstance(devs, list)
            for v, p, _ in devs: self.assertTrue(0 <= v <= 0xFFFF and 0 <= p <= 0xFFFF)
        finally: u.close()


if __name__ == "__main__": unittest.main()
