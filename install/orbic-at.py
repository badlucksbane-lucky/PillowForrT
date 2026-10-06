#!/usr/bin/env python3
"""orbic-at.py -- send AT+SYSCMD to the Orbic RC400L over its USB cable. No dependencies beyond the system libusb (ctypes).

AT+SYSCMD=<shell command> makes the modem's AT daemon run that command on the unit as root, so this needs physical access to your own unit. The unit
must be in command mode (USB 05c6:f601, serial plus adb); a factory-fresh unit shows up as 05c6:f626 until `mode-switch`.
Wire format: control request 0x22 (value 3, interface 1), write the line plus CRLF to bulk OUT 0x02, read bulk IN 0x82 (the echo, then the answer: OK).
Keep lines under 64 bytes and free of ; and , : a 96-byte line wedged the unit's AT port until a reboot.

  orbic-at.py list                       read-only: show Qualcomm (05c6) devices on the USB bus
  orbic-at.py sys '<shell command>'      run a shell command on the Orbic as root: sends  AT+SYSCMD=<shell command>
  orbic-at.py raw 'AT...'                send any single AT line (still one line, no CR/LF)
  orbic-at.py mode-switch                05c6:f626 (no serial) -> 05c6:f601 (serial + adb); only when f626 is present

Exit 0 only when the unit answered OK. The reply carries no output: have the command write to a file and read it
over SSH or adb. Every command sent is appended to ~/.orbic-at.log (0600).
"""
import ctypes, ctypes.util, os, sys, time

VENDOR = 0x05C6
PID_CMD, PID_CMD_RNDIS, PID_RNDIS_ONLY = 0xF601, 0xF622, 0xF626
SERIAL_IFACE, RNDIS_IFACE = 1, 1
EP_OUT, EP_IN = 0x02, 0x82
TIMEOUT_MS = 2000
MAX_LINE = 64      # a 61-byte line is known to work; 96 bytes wedged the port. Stay at or under 64.
OK = b"\r\nOK\r\n"


class AtError(Exception):
    pass


def frame(cmd):
    """The wire frame: CRLF + command + CRLF. A CR or LF inside the command would end the line early and smuggle a second command, so it is refused."""
    if "\r" in cmd or "\n" in cmd:
        raise AtError("a command must be one line (no CR or LF)")
    if not cmd.startswith("AT"):
        raise AtError("not an AT command: %r" % cmd[:20])
    b = cmd.encode("utf-8")
    if len(b) > MAX_LINE:
        raise AtError("command too long (%d bytes, limit %d). A 96-byte line wedged the Orbic's AT port on 2026-10-05 (silent until a reboot); "
                      "put the work in a script on the unit and send `sh /tmp/script` instead" % (len(b), MAX_LINE))
    for bad in ";,":
        if bad in cmd[cmd.find("=") + 1:] and cmd.startswith("AT+SYSCMD="):
            raise AtError("%r in an AT+SYSCMD command makes the device answer ERROR (it is an AT separator): use a script on the unit" % bad)
    return b"\r\n" + b + b"\r\n"


def judge(reply):
    """True for OK, False for an ERROR reply, None while the reply is still incomplete."""
    if OK in reply:
        return True
    if b"ERROR" in reply:
        return False
    return None


def exchange(t, cmd):
    """One AT command on an open serial transport t (control_out, bulk_write, bulk_read). Returns the reply bytes after the echo.
    The device echoes the command first, then answers; both can arrive in one read or two, so read until the answer is complete."""
    data = frame(cmd)
    t.control_out(0x21, 0x22, 3, SERIAL_IFACE)          # class, interface: SET_CONTROL_LINE_STATE, DTR|RTS
    t.bulk_write(EP_OUT, data)
    raw = b""
    for _ in range(4):
        raw += t.bulk_read(EP_IN, 256)
        i = raw.find(cmd.encode("utf-8"))
        reply = raw[i + len(cmd.encode("utf-8")):] if i >= 0 else raw  # drop the echo so its text can never count as an answer
        v = judge(reply)
        if v is True:
            return reply
        if v is False:
            raise AtError("device answered ERROR: %r" % reply.decode("utf-8", "replace").strip())
    raise AtError("no OK from the device, got %r" % raw.decode("utf-8", "replace"))


# ---------------------------------------------------------------- libusb through ctypes
class _Desc(ctypes.Structure):
    _fields_ = [("bLength", ctypes.c_uint8), ("bDescriptorType", ctypes.c_uint8), ("bcdUSB", ctypes.c_uint16),
                ("bDeviceClass", ctypes.c_uint8), ("bDeviceSubClass", ctypes.c_uint8), ("bDeviceProtocol", ctypes.c_uint8),
                ("bMaxPacketSize0", ctypes.c_uint8), ("idVendor", ctypes.c_uint16), ("idProduct", ctypes.c_uint16),
                ("bcdDevice", ctypes.c_uint16), ("iManufacturer", ctypes.c_uint8), ("iProduct", ctypes.c_uint8),
                ("iSerialNumber", ctypes.c_uint8), ("bNumConfigurations", ctypes.c_uint8)]


class Usb:
    def __init__(self):
        name = ctypes.util.find_library("usb-1.0") or "libusb-1.0.so.0"
        try:
            L = self.L = ctypes.CDLL(name)
        except OSError as e:
            raise AtError("libusb-1.0 is not installed (%s)" % e)
        V, P, I, U = ctypes.c_void_p, ctypes.POINTER, ctypes.c_int, ctypes.c_uint
        L.libusb_init.argtypes = [P(V)]
        L.libusb_exit.argtypes = [V]
        L.libusb_get_device_list.argtypes = [V, P(P(V))]; L.libusb_get_device_list.restype = ctypes.c_ssize_t
        L.libusb_free_device_list.argtypes = [P(V), I]
        L.libusb_get_device_descriptor.argtypes = [V, P(_Desc)]
        L.libusb_open.argtypes = [V, P(V)]
        L.libusb_close.argtypes = [V]
        for f in ("kernel_driver_active", "detach_kernel_driver", "attach_kernel_driver", "claim_interface", "release_interface"):
            getattr(L, "libusb_" + f).argtypes = [V, I]
        L.libusb_control_transfer.argtypes = [V, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_uint16, U]
        L.libusb_bulk_transfer.argtypes = [V, ctypes.c_uint8, ctypes.c_char_p, I, P(I), U]
        self.ctx = V()
        if L.libusb_init(ctypes.byref(self.ctx)) != 0:
            raise AtError("libusb_init failed")

    def devices(self):
        """[(vendor, product, device pointer)] for everything on the bus; call release() when done with the pointers."""
        lst = ctypes.POINTER(ctypes.c_void_p)()
        n = self.L.libusb_get_device_list(self.ctx, ctypes.byref(lst))
        if n < 0:
            raise AtError("libusb_get_device_list failed (%d)" % n)
        self._list, out = lst, []
        for i in range(n):
            d = _Desc()
            if self.L.libusb_get_device_descriptor(lst[i], ctypes.byref(d)) == 0:
                out.append((d.idVendor, d.idProduct, lst[i]))
        return out

    def release(self):
        if getattr(self, "_list", None):
            self.L.libusb_free_device_list(self._list, 1); self._list = None

    def open(self, vendor, product):
        for v, p, dev in self.devices():
            if (v, p) == (vendor, product):
                h = ctypes.c_void_p()
                r = self.L.libusb_open(dev, ctypes.byref(h))
                if r != 0:
                    raise AtError("cannot open %04x:%04x (libusb %d): run as a user that may use USB (a udev rule or sudo)" % (v, p, r))
                self.release()
                return Handle(self, h)
        self.release()
        return None

    def close(self):
        self.release(); self.L.libusb_exit(self.ctx)


class Handle:
    def __init__(self, usb, h):
        self.u, self.h, self.claimed, self.detached = usb, h, [], []

    def claim(self, iface):
        L = self.u.L
        if L.libusb_kernel_driver_active(self.h, iface) == 1:
            L.libusb_detach_kernel_driver(self.h, iface)
            self.detached.append(iface)                       # given back on close
        r = L.libusb_claim_interface(self.h, iface)
        if r != 0:
            raise AtError("cannot claim interface %d (libusb %d)" % (iface, r))
        self.claimed.append(iface)

    def control_out(self, rtype, req, value, index, data=b""):
        r = self.u.L.libusb_control_transfer(self.h, rtype, req, value, index, data, len(data), TIMEOUT_MS)
        if r < 0:
            raise AtError("control transfer failed (libusb %d)" % r)
        return r

    def bulk_write(self, ep, data):
        n = ctypes.c_int(0)
        r = self.u.L.libusb_bulk_transfer(self.h, ep, data, len(data), ctypes.byref(n), TIMEOUT_MS)
        if r != 0:
            raise AtError("bulk write failed (libusb %d)" % r)

    def bulk_read(self, ep, size):
        buf, n = ctypes.create_string_buffer(size), ctypes.c_int(0)
        r = self.u.L.libusb_bulk_transfer(self.h, ep, buf, size, ctypes.byref(n), TIMEOUT_MS)
        if r != 0:
            raise AtError("bulk read failed or timed out (libusb %d)" % r)
        return buf.raw[:n.value]

    def close(self):
        for i in self.claimed:
            self.u.L.libusb_release_interface(self.h, i)
        for i in self.detached:
            self.u.L.libusb_attach_kernel_driver(self.h, i)
        self.u.L.libusb_close(self.h)


# ---------------------------------------------------------------- commands
def log(cmd):
    p = os.path.expanduser("~/.orbic-at.log")
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), cmd))


def cmd_list(u):
    seen = [(v, p) for v, p, _ in u.devices() if v == VENDOR]
    u.release()
    if not seen:
        print("no Qualcomm (05c6) device on the USB bus: is the cable between this computer and the Orbic?")
        return 1
    names = {PID_CMD: "command mode (serial + adb): ready", PID_CMD_RNDIS: "command mode + RNDIS: ready", PID_RNDIS_ONLY: "RNDIS only, no serial: run mode-switch"}
    for v, p in seen:
        print("%04x:%04x  %s" % (v, p, names.get(p, "unknown product")))
    return 0


def serial_handle(u):
    for pid in (PID_CMD, PID_CMD_RNDIS):
        h = u.open(VENDOR, pid)
        if h:
            h.claim(SERIAL_IFACE)
            return h
    raise AtError("no Orbic in command mode (05c6:f601): run `orbic-at.py list`; if it shows f626, run `mode-switch`")


def cmd_send(u, line):
    log(line)
    h = serial_handle(u)
    try:
        reply = exchange(h, line)
    finally:
        h.close()
    print("OK")
    return 0


def cmd_mode_switch(u):
    pids = {p for v, p, _ in u.devices() if v == VENDOR}
    u.release()
    if pids & {PID_CMD, PID_CMD_RNDIS}:
        print("already in command mode: nothing to do"); return 0
    if PID_RNDIS_ONLY not in pids:
        raise AtError("no 05c6:f626 on the bus: nothing to switch")
    log("mode-switch (vendor request 0xa0 on 05c6:f626)")
    h = u.open(VENDOR, PID_RNDIS_ONLY)
    try:
        h.claim(RNDIS_IFACE)
        try:
            h.control_out(0x40, 0xA0, 0, 0)                  # vendor, device: the device reboots into command mode; a stall here is normal
        except AtError:
            pass
    finally:
        h.close()
    for _ in range(30):
        time.sleep(1)
        ps = {p for v, p, _ in u.devices() if v == VENDOR}; u.release()
        if ps & {PID_CMD, PID_CMD_RNDIS}:
            print("now in command mode"); return 0
    raise AtError("the unit did not come back in command mode within 30 s")


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__); return 2
    u = Usb()
    try:
        c = argv[1]
        if c == "list": return cmd_list(u)
        if c == "mode-switch": return cmd_mode_switch(u)
        if c in ("sys", "raw") and len(argv) == 3:
            return cmd_send(u, ("AT+SYSCMD=" + argv[2]) if c == "sys" else argv[2])
        print(__doc__); return 2
    except AtError as e:
        print("orbic-at: %s" % e, file=sys.stderr); return 1
    finally:
        u.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
