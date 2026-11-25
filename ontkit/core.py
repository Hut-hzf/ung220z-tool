# -*- coding: utf-8 -*-
"""公共部件：日志、HTTP 会话、Telnet 客户端。"""
import http.cookiejar
import re
import select
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

_CHARSET_RE = re.compile(r"charset=([A-Za-z0-9_-]+)", re.I)


def decode_body(raw, ctype=""):
    """光猫页面常为 GBK：先按响应头 charset，再 utf-8 → gbk → gb18030 回退。"""
    encs = []
    m = _CHARSET_RE.search(ctype or "")
    if m:
        encs.append(m.group(1))
    encs += ["utf-8", "gbk", "gb18030"]
    for enc in encs:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def log(tag, msg):
    print("[%s] %-6s %s" % (time.strftime("%H:%M:%S"), tag, msg), flush=True)


class Http:
    """带 Cookie 的极简 HTTP 会话。"""

    def __init__(self, base, timeout=8):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.op.addheaders = [("User-Agent", UA), ("Referer", self.base + "/")]

    def get(self, path, raw=False):
        try:
            with self.op.open(self.base + path, timeout=self.timeout) as r:
                data = r.read()
                if raw:
                    return data, r.status
                return decode_body(data, r.headers.get("Content-Type", "")), r.status
        except urllib.error.HTTPError as e:
            data = e.read() or b""
            if raw:
                return data, e.code
            return decode_body(data, (e.headers or {}).get("Content-Type", "")), e.code

    def post(self, path, body, raw=False, ctype=None):
        if isinstance(body, str):
            body = body.encode()
        req = urllib.request.Request(self.base + path, data=body)
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with self.op.open(req, timeout=self.timeout) as r:
                data = r.read()
                if raw:
                    return data, r.status
                return decode_body(data, r.headers.get("Content-Type", "")), r.status
        except urllib.error.HTTPError as e:
            data = e.read() or b""
            if raw:
                return data, e.code
            return decode_body(data, (e.headers or {}).get("Content-Type", "")), e.code

    def post_form(self, path, data):
        return self.post(path, urllib.parse.urlencode(data), ctype="application/x-www-form-urlencoded")


# ───────────────────────────── Telnet ─────────────────────────────
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


def _parse(buf):
    out, rep, i = bytearray(), bytearray(), 0
    while i < len(buf):
        b = buf[i]
        if b == IAC and i + 1 < len(buf):
            cmd = buf[i + 1]
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(buf):
                rep += bytes([IAC, WONT if cmd == DO else DONT, buf[i + 2]])
                i += 3
                continue
            if cmd == SB:
                j = buf.find(bytes([IAC, SE]), i + 2)
                i = (j + 2) if j != -1 else len(buf)
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out).decode("utf-8", "replace"), bytes(rep)


class Telnet:
    def __init__(self, host, port=23, timeout=8):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.setblocking(False)
        self.buf = ""

    def _recv(self, wait=0.3):
        r, _, _ = select.select([self.s], [], [], wait)
        if not r:
            return False
        try:
            data = self.s.recv(8192)
        except BlockingIOError:
            return False
        if not data:
            return False
        txt, rep = _parse(data)
        if rep:
            self.s.sendall(rep)
        self.buf += txt
        return True

    def read_until_any(self, tokens, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            for t in tokens:
                if t in self.buf:
                    return t
            self._recv(0.25)
        return None

    def read_for(self, seconds=2.0):
        end = time.time() + seconds
        while time.time() < end:
            self._recv(0.2)
        return self.buf

    def send(self, line, crlf=True):
        self.s.sendall(line.encode() + (b"\r\n" if crlf else b""))

    def run(self, cmd, timeout=12):
        self.buf = ""
        self.send(cmd)
        time.sleep(0.3)
        self.send("echo __X__")
        self.read_until_any(["__X__"], timeout)
        out = self.buf.split("__X__")[0]
        lines = [l.rstrip() for l in out.splitlines()
                 if l.strip() and not l.strip().startswith("/ #") and l.strip() != "echo"]
        if lines and cmd[:20] in lines[0]:
            lines = lines[1:]
        return "\n".join(lines).strip()

    def login(self, user, passwords, timeout=8):
        self.read_until_any(["login:", "Login:"], timeout)
        for pw in passwords:
            self.buf = ""
            self.send(user)
            got = self.read_until_any(["assword:", "incorrect", "Login:"], timeout)
            if got != "assword:":
                return False
            self.buf = ""
            self.send(pw)
            got = self.read_until_any(["/ #", "$", "#", "incorrect", "Login:"], timeout)
            if got in ("/ #", "#", "$"):
                return True
        return False

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass
