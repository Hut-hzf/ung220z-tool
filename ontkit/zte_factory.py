# -*- coding: utf-8 -*-
"""中兴系 webFac 工厂模式 —— 开启 Telnet 并取得登录凭据。

协议来源：对 zteOnu (github.com/idrnyu/zteOnu) 的公开实现做 Python 移植，
v3（re_rand）握手取自 zte_modem_tools issue #33 的公开讨论。
流程：
    1. POST webFac      SendSq.gch                 复位
    2. POST webFac      RequestFactoryMode.gch     申请工厂模式
    3. POST webFac      SendSq.gch?rand=0           取版本与密钥（v3 只认 rand=0）
    4. POST webFacEntry AES(CheckLoginAuth.gch...)  认证
       （version>=2 时先发 SendInfo.gch；v2 的 payload 由本机 MAC 反推）
    5. POST webFacEntry AES(FactoryMode.gch...)     返回 telnet 账号密码

SendSq 的三种响应决定协议版本：
    v1  body 为空                    → AES_KEY_POOL，索引 = rand
    v2  body 以 newrand= 开头        → AES_KEY_POOL_NEW，索引由 rand/newrand 推出
    v3  body 为 re_rand=<i>&<n>&<mac> → AES_KEY_POOL_RERAND，索引 = i
                                          （nonce 与 mac 不参与派生）
"""
import re
import urllib.error

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .core import Http, Telnet, log

# ── 密钥池（来自公开实现，96 字节） ──
AES_KEY_POOL = bytes([
    0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
    0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
    0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
    0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
    0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
    0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
    0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
    0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
    0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
    0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
])

AES_KEY_POOL_NEW = bytes([
    0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
    0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
    0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
    0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
    0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
    0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
    0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
    0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
    0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
    0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
])

# v3：SendSq 返回 re_rand=... 时使用的密钥池（96 字节）
AES_KEY_POOL_RERAND = bytes([
    0x9C, 0x33, 0x75, 0xD1, 0x1C, 0x42, 0x45, 0x37, 0x18, 0x48, 0x91, 0x73,
    0x17, 0x45, 0x79, 0x44, 0x43, 0xD7, 0xD5, 0x73, 0x33, 0x54, 0x76, 0xD2,
    0xC5, 0xF1, 0x2C, 0x4F, 0x7A, 0xBA, 0x61, 0xD9, 0x5C, 0x69, 0xDF, 0x8C,
    0xD2, 0x1C, 0xDE, 0x3B, 0x35, 0x2D, 0x2F, 0xE1, 0xDE, 0x4C, 0x77, 0xF5,
    0x1A, 0x65, 0xD1, 0xFE, 0x18, 0x43, 0x8E, 0xA7, 0x42, 0x08, 0x04, 0x78,
    0xD5, 0xE4, 0xF3, 0x34, 0xA4, 0xD3, 0xF2, 0x36, 0x47, 0x6D, 0x86, 0x9D,
    0x42, 0x65, 0x13, 0x42, 0xDC, 0x42, 0x99, 0x48, 0xDC, 0x67, 0x9F, 0x9E,
    0xDC, 0x46, 0x37, 0x5F, 0x84, 0x9F, 0x6F, 0x76, 0xCE, 0x79, 0x4F, 0x49,
])

MOD, EXP = 0x9E9, 0x4F8 - 1   # 2537, 1271


# ─────────────────────────── 加解密 ───────────────────────────
def _pad(b):
    """零填充：总是补满一整块。

    固件侧 httpd 会给明文多分配 1 字节保证 NUL 结尾，所以长度恰为 16 的倍数时
    也要再补一块（Go 版 padding() 与 C 版一致）。此前按 `len % 16` 取余，
    这种情况会少补一整块，导致设备解密后取不到结尾的 NUL 而判错。
    """
    return b + b"\x00" * (16 - len(b) % 16)


def ecb_encrypt(data: bytes, key: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(_pad(data)) + enc.finalize()


def ecb_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 16:
        data = _pad(data)
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return (dec.update(data) + dec.finalize()).rstrip(b"\x00")


def key_pool(version: int, r: int, new_r: int = 0) -> bytes:
    idx, pool = r, AES_KEY_POOL
    if version == 2:
        idx = ((0x1000193 * r) & 0x3F ^ new_r) % 60
        pool = AES_KEY_POOL_NEW
    elif version == 3:
        pool = AES_KEY_POOL_RERAND
    return bytes((b ^ 0xA5) & 0xFF for b in pool[idx:idx + 24])


# ────────────────────── SendInfo 魔数 payload ──────────────────────
def power(w: int) -> int:
    w %= MOD
    acc = 1
    e = EXP
    while e:
        if e & 1:
            acc = (acc * w) % MOD
        w = (w * w) % MOD
        e >>= 1
    return acc & 0xFF


_REV = {}
for _v in range(MOD):
    _REV.setdefault(power(_v), _v)


def magic_bytes(mac: bytes) -> bytes:
    """把 6 字节 MAC 编码成 46 字节 SendInfo payload。"""
    vals = [_REV[b] for b in mac] + [0] * 6
    out = bytearray()
    for v in vals[:11]:
        out += bytes([v & 0xFF, (v >> 8) & 0xFF, 0, 0])
    out += bytes([vals[11] & 0xFF, (vals[11] >> 8) & 0xFF])
    return bytes(out)


def verify_payload(payload: bytes, mac: bytes) -> bool:
    """复刻设备端校验，用于自测。"""
    check = bytearray()
    for k in range(12):
        w = 0
        for i in range(4):
            idx = 4 * k + i
            if idx < len(payload):
                w |= payload[idx] << (8 * i)
        check.append(power(w))
    return mac in [bytes(check[i:i + 6]) for i in range(0, 12, 6)]


# ─────────────────────────── 主流程 ───────────────────────────
class Factory:
    def __init__(self, ip, port=8080, user="telecomadmin", password="nE7jA%5m", timeout=8):
        self.ip, self.port = ip, port
        self.user, self.password = user, password
        self.http = Http("http://%s:%d" % (ip, port), timeout=timeout)
        self.key = b""
        self.version = 0

    def _post_web(self, body):
        return self.http.post("/webFac", body)

    def _post_entry(self, plain: bytes):
        """返回 (响应体, 状态码)。

        urllib 会把 4xx 抛成 HTTPError，若不在这里兜住，
        check_login_auth 的 401 分支和 send_info 的 400 分支永远走不到，
        报错会退化成「HTTP Error 401: Unauthorized」，看不出是账号问题还是协议问题。
        """
        try:
            return self.http.post("/webFacEntry", ecb_encrypt(plain, self.key), raw=True)
        except urllib.error.HTTPError as e:
            return (e.read() or b""), e.code

    def reset(self):
        try:
            self.http.get("/")
        except Exception:
            raise RuntimeError("HTTP 不可达：%s:%d" % (self.ip, self.port))
        try:
            _, st = self._post_web("SendSq.gch")
        except urllib.error.HTTPError as e:
            # 400 是「复位就绪」的正常应答：urllib 会把它抛成异常，
            # 不能当成设备不支持
            if e.code == 400:
                return True
            raise RuntimeError("webFac 返回 %d —— 该设备可能不是中兴系，或端口不是 %d"
                               % (e.code, self.port))
        return st in (200, 400)

    def request_factory_mode(self):
        try:
            self._post_web("RequestFactoryMode.gch")
        except Exception:
            pass
        return True

    def send_sq(self):
        # rand 固定取 0。v3（re_rand）固件对非零 rand 会在后续 webFacEntry 上
        # 直接断连；v1/v2 的密钥索引由「发送的 rand」与设备回传值共同决定，
        # 两端看到的值一致，取 0 同样成立。
        r = 0
        body, st = self._post_web("SendSq.gch?rand=%d\r\n" % r)
        if st != 200 and st != 401:
            return None
        if "re_rand=" in body:
            # v3：re_rand=<index>&<nonce>&<device mac>，只有 index 参与派生
            ver = 3
            m = re.search(r"re_rand=(\d+)", body)
            if not m:
                return None
            self.key = key_pool(ver, int(m.group(1)))
            log("DEBUG", "re_rand 索引 = %s" % m.group(1))
        elif "newrand" in body:
            ver = 2
            new_rand = int(re.sub(r"[^0-9]", "", body.replace("newrand=", "")) or 0)
            self.key = key_pool(ver, r, new_rand)
        elif body == "":
            ver = 1
            self.key = key_pool(ver, r, 0)
        else:
            return None
        self.version = ver
        return ver

    def check_login_auth(self):
        # v3 固件用 version50，v1/v2 保持 version61（v3 也不再带前导 &）
        ver_flag = 50 if self.version == 3 else 61
        sep = "?" if self.version == 3 else "?&"
        cmd = "CheckLoginAuth.gch%sversion%d&user=%s&pass=%s" % (
            sep, ver_flag, self.user, self.password)
        _, st = self._post_entry(cmd.encode())
        if st == 401:
            raise RuntimeError("工厂模式账号密码错误（%s/%s）" % (self.user, self.password))
        if st == 400:
            raise RuntimeError("设备拒绝（400）")
        return True

    def send_info(self, mac_candidates):
        if self.version == 3:
            # v3 不再提交 MAC 魔数，固定 info=6
            payloads = [b"SendInfo.gch?info=6|"]
        else:
            payloads = [b"SendInfo.gch?info=12|" + magic_bytes(mac) for mac in mac_candidates]
        for payload in payloads:
            resp, st = self._post_entry(payload)
            if st == 200:
                return True
            log("DEBUG", "%r 被拒（%d）" % (payload[:24], st))
        raise RuntimeError("SendInfo 被拒绝")

    def factory_mode(self):
        resp, _ = self._post_entry(b"FactoryMode.gch?mode=2&user=notused")
        plain = ecb_decrypt(resp, self.key).decode("utf-8", "replace")
        u = re.search(r"user=([^&\s]+)", plain)
        p = re.search(r"pass=([^&\s]+)", plain)
        return (u.group(1) if u else None, p.group(1) if p else None)

    def run(self, macs):
        log("INFO", "目标 %s:%d  工厂账号 %s" % (self.ip, self.port, self.user))
        log("STEP", "[0] 复位 webFac")
        if not self.reset():
            raise RuntimeError("webFac 无响应，可能不是中兴系或端口不对")
        log("STEP", "[1] 申请工厂模式")
        self.request_factory_mode()
        log("STEP", "[2] SendSq 握手")
        ver = self.send_sq()
        if ver is None:
            raise RuntimeError("SendSq 返回异常")
        log("STEP", "    版本 = %d（%s），密钥已派生"
            % (ver, {1: "空响应", 2: "newrand", 3: "re_rand"}[ver]))
        log("STEP", "[3] 认证")
        if ver >= 2:
            self.send_info(macs)
        self.check_login_auth()
        log("STEP", "[4] 进入工厂模式")
        user, pw = self.factory_mode()
        if not user:
            raise RuntimeError("未解析到 telnet 凭据")
        log("DATA", "Telnet 账号 %s / %s" % (user, pw))
        return user, pw


def enable_permanent_telnet(ip, user, pw, port=23):
    """登录 telnet 后写入 TelnetCfg，使 Telnet 开机自启。"""
    t = Telnet(ip, port)
    if not t.login(user, [pw]):
        t.close()
        raise RuntimeError("Telnet 登录失败")
    cmds = [
        "sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1",
        "sendcmd 1 DB set TelnetCfg 0 TSLan_UName root",
        "sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd Zte521",
        "sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 3",
        "sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3",
        "sendcmd 1 DB save",
    ]
    for c in cmds:
        log("SHELL", c)
        t.send(c)
        t.read_for(0.5)
    t.close()
    return True
