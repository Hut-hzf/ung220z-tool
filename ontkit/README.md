# ontkit

多厂商光猫（ONT）安全自查工具：识别固件家族 → 开启 Telnet → 读取配置 → 提取凭据。

## 型号对照

| 型号 | 厂商 | 固件家族 | 默认端口 | 主要入口 | 状态 |
|---|---|---|---|---|---|
| 九联 UNG853H | 九联（移动定制） | ZTE 系 | 80 | `.gch` + `lastgood.xml` | 推断，待真机验证 |
| 吉比特 H3-2 | 吉比特 | ZTE 系 | 80 | `.gch` + `sendcmd` | 推断，待真机验证 |
| 中兴 ZXHN G7615 | 中兴 | ZTE 系 | 8080 | `webFac` 工厂模式 | 协议已按公开实现移植 |
| 烽火 HG6042A1 | 烽火 | FiberHome | 8080 | `telnetenable.cgi?key=<MAC>` | 有公开案例，未复现 |
| 华为 HS8145X6 | 华为 | 华为 ssmp | 80 | Web 登录 → 开 Telnet | 实验性 |
| 华为 B866-L1 | 华为 | 华为 ssmp | 80 | 同上 | 实验性 |

> 判断依据：UNG853H 的超级密码社区方法围绕 `lastgood.xml` 展开，`sidbg`/`sendcmd`/`webFac` 是中兴方案的标志性组件；G7615 直接命中 zteOnu 的支持列表；HS8145X6 / B866-L1 为华为 ssmp 体系，登录与 Telnet 机制与中兴完全不同，因此单列一套引擎。

## 快速开始

```bash
# 1) 先识别
python3 -m ontkit probe -H 192.168.1.1

# 2) 中兴系：开 Telnet + 提凭据
python3 -m ontkit zte -H 192.168.1.1 -p 8080 --mode factory --enable-telnet

# 3) 华为系
python3 -m ontkit huawei -H 192.168.1.1
```

按型号直接跑（入口脚本会自动补默认端口）：

```bash
python3 models/ung853h.py  -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
python3 models/h3_2.py     -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
python3 models/g7615.py    -H 192.168.1.1 --mode factory --enable-telnet
python3 models/hs8145x6.py -H 192.168.1.1
python3 models/b866l1.py   -H 192.168.1.1
```

## 中兴系原理

### 1. webFac 工厂模式

设备在 `http://<ip>:8080` 暴露一个未鉴权的 `webFac` 接口，流程为：

```
POST webFac      SendSq.gch                  复位，返回 400 表示就绪
POST webFac      RequestFactoryMode.gch      申请进入工厂模式（设备主动断连，属正常）
POST webFac      SendSq.gch?rand=0           握手，响应决定协议版本
POST webFacEntry AES(SendInfo.gch?info=..|)  v2/v3 先发
POST webFacEntry AES(CheckLoginAuth.gch?..)  认证
POST webFacEntry AES(FactoryMode.gch?mode=2) 返回 telnet 账号密码
```

SendSq 的响应形态决定版本与密钥来源：

| 版本 | SendSq 响应 | 密钥池 | 索引 |
|---|---|---|---|
| v1 | 空 | `AES_KEY_POOL` | `rand` |
| v2 | `newrand=<n>` | `AES_KEY_POOL_NEW` | `((0x1000193*rand) & 0x3F ^ n) % 60` |
| v3 | `re_rand=<i>&<nonce>&<mac>` | `AES_KEY_POOL_RERAND` | `i`（nonce 与 mac 不参与派生） |

- 密钥统一为：从 96 字节池按索引切 24 字节，逐字节异或 `0xA5`
- 通信体为 **AES-ECB + 零填充**；长度恰为 16 的倍数时也要再补一整块（固件按 NUL 结尾取串）
- v2 的 `SendInfo.gch?info=12|` 后面跟 46 字节 MAC 魔数；v3 固定 `info=6|` 且不带魔数
- **v3 固件只接受 `rand=0`**：非零值会让后续 `webFacEntry` 直接断连（ZXHN G7615TV2 / V3.1.0P1T1 实测）
- 认证用的是设备**当前**的管理员口令。`CheckLoginAuth` 返回 401 就是口令不对，不是协议问题
- 拿到凭据不等于 Telnet 已放开：新固件还要过 `setTelnetPri`（按 PON MAC + 索引生成的授权串）和 `PortControl`，重启或重新拨号会清掉授权位

### 2. SendInfo 的数学

设备侧校验：把 payload 每 4 字节读成小端整数 `w`，计算 `w^1271 mod 2537`，取低 8 位；每 6 个结果与客户端 MAC 比对。

因此本工具反解：对每个 MAC 字节找 `v` 使 `(v^1271 mod 2537) & 0xff` 等于它，填入 payload。`magic_bytes()` 生成后可用 `verify_payload()` 自测（已在本地验证通过）。

### 3. 配置读取

```bash
sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1
sendcmd 1 DB set TelnetCfg 0 TSLan_UName root
sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd  Zte521
sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 3
sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3
sendcmd 1 DB save
sidbg 1 DB decry /userconfig/cfg/db_user_cfg.xml
```

解出的明文配置包含 `DevAuthInfo`（Web 账号）、`TelnetUser`、`WANCPPP`（PPPoE）、`WLANPSK`（WiFi 密钥）。

## 华为系原理（实验性）

- 默认超管：电信 `telecomadmin/nE7jA%5m`，移动 `CMCCAdmin/aDm8H%MdA`
- Telnet：`root/adminHW`，进入后常需 `su`
- 开启入口各固件不同，工具会依次尝试 `/onttelnet.cgi`、`/enableTelnet.cgi` 等，失败则提示在 Web「安全 → 设备访问控制」手动开启

华为的 `su` 密码由设备序列号推导，各版本算法不一，本工具**未内置**该算法，避免给出不可靠结果。

## 已知限制

- 除 G7615 的 webFac 协议外，其余型号均**未经真机验证**，请把运行日志反馈后再迭代
- 光猫升级固件后接口路径可能变化
- 部分运营商固件把 webFac 关闭，此时工厂模式不可用
- 华为系目前只能做「登录 + 尝试开启 Telnet」，不保证成功

## 免责声明

仅限对你**自有设备**进行维护与自查。未经授权访问他人设备违反法律。

## 安全提醒

- 华为/中兴的 Web 登录都有失败计数（通常 3 次），本工具已把尝试上限设为 3 次并在达到后停止
- 若设备已因多次失败进入延时校验，请静默等待 10~30 分钟再试，不要继续重试
- 首次在真机上运行时建议加 `--mode web` 只做只读探测，确认流程后再开启 `--enable-telnet`

## 烽火（FiberHome）流程

公开实操来源：[阿凡博客 · 烽火光猫 HG6042A1](https://blog.iafan.com/post-6.html)

```bash
python3 -m ontkit fiberhome -H 192.168.1.1 -m AA:BB:CC:DD:EE:FF
```

1. `GET http://<ip>:8080/cgi-bin/telnetenable.cgi?telnetenable=1&key=<MAC大写12位>`
2. Telnet：`admin` / `Fh@<MAC 后六位大写>`
3. `load_cli factory` → `show admin_name` / `show admin_pwd`
4. 需要 su 时：`root` / `hg2x0`（部分固件）

## 其他机型的公开案例

| 机型 | 关键点 | 来源 |
|---|---|---|
| 九联 UNG953h1-S | Telnet 默认 `useradmin/useradmin`；超密在加密的 `lastgood.xml` | [cnblogs](https://www.cnblogs.com/Prego/p/22631311) |
| 移动 GM232 | `telnet.gch` 中 `%` 必须写成 `%25`；Telnet 口令在 `config.bin`（RouterPassView 搜 `TS_UPwd`） | [萝卜头论坛](https://bbs.luobotou.org/forum.php?mod=viewthread&tid=49623) |
