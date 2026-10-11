<div align="center">

# emoticon_export

**微信 4.1.x (Windows) 表情包解密导出工具**

把微信本地加密存储的表情包还原为普通图片文件 · 单文件 Python · 除收藏表情外全程离线

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#13-许可证)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](#3-环境要求)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#3-环境要求)
[![WeChat](https://img.shields.io/badge/WeChat-4.1.x-green.svg)](#3-环境要求)

[功能](#1-项目简介) · [快速开始](#5-快速开始) · [工作原理](#8-工作原理) · [已知问题](#9-已知问题与限制) · [故障排查](#10-故障排查)

</div>

---

## 目录

1. [项目简介](#1-项目简介)
2. [免责声明](#2-免责声明)
3. [环境要求](#3-环境要求)
4. [安装](#4-安装)
5. [快速开始](#5-快速开始)
6. [使用手册](#6-使用手册)
7. [输出说明](#7-输出说明)
8. [工作原理](#8-工作原理)
9. [已知问题与限制](#9-已知问题与限制)
10. [故障排查](#10-故障排查)
11. [项目结构](#11-项目结构)
12. [致谢与来源](#12-致谢与来源)
13. [许可证](#13-许可证)

---

## 1　项目简介

### 1.1　这是什么

微信 4.1.x (Windows) 把表情包以加密文件的形式存储在本地 `xwechat_files` 数据目录中——文件名是内容 md5，内容经过 AES 加密，直接拷贝无法使用。本工具读取这些本地加密文件，提取密钥解密，按微信元数据还原表情包分组与标题，输出为普通图片文件：

```
微信本地加密存储                     导出结果
─────────────────                  ──────────────────────────
business/emoticon/Persist/    →    emoticon_export/store/<包名>/<标题>.gif
  (md5 命名, AES 加密)               emoticon_export/favorite/001.gif …
db_storage/emoticon/emoticon.db →  emoticon_export/unknown/
  (SQLCipher 4 加密)                emoticon_export/manifest.json
```

单文件 Python 实现（`emoticon_export.py`，约 1160 行），无框架依赖，可命令行使用，也可作为模块被其他程序调用（`from emoticon_export import run_export`）。

### 1.2　边界（这不是什么）

- **不是聊天记录导出工具**——只处理表情包，不涉及消息、联系人。
- **不是 V2 聊天图片解密工具**——`msg/` 目录下 `.dat` 聊天图片的解密在原版完整工具中，未包含在本模块。
- **方向是「本地 → 本地」**——不登录微信、不抓取服务器数据；唯一联网环节是收藏表情的 CDN 补下载（可 `--no-cdn` 关闭）。
- **仅支持 Windows**——密钥提取依赖读取微信进程内存（Win32 API）。

### 1.3　特性

- **全通路导出**：密钥提取 → 文件解密 → 容器分割 → 数据库解密 → 按包分组命名 → CDN 收藏补全 → 结构化清单，一条命令完成
- **密钥自动提取**：扫描微信进程内存获取账号 seed 并派生密钥，无需第三方工具；支持 `--key`/`--seed` 完全离线
- **数据库自包含解密**：内置 WCDB/SQLCipher 4 运行时解密（内存指针链提取 + HMAC-SHA512 校验 + 逐页解密），不依赖外部 key 工具
- **结构级容器分割**：按 PNG/GIF/JPEG 文件结构精确切分容器文件，压缩数据内部的巧合魔数不产生残片
- **wxgf 动图转码**：微信私有 HEVC 动图格式自动转 GIF（需可选依赖）
- **结构化 manifest**：`manifest.json` 与输出目录一一对应，记录每个表情的 md5、标题、排序、来源
- **内置自检**：`--selftest` 无需微信即可验证密钥派生与分割器正确性
- **降级容错**：密钥方案变更时自动降级为「仅收藏导出」，不中断

---

## 2　免责声明

1. 本工具仅用于**导出用户本人账号**存储在**本人电脑**上的表情数据，用途限于个人备份与迁移（例如迁往其他 IM）。
2. 本工具与腾讯/微信官方无任何关联；微信是 Tencent 的商标。
3. 密钥提取依赖读取微信进程内存，请确保用途合法合规，并自行评估与微信用户协议的兼容性；使用本工具产生的一切后果由使用者自行承担。
4. 输出内容（密钥文件、解密数据库、聊天图片）属于个人隐私数据，请妥善保管，勿传播他人数据。
5. 本项目按「现状」提供，不提供任何担保，详见[许可证](#13-许可证)。

---

## 3　环境要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows 10/11（密钥提取依赖 Win32 API，不支持 macOS/Linux） |
| 微信版本 | 4.1.x（Windows 版 Weixin.exe）；密钥提取与数据库解密期间**微信必须处于登录运行状态** |
| Python | 3.8+ |
| pycryptodome | 必需，`>= 3.20` |
| imageio-ffmpeg | 可选，`>= 0.5.0`——wxgf/HEVC 动图转 GIF 所需；缺失时自动跳过转码并保留 `.wxgf` 原始文件 |

磁盘空间：输出体积约为表情目录原始体积的 1–2 倍（含解密中间产物，完成后自动清理）。

---

## 4　安装

```bash
# 1. 获取代码
git clone <本仓库地址>
cd <仓库目录>

# 2. 安装依赖
pip install -r requirements.txt
# 或手动安装：
pip install pycryptodome            # 必需
pip install imageio-ffmpeg          # 可选：wxgf 动图转 GIF

# 3. （无需微信）验证安装
python emoticon_export.py --selftest
```

期望输出：`[OK] 自检通过: 密钥派生/验证、容器分割`

---

## 5　快速开始

**第一步**：登录微信并保持运行（密钥要从微信进程内存中提取）。

**第二步**：运行导出：

```bash
python emoticon_export.py
```

工具自动定位数据目录（依次探测常见安装路径，失败时读取同目录 `wechat_path.ini`），打印定位结果后开始全通路导出。完成后输出目录为 `emoticon_export/`。

**数据目录未被自动定位？** 显式指定：

```bash
python emoticon_export.py --data-dir "C:\Users\<你>\xwechat_files\wxid_xxxxx_b487"
```

> 数据目录名以 `wxid_` 开头、以 `_b487` 结尾；可在微信「设置 → 文件管理」中找到实际位置。

---

## 6　使用手册

### 6.1　命令行参数

```
python emoticon_export.py [选项]
```

| 参数 | 说明 |
|---|---|
| `--data-dir <路径>` | 指定账号数据目录（`xwechat_files/wxid_xxx_b487`），跳过自动定位 |
| `--key <hex>` | 直接提供表情密钥（64 位十六进制），跳过内存扫描，可完全离线 |
| `--seed <整数>` | 直接提供账号 seed，跳过内存扫描，可完全离线 |
| `--db <路径>` | 提供已解密的 `emoticon.db`，跳过数据库解密（配合 `--key` 可全离线） |
| `--out <目录>` | 输出目录，默认 `emoticon_export` |
| `--notype` | 平铺输出模式：全部表情放入 `emoticon_export_all/`（见 [已知问题 #3](#9-已知问题与限制)） |
| `--no-cdn` | 跳过收藏表情的 CDN 下载 |
| `--no-wxgf` | 跳过 wxgf/HEVC 转码 |
| `--keep-decrypted` | 保留解密中间产物（`_decrypted/`、`store_extra/`、临时数据库） |
| `--selftest` | 运行内置自检（无需微信与真实数据） |

### 6.2　典型场景

```bash
# 场景一：微信登录运行中，一键全量导出（最常用）
python emoticon_export.py

# 场景二：自动定位失败 / 多账号机器，显式指定账号目录
python emoticon_export.py --data-dir "D:\xwechat_files\wxid_abc123_b487"

# 场景三：完全离线导出（微信已卸载，但有此前保存的密钥与明文库）
python emoticon_export.py --key <64位hex> --db emoticon.db --no-cdn --no-wxgf

# 场景四：导入其他软件时希望文件名自解释（包名_标题），选平铺模式
python emoticon_export.py --notype

# 场景五：只想要收藏表情，跳过转码加速
python emoticon_export.py --no-wxgf

# 场景六：作为模块被其他程序调用
```

```python
from emoticon_export import run_export

result = run_export(
    data_dir=r"C:\Users\me\xwechat_files\wxid_abc_b487",
    wxid="wxid_abc",           # 数据目录名去掉 _b487 后缀
    emo_dir=r"...\wxid_abc_b487\business\emoticon",
    out_dir="my_export",       # 其余参数均可选：key_hex / seed / db / no_cdn / notype …
)
# result 为 manifest 同构字典：{"packs", "favorites", "unknown", "summary"}
```

### 6.3　密码文件的安全处理

`wechat_keys.txt`（使用密钥显示功能时生成）与全部输出目录包含个人隐私数据——密钥可用于解密你账号的全部本地表情数据。请勿提交到版本库、勿分享给他人。

---

## 7　输出说明

### 7.1　目录结构

```
emoticon_export/                    输出根（--out 可改）
├── store/                          商店表情，按包名分组
│   └── <包名>/<标题>.gif           文件名 = 表情标题；包内重名自动加 _2、_3
├── favorite/                       收藏表情，按收藏顺序编号
│   └── 001.gif                     001、002、…；来自 CDN 下载
├── unknown/                        未匹配到元数据的残留（文件名 = md5）
└── manifest.json                   结构化清单（见下）
```

### 7.2　manifest.json

与目录内容一一对应，`file` 字段即文件的相对路径：

```jsonc
{
  "packs": {
    "<包名>": {
      "package_id": "…",
      "stickers": [
        { "md5": "…", "caption": "标题", "sort": 1,
          "file": "store/<包名>/<标题>.gif", "ext": "gif", "size": 12345 }
      ]
    }
  },
  "favorites": [
    { "md5": "…", "sort": 1, "product_id": "…",
      "file": "favorite/001.gif", "ext": "gif", "size": 12345, "source": "cdn" }
  ],
  "unknown": [
    { "md5": "…", "file": "unknown/<md5>.jpg", "ext": "jpg", "size": 12345 }
  ],
  "summary": { "packs": 12, "stickers": 863, "favorites": 154, "unknown": 7, "total": 1024 }
}
```

---

## 8　工作原理

### 8.1　流水线

```
数据目录定位 ──► wxid 提取（目录名去 _b487）
      │
      ▼
扫微信进程内存找 seed ──► 派生表情密钥 ──► C0 首块解密验证
      │                                    │ 失败（密钥方案变更等）
      │                                    ▼
      │                          降级：仅解库 + CDN 收藏
      ▼
解密 Persist / PersistStore / Thumb / ThumbStore（AES-128-CBC）
      │
      ▼
分割 PersistStore 容器（PNG/GIF/JPEG 结构级解析）
      │
      ▼
解密 emoticon.db（SQLCipher 4：内存指针链提取密钥 → 逐页解密）
      │
      ▼
元数据匹配命名（store / unknown）──► wxgf 转 GIF ──► CDN 补收藏 ──► manifest.json
```

### 8.2　密钥体系

| 密钥 | 公式 | 用途 |
|---|---|---|
| 表情密钥（16B） | `md5("{seed}{wxid}EMOTICON")` 十六进制解码取前 16 字节 | 表情文件 AES-128-CBC，IV = 密钥 |
| 数据库密钥（32B） | 从微信进程内存的 WCDB Cipher 配置对象中提取（XOR 反混淆 + HMAC-SHA512 校验） | `emoticon.db` AES-256-CBC 逐页解密（SQLCipher 4 规范：页 4096B，salt 16B，IV 16B，页尾 HMAC-SHA512 64B） |

密钥验证的原理：IV 等于密钥本身，因此任取一个表情文件的前 16 字节做探针，解密后前 4 字节命中标准图片魔数（`89PNG`/`GIF8`/`FFD8FF`/`wxgf`/`RIFF`）即可确认密钥正确。

### 8.3　关键实现

- **容器分割**：`PersistStore` 文件是同一包多张表情的顺序拼接。裸搜索魔数会把压缩数据内部的巧合字节切为残片，因此按 PNG 块链（→IEND）、GIF 块结构（→trailer 0x3B）、JPEG marker 段（→EOI）解析到真实结束位置。
- **wxgf 格式**：微信私有 HEVC 动图，魔数 `wxgf` 后接裸 H.265 流，经 ffmpeg（palettegen/paletteuse 滤镜链）转 GIF 动画。
- **收藏表情**：本地库记录 CDN 地址与 AES 密钥，优先明文 URL，失败时下载密文用 AES-128-CBC（key=IV）解密，按收藏顺序命名。

完整算法推导与完整版工具（含 V2 聊天图片解密、全库解密）见上游项目 [CN-Grace/Wechat-Emoticon-Parser](https://github.com/CN-Grace/Wechat-Emoticon-Parser)。

---

## 9　已知问题与限制

按诚实发布原则列出当前已确认、尚未修复的问题：

1. **微信版本敏感**。数据库密钥提取依赖微信 4.1.x 的内存布局；社区已证实 4.1.11+ 变更了密钥缓存格式，此类版本上数据库解密会失败，工具自动降级为「仅收藏导出」。表情文件密钥提取（seed 派生）与数据库密钥相互独立，不受此影响。
2. **C0 探针的 JPEG 边角情形**。密钥验证用 4 字节切片比对魔数表，而 JPEG 魔数只有 3 字节——若目录中第一个被探测的文件恰好是 JPEG，密钥验证会全部失败并触发降级。规避方法：重试（探针按目录序取文件），或使用 `--key`/`--seed` 离线模式。
3. **`--notype` 与 `--out` 组合的目录删除风险**。`--notype` 完成后会删除默认输出目录；若你恰好用 `--out emoticon_export_all` 指定输出（与平铺目录同名），导出结果会被一并删除。规避方法：`--notype` 时不要指定 `--out`，或指定其他名字。
4. **Windows 大小写不敏感的命名碰撞**。同一包内两个标题仅大小写不同（如 `OK`/`ok`）时，后写入者会覆盖先写入者，manifest 与磁盘可能出现不一致。
5. **imageio-ffmpeg 二进制被杀软处理时**，转码环节会抛出未捕获异常而非跳过（该库以 `RuntimeError` 报告二进制缺失，本模块目前只捕获 `ImportError`）。规避方法：`--no-wxgf` 跳过转码，或将 ffmpeg 加入杀软白名单。

其他已知限制（设计使然，非缺陷）：`-wal` 数据库日志不参与解密（解出的是运行瞬间快照）；收藏表情不使用本地解密结果而统一走 CDN；数据库解出的 `unknown/` 在微信 4.1.10+ 上可能偏多（新版 schema 移除了商店元数据表）。

---

## 10　故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 输出目录只有 manifest.json，没有 favorite/ | 密钥扫描失败触发降级，且数据库也未解出 | 确认微信**正在登录运行**后重跑；对照[已知问题 #1](#9-已知问题与限制) 检查微信版本 |
| 提示 WeChat not running | 导出期间微信未运行 | 启动并登录微信，保持运行状态重跑 |
| `Decrypting Persist: 0 ok N failed` | wxid 不匹配：数据目录名不符合 `wxid_xxx_b487`，或定位到了其他账号 | 核对启动时打印的 data dir / wxid；用 `--data-dir` 显式指定 |
| `No imageio-ffmpeg, skipping wxgf transcode` | 可选依赖未安装 | `pip install imageio-ffmpeg`；不需要动图可忽略 |
| wxgf 转码阶段崩溃 | ffmpeg 二进制缺失/被杀软隔离（[已知问题 #5](#9-已知问题与限制)） | `--no-wxgf` 或白名单处理 |
| `unknown/` 目录异常多 | 新版微信 schema 移除商店元数据表 | 属正常行为；需要完整元数据可用原版完整工具的数据库解密功能 |
| 自动定位不到数据目录 | 微信安装在非默认路径 | `--data-dir` 显式指定，或编辑同目录 `wechat_path.ini`（写入数据目录路径即可，支持注释） |
| 导出中途崩溃后重跑仍失败 | 半写文件残留触发解密异常 | 关闭微信后清理 `_decrypted/` 重试；或先 `--keep-decrypted` 观察失败文件 |

运行日志约定：`[+]` 关键成功（如密钥命中）、`[*]` 进度、`[!]` 警告。`[OK]` 结尾表示该阶段完成。

---

## 11　项目结构

```
.
├── emoticon_export.py      主模块（单文件，全部逻辑）
├── requirements.txt        依赖清单
├── wechat_path.ini         数据目录回退配置（可选，默认全注释）
├── LICENSE                 MIT 许可证（含上游归属声明）
└── README.md               本文件
```

---

## 12　致谢与来源

本模块衍生自以下开源项目，感谢原作者的工作：

- **[CN-Grace/Wechat-Emoticon-Parser](https://github.com/CN-Grace/Wechat-Emoticon-Parser)**（MIT）—— 直接上游。本项目在其单文件工具基础上提取表情包通路并工程化整理。
- 算法思路致谢（同上游）：
  - [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) — WCDB 数据库运行时扫描解密
  - [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) — 密钥派生公式与候选验证
  - [junuo-S/WeChatMsgDump](https://github.com/junuo-S/WeChatMsgDump) — 进程内存读取架构
  - [93857536-pixel/WeChatExporter](https://github.com/93857536-pixel/WeChatExporter) — 表情 CDN 下载与 wxgf 解析
  - [CipherTalk/wechat-key-tool](https://github.com/CipherTalk/wechat-key-tool) — 账号 seed 提取

---

## 13　许可证

本项目以 [MIT License](LICENSE) 发布。

本项目的核心代码衍生自 CN-Grace/Wechat-Emoticon-Parser（MIT License, Copyright (c) 2026 CN-Grace），其版权声明与许可文本随本项目一并分发。修改内容：按依赖闭包提取表情包通路、移除 V2 聊天图片与全库解密及交互菜单、新增命令行自检。

使用微信、Windows 及本工具引用的任何第三方名称的权利归其各自所有者所有。
