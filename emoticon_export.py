#!/usr/bin/env python3
"""emoticon_export.py — 微信表情包独立导出模块

从 wechat_emoticon_export.py (V4.0-plus 工作区版) 按依赖闭包提取，仅含表情包通路：
  数据目录定位 → 内存扫 seed → 派生表情密钥（C0 验证）→ 解密
  Persist/PersistStore/Thumb/ThumbStore → 结构级分割容器
  → WCDB 解密 emoticon.db → 匹配命名 → CDN 下载收藏 → manifest.json

不包含：V2 聊天图片解密、db_storage 全库解密、交互菜单。
原单文件工具与本模块互不影响。

CLI 用法:
  python emoticon_export.py --selftest              # 内置自检（无需微信与真实数据）
  python emoticon_export.py                         # 自动定位数据目录并全通路导出
  python emoticon_export.py --data-dir <xwechat_files/wxid_xxx_b487> --out <输出目录>
  python emoticon_export.py --key <hex> --db <已解密emoticon.db> --no-cdn --no-wxgf   # 离线回归

程序调用:
  from emoticon_export import run_export
  run_export(data_dir, wxid, emo_dir, out_dir="emoticon_export")

依赖: pycryptodome (必需), imageio-ffmpeg (可选, wxgf 转码)
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes as wt

# ==================== 常量 ====================
MAGICS = (b'\x89PNG', b'GIF8', b'\xff\xd8\xff', b'wxgf', b'RIFF')
MEM_COMMIT = 0x1000
READABLE = {2, 4, 8, 16, 32, 64, 128}
MAX_REGION = 200 * 1024 * 1024
CHUNK = 32 * 1024 * 1024  # 大块读取减少 syscall 往返
RE_SEED = re.compile(rb'(?<![0-9])(\d{8,12})(?![0-9])')
DEFAULT_BASES = [
    r"E:\Program\Tencent Files\xwechat_files",
    r"D:\Program Files\Tencent\xwechat_files",
    r"%USERPROFILE%\Documents\xwechat_files",
]

# ==================== Windows 内存读取 ====================
class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


kernel32 = ctypes.windll.kernel32


def read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[: n.value]
    return None


def enum_regions(h, writable_only=False):
    regs = []
    addr = 0
    mbi = MBI()
    MEM_PRIVATE = 0x20000
    WRITABLE = {0x04, 0x08, 0x40}  # READWRITE / WRITECOPY / EXECUTE_READWRITE
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < MAX_REGION:
            if writable_only and not (mbi.Type == MEM_PRIVATE and mbi.Protect in WRITABLE):
                pass  # 跳过只读区/映射文件区
            else:
                regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def get_pids():
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return [int(l.strip('"').split('","')[1]) for l in r.stdout.strip().split('\n') if l.strip() and '","' in l]


def scan_seeds_from_memory(pid=None):
    """扫描 Weixin.exe 主进程内存, 提取 seed 候选 (数字串)"""
    pids = [pid] if pid else get_pids()[:1]
    seeds = set()
    for pid in pids:
        h = kernel32.OpenProcess(0x0410, False, pid)  # QUERY_INFO | VM_READ
        if not h:
            print(f"[!] cannot open PID {pid}")
            continue
        for base, size in enum_regions(h, writable_only=True):
            off = 0
            tail = b""
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    for m in RE_SEED.finditer(data):
                        v = int(m.group(0))
                        if 100_000_000 < v < 4_000_000_000:
                            seeds.add(v)
                    tail = data[-64:]
                else:
                    tail = b""
                off += cur
        kernel32.CloseHandle(h)
        print(f"[*] PID {pid}: seed candidates {len(seeds)}")
    return seeds


# ==================== key 派生与验证 ====================
def derive_key(seed, wxid):
    d = hashlib.md5(f"{seed}{wxid}EMOTICON".encode()).hexdigest()
    return bytes.fromhex(d)[:16]


def verify_key(key, c0):
    try:
        from Crypto.Cipher import AES
        dec = AES.new(key, AES.MODE_CBC, key).decrypt(c0)
        return dec[:4] in MAGICS
    except Exception:
        return False


def find_key_from_memory(c0, wxid):
    """内存扫描 seed -> 派生 -> C0 验证, 返回 (seed, key) 或 None (并行验证)"""
    seeds = scan_seeds_from_memory()
    print(f"[*] Verifying {len(seeds)} candidates (wxid={wxid})...")
    n = min(16, (os.cpu_count() or 8))
    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = {pool.submit(_verify_one, s, wxid, c0): s for s in sorted(seeds)}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                return r
    return None


def _verify_one(seed, wxid, c0):
    key = derive_key(seed, wxid)
    if verify_key(key, c0):
        return seed, key
    return None


# ==================== data dir定位 ====================
def find_data_dir():
    for base in DEFAULT_BASES:
        b = os.path.expandvars(base)
        if not os.path.isdir(b):
            continue
        for d in sorted(os.listdir(b)):
            if d.startswith("wxid_"):
                return os.path.join(b, d)
    # 自动定位失败: 回退读取脚本/EXE 同级目录下的 wechat_path.ini
    base_dir = os.path.dirname(sys.executable if getattr(sys, "frozen", False)
                               else os.path.abspath(__file__))
    ini = os.path.join(base_dir, "wechat_path.ini")
    if os.path.isfile(ini):
        try:
            with open(ini, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line[0] in "#;":
                        continue
                    # 支持 path = C:\... 形式或纯路径行
                    path = line.split("=", 1)[1].strip().strip('"\'') if "=" in line else line.strip('"\'')
                    path = os.path.expandvars(path)
                    if not path:
                        continue
                    # ini 路径可指向账号目录 (wxid_xxx) 或其父目录 (含 wxid_ 子目录)
                    if os.path.isdir(path):
                        if os.path.basename(path.rstrip("\\/")).startswith("wxid_"):
                            return path  # 直接是账号目录
                        for d in sorted(os.listdir(path)):  # 父目录: 钻入找 wxid_ 子目录
                            if d.startswith("wxid_") and os.path.isdir(os.path.join(path, d)):
                                return os.path.join(path, d)
                    return path  # 非目录: 原样返回, 由下游报具体错误
        except OSError:
            pass
    return None


def auto_wxid(data_dir):
    name = os.path.basename(data_dir)
    return name[:-5] if name.endswith("_b487") else name


def find_emoticon_dir(data_dir):
    for sub in ["business/emoticon", "emoticon"]:
        p = os.path.join(data_dir, sub)
        if os.path.isdir(p):
            return p
    return None


def find_db():
    """自动搜索已解密的 emoticon.db (旧快照 fallback)"""
    pats = [
        r"C:\Users\%USERNAME%\AppData\Local\Temp\wcdb-key-tool\decrypted\emoticon\emoticon.db",
        os.path.expandvars(r"%LOCALAPPDATA%\Temp\wcdb-key-tool\decrypted\emoticon\emoticon.db"),
        "emoticon.db",
    ]
    for p in pats:
        p = os.path.expandvars(p)
        if os.path.isfile(p):
            return p
    return None


# ==================== WCDB 数据库自包含Decrypting ====================
# 移植自 TANGandXue/wcdb-key-tool (Windows 4.1+ 主路径):
#   内存扫 com.Tencent.WCDB.Config.Cipher 对象 -> XOR 反混淆 -> 候选 enc_key
#   -> HMAC-SHA512 校验 -> AES-256-CBC 逐页Decrypting (SQLCipher4 规范)
WCDB_PAGE = 4096
WCDB_SALT_SZ = 16
WCDB_HMAC_SZ = 64
WCDB_RESERVE = 80
WCDB_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
WCDB_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b450048844c2448488944254048584c24")
WCDB_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
WCDB_BLOB_MAX = 1024
WCDB_MAX_ADDR = 0x0000_8000_0000_0000


def wcdb_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0] if off + 8 <= len(data) else 0


def wcdb_xor_repeat(data, mask):
    return bytes(v ^ mask[i % len(mask)] for i, v in enumerate(data))


def wcdb_verify_key(enc_key, page1):
    """HMAC-SHA512 校验 enc_key 是否匹配 db 页1 (SQLCipher4 规范)"""
    from Crypto.Cipher import AES  # noqa: F401 (确认依赖)
    salt = page1[:WCDB_SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)
    hmac_data = page1[WCDB_SALT_SZ: WCDB_PAGE - WCDB_RESERVE + 16]
    stored = page1[WCDB_PAGE - WCDB_HMAC_SZ: WCDB_PAGE]
    hm = hmac.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac.compare_digest(hm.digest(), stored)


def wcdb_decrypt_page(enc_key, page, pgno):
    from Crypto.Cipher import AES
    iv = page[WCDB_PAGE - WCDB_RESERVE: WCDB_PAGE - WCDB_RESERVE + 16]
    if pgno == 1:
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(page[WCDB_SALT_SZ: WCDB_PAGE - WCDB_RESERVE])
        return b"SQLite format 3\x00" + dec + b"\x00" * WCDB_RESERVE
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(page[: WCDB_PAGE - WCDB_RESERVE])
    return dec + b"\x00" * WCDB_RESERVE


def wcdb_scan_candidate_keys(pid):
    """只读扫描一次进程内存, 收集所有 Config.Cipher 中的 enc_key 候选 (去重)"""
    h = kernel32.OpenProcess(0x0410, False, pid)
    if not h:
        return []
    try:
        regions = enum_regions(h)  # DB key needle 在只读段 .rdata, 需全可读扫描
        needle_addrs = set()
        for base, size in regions:
            off = 0
            tail = b""
            tail_base = base
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    dbase = tail_base if tail else base + off
                    pos = data.find(WCDB_CIPHER_NAME)
                    while pos >= 0:
                        needle_addrs.add(dbase + pos)
                        pos = data.find(WCDB_CIPHER_NAME, pos + 1)
                    tail = data[-32:]
                    tail_base = dbase + max(0, len(data) - len(tail))
                else:
                    tail = b""
                    tail_base = base + off + cur
                off += cur
        if not needle_addrs:
            return []
        cands = []
        seen = set()
        patterns = [struct.pack("<Q", a) + struct.pack("<Q", len(WCDB_CIPHER_NAME)) for a in needle_addrs]
        for base, size in regions:
            off = 0
            tail = b""
            tail_base = base
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    dbase = tail_base if tail else base + off
                    for pat in patterns:
                        pos = data.find(pat)
                        while pos >= 0:
                            qaddr = dbase + pos
                            node = read_mem(h, qaddr - 0x10, 0x50)
                            if node and len(node) >= 0x40:
                                if (wcdb_u64(node, 0x10) in needle_addrs
                                        and wcdb_u64(node, 0x18) == len(WCDB_CIPHER_NAME)):
                                    cfg = wcdb_u64(node, 0x28)
                                    if 0x10000 <= cfg < WCDB_MAX_ADDR:
                                        obj = read_mem(h, cfg + 0x88, 0x28)
                                        if obj and len(obj) >= 0x18:
                                            dp = wcdb_u64(obj, 0x8)
                                            dl = wcdb_u64(obj, 0x10)
                                            if 0 < dl <= WCDB_BLOB_MAX and 0x10000 <= dp < WCDB_MAX_ADDR:
                                                blob = read_mem(h, dp, int(dl))
                                                if blob and len(blob) == dl:
                                                    decoded = wcdb_xor_repeat(blob, WCDB_XOR_MASK)
                                                    for m in WCDB_LITERAL_RE.finditer(decoded):
                                                        run = m.group(1).decode("ascii").lower()
                                                        starts = [0]
                                                        if len(run) > 96:
                                                            starts.extend(range(0, len(run) - 63, 32))
                                                        for st in dict.fromkeys(starts):
                                                            if st + 64 > len(run):
                                                                continue
                                                            try:
                                                                ek = bytes.fromhex(run[st:st + 64])
                                                            except ValueError:
                                                                continue
                                                            if len(set(ek)) < 15:
                                                                continue
                                                            if ek not in seen:
                                                                seen.add(ek)
                                                                cands.append(ek)
                            pos = data.find(pat, pos + 1)
                    tail = data[-0x80:]
                    tail_base = dbase + max(0, len(data) - len(tail))
                else:
                    tail = b""
                    tail_base = base + off + cur
                off += cur
        return cands
    finally:
        kernel32.CloseHandle(h)


def wcdb_scan_key(pid, page1):
    """兼容单库场景: 扫候选后验证匹配 db 的 enc_key 或 None"""
    for ek in wcdb_scan_candidate_keys(pid):
        if wcdb_verify_key(ek, page1):
            return ek
    return None


def decrypt_emoticon_db(data_dir, out_path):
    """Self-contained emoticon.db decryption (扫内存 key -> 逐页解密), 返回明文路径或 None"""
    db_path = os.path.join(data_dir, "db_storage", "emoticon", "emoticon.db")
    if not os.path.isfile(db_path):
        return None
    # 微信是否运行
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if not r.stdout.strip():
        print("[!] WeChat not running, cannot decrypt DB; using old snapshot")
        return None
    # 主进程 (内存最大)
    pids = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            try:
                pids.append((int(p[1]), int(p[4].replace(",", "").replace(" K", "") or 0)))
            except ValueError:
                pass
    if not pids:
        return None
    pids.sort(key=lambda x: -x[1])
    pid = pids[0][0]

    sz = os.path.getsize(db_path)
    if sz < WCDB_PAGE:
        return None
    with open(db_path, "rb") as f:
        page1 = f.read(WCDB_PAGE)
    print(f"[*] Self-contained emoticon.db decryption ({sz // 1024}KB, pid={pid})...")
    enc_key = wcdb_scan_key(pid, page1)
    if not enc_key:
        print("[!] Memory scan found no DB key, using old snapshot")
        return None
    print(f"[*] DB key found: {enc_key.hex()[:16]}...")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    total = (sz + WCDB_PAGE - 1) // WCDB_PAGE
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total + 1):
            page = fin.read(WCDB_PAGE)
            if len(page) < WCDB_PAGE:
                if not page:
                    break
                page = page + b"\x00" * (WCDB_PAGE - len(page))
            fout.write(wcdb_decrypt_page(enc_key, page, pgno))
    print(f"[*] Latest db: {out_path} ({total}  pages)")
    return out_path


# ==================== Decrypting ====================
def decrypt_file(path, key):
    from Crypto.Cipher import AES
    C = open(path, "rb").read()
    dec = AES.new(key, AES.MODE_CBC, key).decrypt(C)  # 每文件独立 cipher (避免状态污染)
    pad = dec[-1]
    if not (0 < pad <= 16 and all(b == pad for b in dec[-pad:])):
        return None
    return dec[:-pad]


def fmt_of(dec):
    if dec[:4] == b'\x89PNG':
        return 'png'
    if dec[:3] == b'GIF':
        return 'gif'
    if dec[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if dec[:4] == b'wxgf':
        return 'wxgf'
    if dec[:4] == b'RIFF':
        return 'webp'
    return 'dat'


def decrypt_all(emo_dir, key, out_dir):
    """Decrypting Persist/PersistStore/Thumb/ThumbStore, 返回 {md5: (subdir, filename, fmt)}"""
    os.makedirs(out_dir, exist_ok=True)
    mapping = {}
    for sub in ["Persist", "PersistStore", "Thumb", "ThumbStore"]:
        sd = os.path.join(emo_dir, sub)
        if not os.path.isdir(sd):
            continue
        od = os.path.join(out_dir, sub)
        os.makedirs(od, exist_ok=True)
        n_ok = n_fail = 0
        for root, dirs, names in os.walk(sd):
            for n in names:
                base = n[:-6] if n.endswith(".thumb") else n
                if len(base) != 32 or not all(c in "0123456789abcdef" for c in base):
                    continue
                dec = decrypt_file(os.path.join(root, n), key)
                if dec is None:
                    n_fail += 1
                    continue
                f = fmt_of(dec)
                fn = f"{base}.{f}"
                open(os.path.join(od, fn), "wb").write(dec)
                mapping[base] = (sub, fn, f)
                n_ok += 1
        print(f"[*] Decrypting {sub}: {n_ok} ok {n_fail} failed")
    return mapping


# ==================== 容器分割 ====================
def _png_end(data, start):
    """从 PNG 签名解析块链到 IEND, 返回结束位置或 None"""
    if data[start:start + 8] != b'\x89PNG\r\n\x1a\n':
        return None
    pos = start + 8
    n = len(data)
    while pos + 8 <= n:
        ln = struct.unpack('>I', data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if pos + 8 + ln + 4 > n:
            return None
        if typ == b'IEND':
            return pos + 8 + ln + 4
        pos += 8 + ln + 4
    return None


def _gif_end(data, start):
    """按 GIF 块结构解析到 trailer 0x3B, 返回结束位置或 None"""
    if data[start:start + 6] not in (b'GIF87a', b'GIF89a'):
        return None
    pos = start + 6
    n = len(data)
    if pos + 7 > n:
        return None
    flags = data[pos + 4]
    pos += 7
    if flags & 0x80:  # 全局色表
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    while pos < n:
        b = data[pos]
        if b == 0x3B:  # trailer
            return pos + 1
        if b == 0x21:  # extension: label + data sub-blocks
            pos += 2
        elif b == 0x2C:  # image descriptor
            pos += 10
            if pos <= n and data[pos - 1] & 0x80:  # 局部色表
                pos += 3 * (2 ** ((data[pos - 1] & 0x07) + 1))
            if pos >= n:
                return None
            pos += 1  # LZW 最小码长
        else:
            return None
        # 数据子块 (长度前缀, 0 结束): LZW 图像数据 / 扩展数据
        while pos < n:
            sz = data[pos]
            pos += 1
            if sz == 0:
                break
            pos += sz
        if pos > n:
            return None
    return None


def _jpeg_end(data, start):
    """按 marker 段解析到 EOI (FF D9), 返回结束位置或 None"""
    if data[start:start + 2] != b'\xff\xd8':
        return None
    pos = start + 2
    n = len(data)
    no_len = {0x01, *range(0xD0, 0xD8)}
    while pos + 2 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        if data[pos + 1] == 0x00:  # 字节填充
            pos += 2
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            return pos + 2
        if marker in no_len or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > n:
            return None
        seg_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        if seg_len < 2 or pos + 2 + seg_len > n:
            return None
        pos += 2 + seg_len
    return None


def _magic_at(data, i):
    if data[i:i + 8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[i:i + 6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if data[i:i + 2] == b'\xff\xd8':
        return 'jpg'
    if data[i:i + 4] == b'wxgf':
        return 'wxgf'
    if data[i:i + 4] == b'RIFF':
        return 'webp'
    return None


def _parse_end(data, i, ext):
    if ext == 'png':
        return _png_end(data, i)
    if ext == 'gif':
        return _gif_end(data, i)
    if ext == 'jpg':
        return _jpeg_end(data, i)
    return None  # wxgf/webp: 结构不定, 无法精确解析


def split_container(data):
    """流式分割: 完整解析一个文件到结束标记, 从结束位置继续 -> 天然跳过内部魔数误匹配

    只认能解析到结构结束的魔数 (PNG->IEND, GIF->0x3B, JPEG->EOI);
    数据内部的误匹配魔数无法形成完整结构 -> 自动忽略。
    """
    parts = []
    i = 0
    n = len(data)
    while i < n - 3:
        ext = _magic_at(data, i)
        if ext is None:
            i += 1
            continue
        end = _parse_end(data, i, ext)
        if end is None:
            # wxgf/webp 或误匹配: 若为不确定格式且后面有真实魔数, 切到下一个魔数
            if ext in ('wxgf', 'webp'):
                nxt = None
                for j in range(i + 4, n - 3):
                    if _magic_at(data, j):
                        nxt = j
                        break
                end = nxt if nxt is not None else n
            else:
                i += 1
                continue  # 误匹配
        if end - i < 16:  # 过小, 视为误匹配
            i += 1
            continue
        parts.append(data[i:end])
        i = end
    return parts


def extract_store(dec_dir, out_dir):
    """分割 PersistStore 容器, 返回 {md5: filename}"""
    src = os.path.join(dec_dir, "PersistStore")
    if not os.path.isdir(src):
        return {}
    od = os.path.join(out_dir, "store_extra")
    os.makedirs(od, exist_ok=True)
    extracted = {}
    for f in os.listdir(src):
        data = open(os.path.join(src, f), "rb").read()
        for pi, part in enumerate(split_container(data)):
            md5 = hashlib.md5(part).hexdigest()
            ext = fmt_of(part)
            if ext == 'dat':
                continue
            fn = f"{md5}.{ext}" if md5 not in extracted else f"{md5}_{pi}.{ext}"
            open(os.path.join(od, fn), "wb").write(part)
            extracted[md5] = fn
    print(f"[*] Container split: {len(extracted)} stickers")
    return extracted


# ==================== db 匹配与命名 ====================
def match_and_name(dec_dir, extracted, db_path, out_dir, do_wxgf=True):
    """对照 emoticon.db 按包分组命名, 返回结构化 result: {packs, favorites, unknown}"""
    result = {"packs": {}, "favorites": [], "unknown": []}
    pkg_dir = os.path.join(out_dir, "store")
    fav_dir = os.path.join(out_dir, "favorite")
    unk_dir = os.path.join(out_dir, "unknown")
    os.makedirs(pkg_dir, exist_ok=True)
    os.makedirs(fav_dir, exist_ok=True)
    os.makedirs(unk_dir, exist_ok=True)

    if db_path and os.path.isfile(db_path):
        import sqlite3
        db = sqlite3.connect(db_path)
        cur = db.cursor()
        fav_md5s = {r[0] for r in cur.execute("SELECT md5 FROM kNonStoreEmoticonTable")}
        pkg_names, caps, cap_pkg, file_info = {}, {}, {}, {}
        try:  # 新版 4.1.10+ schema 已移除 store 相关表
            pkg_names = dict(cur.execute("SELECT package_id_, package_name_ FROM kStoreEmoticonPackageTable"))
        except sqlite3.OperationalError:
            pass
        try:
            for pid, md5, lang, cap in cur.execute(
                    "SELECT package_id_, md5_, language_, caption_ FROM kStoreEmoticonCaptionsTable"):
                caps[md5] = cap
                cap_pkg[md5] = pid
        except sqlite3.OperationalError:
            pass
        try:
            for pid, md5, typ, sort in cur.execute(
                    "SELECT package_id_, md5_, type_, sort_order_ FROM kStoreEmoticonFilesTable"):
                file_info[md5] = (pid, sort)
        except sqlite3.OperationalError:
            pass
        db.close()
    else:
        print("[!] No emoticon.db, md5-only naming")
        fav_md5s, pkg_names, caps, cap_pkg, file_info = set(), {}, {}, {}, {}

    clean = lambda s: re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', str(s)).strip() or 'untitled'

    def _link_or_copy(src, dst):
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst)

    n_pkg = n_fav = n_unk = 0
    sort_counter = {}  # 包 -> 递增序号 (unknown 无 sort_order_)
    used_names = {}  # (包名, 标题) -> 已用次数, 用于重名去重

    # 组装所有待命名文件: 仅 Persist 原图 + 容器分割切片
    # (PersistStore 容器文件本身不参与命名 — 已被分割为 store_extra)
    all_files = {}  # md5 -> src_path
    sd = os.path.join(dec_dir, "Persist")
    if os.path.isdir(sd):
        for fn in os.listdir(sd):
            md5 = fn.split('.')[0]
            all_files.setdefault(md5, os.path.join(sd, fn))
    # 容器切片: 全部保留 (完整解析出的切片都是真实文件;
    # 匹配 db 的进 store, 不匹配的进 unknown 保留)
    for md5, fn in extracted.items():
        all_files.setdefault(md5, os.path.join(out_dir, "store_extra", fn))

    for md5, src in all_files.items():
        ext = src.split('.')[-1]
        size = os.path.getsize(src)
        if md5 in fav_md5s:
            # favorites come from CDN — 由 CDN 全量下载 (见 cdn_fill_favorites)
            continue
        elif md5 in file_info:
            pid, sort = file_info[md5]
            pname = clean(pkg_names.get(pid, ''))
            cap = clean(caps.get(md5, ''))
            pd = os.path.join(pkg_dir, pname)
            os.makedirs(pd, exist_ok=True)
            # 文件名 = titled (序号/md5 只存 JSON)
            base = cap if cap and cap != 'untitled' else md5
            cnt = used_names.get((pname, base), 0)
            fn = f"{base}.{ext}" if cnt == 0 else f"{base}_{cnt+1}.{ext}"
            used_names[(pname, base)] = cnt + 1
            dst = os.path.join(pd, fn)
            _link_or_copy(src, dst)
            pack = result["packs"].setdefault(pname, {"package_id": pid, "stickers": []})
            pack["stickers"].append({"md5": md5, "caption": caps.get(md5, ''), "sort": sort,
                                     "file": f"store/{pname}/{fn}", "ext": ext, "size": size})
            n_pkg += 1
        else:
            # unknown: 无法归类的全部进 unknown (含仅有标题无包名的)
            cap = caps.get(md5, '')
            pid = cap_pkg.get(md5, '')
            pname = clean(pkg_names.get(pid, ''))
            if cap and pname:
                sort_counter[pname] = sort_counter.get(pname, 0) + 1
                capc = clean(cap)
                base = capc if capc != 'untitled' else md5
                cnt = used_names.get((pname, base), 0)
                fn = f"{base}.{ext}" if cnt == 0 else f"{base}_{cnt+1}.{ext}"
                used_names[(pname, base)] = cnt + 1
                dst = os.path.join(pkg_dir, pname, fn)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                _link_or_copy(src, dst)
                pack = result["packs"].setdefault(pname, {"package_id": pid, "stickers": []})
                pack["stickers"].append({"md5": md5, "caption": cap, "sort": sort_counter[pname],
                                         "file": f"store/{pname}/{fn}", "ext": ext, "size": size})
                n_pkg += 1
            else:
                dst = os.path.join(unk_dir, f"{md5}.{ext}")
                _link_or_copy(src, dst)
                item = {"md5": md5, "file": f"unknown/{md5}.{ext}", "ext": ext, "size": size}
                if cap:
                    item["caption"] = cap  # 保留标题信息供参考
                result["unknown"].append(item)
                n_unk += 1

    # wxgf 转码 (遍历结构化 result)
    if do_wxgf:
        try:
            import imageio_ffmpeg
            ff = imageio_ffmpeg.get_ffmpeg_exe()
            n_wxgf = 0
            def iter_items():
                for pack in result["packs"].values():
                    for s in pack["stickers"]:
                        yield s
                for s in result["unknown"]:
                    yield s
            for item in iter_items():
                if item["file"].endswith(".wxgf"):
                    fp = os.path.join(out_dir, item["file"])
                    data = open(fp, 'rb').read()
                    hpath = fp + '.h265'
                    gif = fp[:-5] + '.gif'
                    vf = 'split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse'
                    # 整个 wxgf 直接转 GIF 动画 (含头转码 — VPS 可能在流中, 截取会丢参数集)
                    open(hpath, 'wb').write(data)
                    r = subprocess.run([ff, '-y', '-hide_banner', '-loglevel', 'error',
                                        '-i', hpath, '-vf', vf, '-loop', '0', gif], capture_output=True)
                    if r.returncode != 0 or not (os.path.exists(gif) and os.path.getsize(gif) > 100):
                        # fallback: 从 VPS 截取再试 (旧逻辑)
                        vps = data.find(b'\x00\x00\x00\x01\x40\x01')
                        sps = data.find(b'\x00\x00\x00\x01\x42\x01')
                        cut = min(x for x in (vps, sps) if x >= 0)
                        if cut >= 0:
                            open(hpath, 'wb').write(data[cut:])
                            r = subprocess.run([ff, '-y', '-hide_banner', '-loglevel', 'error',
                                                '-i', hpath, '-vf', vf, '-loop', '0', gif], capture_output=True)
                    os.remove(hpath)
                    if os.path.exists(gif) and os.path.getsize(gif) > 100:
                        os.remove(fp)
                        item["file"] = item["file"][:-5] + '.gif'
                        item["ext"] = 'gif'
                        item["size"] = os.path.getsize(gif)
                        n_wxgf += 1
            print(f"[*] wxgf transcoded: {n_wxgf}")
        except ImportError:
            print("[!] No imageio-ffmpeg, skipping wxgf transcode")

    print(f"[*] Named: store {n_pkg}, favorites {n_fav}, unknown {n_unk}")
    return result


# ==================== CDN favorites补全 ====================
CDN_UA = "Mozilla/5.0"
CDN_TIMEOUT = 20
CDN_MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG": "png",
    b"GIF8": "gif",
    b"RIFF": "webp",
    b"WXGF": "wxgf",
}


def cdn_fetch(url):
    if not url or url == "null":
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": CDN_UA})
        with urllib.request.urlopen(req, timeout=CDN_TIMEOUT) as r:
            data = r.read()
            return data if data else None
    except Exception:
        return None


def cdn_decrypt(data, aes_key_hex):
    """encrypt_url 密文 -> AES-128-CBC(key=IV=aes_key) 明文"""
    try:
        from Crypto.Cipher import AES
        key = bytes.fromhex(aes_key_hex)
        if len(key) != 16:
            return None
        return AES.new(key, AES.MODE_CBC, key).decrypt(data)
    except Exception:
        return None


def cdn_ext(data):
    for sig, ext in CDN_MAGIC.items():
        if data[: len(sig)] == sig:
            return ext
    return "gif"


def cdn_fill_favorites(db_path, fav_dir, favorites):
    """CDN favorites downloaded表情, 追加到结构化 favorites 列表, 返回补全数"""
    if not db_path or not os.path.isfile(db_path):
        return 0
    import sqlite3
    db = sqlite3.connect(db_path)
    cur = db.cursor()
    favs = {}
    for md5, aes, cdn, enc, pid in cur.execute(
            "SELECT md5, aes_key, cdn_url, encrypt_url, product_id FROM kNonStoreEmoticonTable"):
        if md5:
            favs[md5] = (aes, cdn, enc, pid)
    # favorites顺序 (行序 = favorites序号)
    fav_order = {}
    try:
        for idx, (md5,) in enumerate(cur.execute("SELECT md5 FROM kFavEmoticonOrderTable")):
            fav_order[md5] = idx
    except sqlite3.OperationalError:
        # 新版 schema 无此表: 按 kNonStoreEmoticonTable 行序兜底
        fav_order = {m: i for i, m in enumerate(favs)}
    db.close()
    if not favs:
        return 0

    have = {e["md5"] for e in favorites}
    todo = [m for m in favs if m not in have]
    if not todo:
        print(f"[*] CDN favorites: all downloaded ({len(favs)})")
        return 0
    print(f"[*] CDN favorites downloaded: {len(todo)}/{len(favs)}")

    os.makedirs(fav_dir, exist_ok=True)
    n_ok = 0

    def dl(md5):
        aes, cdn, enc, pid = favs[md5]
        data = cdn_fetch(cdn)
        if data is None and enc and aes:
            raw = cdn_fetch(enc)
            if raw:
                data = cdn_decrypt(raw, aes)
        if not data or len(data) < 4:
            return None
        ext = cdn_ext(data)
        return ext if data else None, data, pid

    with ThreadPoolExecutor(max_workers=12) as pool:
        futs = {pool.submit(dl, m): m for m in todo}
        for fut in as_completed(futs):
            md5 = futs[fut]
            try:
                res = fut.result()
            except Exception:
                continue
            if not res:
                print(f"  ! {md5[:12]} download failed")
                continue
            _, data, pid = res
            ext = cdn_ext(data)
            # 文件名 = 仅favorites序号 (md5 只存 JSON)
            idx = fav_order.get(md5)
            fn = f"{idx+1:03d}.{ext}" if idx is not None else f"{md5}.{ext}"
            # 扁平存储: 全部直接放 favorite/ 根目录
            with open(os.path.join(fav_dir, fn), "wb") as f:
                f.write(data)
            favorites.append({"md5": md5, "sort": idx + 1 if idx is not None else None,
                              "product_id": pid, "file": f"favorite/{fn}",
                              "ext": ext, "size": len(data), "source": "cdn"})
            n_ok += 1
    print(f"[*] CDN filled: {n_ok}/{len(todo)}")
    return n_ok


# ==================== 主流程 ====================
def favorites_only_export(data_dir, out_dir, db=None):
    """本地文件密钥不可用时 (新版微信派生方案变更): 解密 emoticon.db + CDN 下载收藏表情"""
    os.makedirs(out_dir, exist_ok=True)
    db_path = db
    tmp_db = None
    if not db_path:
        tmp_db = os.path.join(out_dir, "_emoticon_latest.db")
        db_path = decrypt_emoticon_db(data_dir, tmp_db) or find_db()
    favorites = []
    if db_path:
        print(f"[*] emoticon.db: {db_path}")
        cdn_fill_favorites(db_path, os.path.join(out_dir, "favorite"), favorites)
    else:
        print("[!] no emoticon.db available, cannot download favorites")
    if tmp_db and os.path.isfile(tmp_db):
        os.remove(tmp_db)
    favorites.sort(key=lambda s: s.get("sort") or 0)
    result = {"packs": {}, "favorites": favorites, "unknown": [],
              "summary": {"packs": 0, "stickers": 0, "favorites": len(favorites),
                          "unknown": 0, "total": len(favorites)}}
    json.dump(result, open(os.path.join(out_dir, "manifest.json"), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f"[*] manifest: {result['summary']}")
    print(f"[OK] favorites-only export done, output: {out_dir}")
    return result


def run_export(data_dir, wxid, emo_dir, out_dir="emoticon_export", key_hex=None,
               seed=None, db=None, no_cdn=False, no_wxgf=False, keep=False, notype=False):
    """表情包全通路导出 (Decrypting + 分割 + 命名 + CDN favorites + manifest)"""
    t0 = time.time()
    if not emo_dir or not os.path.isdir(emo_dir):
        print("[!] emoticon dir not found")
        return None
    # 取 C0 probe
    c0 = None
    for root, dirs, names in os.walk(emo_dir):
        for n in names:
            p = os.path.join(root, n)
            if os.path.getsize(p) >= 16:
                c0 = open(p, 'rb').read(16)
                break
        if c0:
            break
    if not c0:
        print("[!] no emoticon files")
        return None
    # 密钥
    if key_hex:
        key = bytes.fromhex(key_hex)
        print(f"[*] Using provided key: {key.hex()}")
    elif seed:
        key = derive_key(seed, wxid)
        print(f"[*] Using seed {seed} -> key: {key.hex()}")
    else:
        found = find_key_from_memory(c0, wxid)
        if not found:
            print("[!] Memory scan found no emoticon key")
            print("    Note: WeChat must be running; or use --key <hex> offline")
            # 新版微信可能已变更密钥派生方案: 降级为 DB + CDN 收藏导出
            return favorites_only_export(data_dir, out_dir, db)
        seed, key = found
        print(f"\n[+] HIT! seed={seed}")
        print(f"[+] emoticon key = {key.hex()}")
        print(f"[+] md5 input = {seed}{wxid}EMOTICON")

    # 解密全部文件
    print('\n[*] 解密表情文件...')
    dec_dir = os.path.join(out_dir, "_decrypted")
    decrypt_all(emo_dir, key, dec_dir)

    # 容器分割
    print('\n[*] 分割容器...')
    extracted = extract_store(dec_dir, out_dir)

    # db 匹配 + 命名
    print('\n[*] DB 匹配与命名...')
    db_path = db
    tmp_db = None
    if not db_path:
        tmp_db = os.path.join(out_dir, "_emoticon_latest.db")
        db_path = decrypt_emoticon_db(data_dir, tmp_db)
        if not db_path:
            db_path = find_db()
    if db_path:
        print(f"[*] emoticon.db: {db_path}")
    result = match_and_name(dec_dir, extracted, db_path, out_dir, do_wxgf=not no_wxgf)

    # CDN favorites
    if not no_cdn and db_path:
        print('\n[*] CDN 下载收藏...')
        cdn_fill_favorites(db_path, os.path.join(out_dir, "favorite"), result["favorites"])

    # 清理 + 结构化 manifest
    if not keep:
        shutil.rmtree(dec_dir, ignore_errors=True)
        shutil.rmtree(os.path.join(out_dir, "store_extra"), ignore_errors=True)
        if tmp_db and os.path.isfile(tmp_db):
            os.remove(tmp_db)
    n_stickers = sum(len(p["stickers"]) for p in result["packs"].values())
    result["packs"] = {k: result["packs"][k] for k in sorted(result["packs"])}
    for pack in result["packs"].values():
        pack["stickers"].sort(key=lambda s: (s.get("sort") or 0, s.get("caption") or ""))
    result["favorites"].sort(key=lambda s: s.get("sort") or 0)
    result["unknown"].sort(key=lambda s: s.get("md5") or "")
    result["summary"] = {
        "packs": len(result["packs"]),
        "stickers": n_stickers,
        "favorites": len(result["favorites"]),
        "unknown": len(result["unknown"]),
        "total": n_stickers + len(result["favorites"]) + len(result["unknown"]),
    }
    json.dump(result, open(os.path.join(out_dir, "manifest.json"), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f"\n[*] manifest: {result['summary']}")

    # 可选: 全量平铺输出 (emoticon_export_all/)
    if notype:
        flat = os.path.join(os.path.dirname(os.path.abspath(out_dir)), "emoticon_export_all")
        os.makedirs(flat, exist_ok=True)
        clean_n = lambda s: re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', str(s)).strip() or 'untitled'

        def _link_or_copy(src, dst):
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)

        used = set()
        n_flat = 0

        def uniq(base, ext):
            name = f"{base}.{ext}"
            k = 2
            while name in used:
                name = f"{base}_{k}.{ext}"
                k += 1
            used.add(name)
            return name

        for pname, pack in result["packs"].items():
            for s in pack["stickers"]:
                base = clean_n(f"{pname}_{s.get('caption') or s['md5']}")
                fn = uniq(base, s["ext"])
                _link_or_copy(os.path.join(out_dir, s["file"]), os.path.join(flat, fn))
                s["flat"] = fn
                n_flat += 1
        for f in result["favorites"]:
            base = f"favorite_{f['sort']:03d}" if f.get("sort") is not None else f"favorite_{f['md5']}"
            fn = uniq(base, f["ext"])
            _link_or_copy(os.path.join(out_dir, f["file"]), os.path.join(flat, fn))
            f["flat"] = fn
            n_flat += 1
        for i in result["unknown"]:
            fn = uniq(i["md5"], i["ext"])
            _link_or_copy(os.path.join(out_dir, i["file"]), os.path.join(flat, fn))
            i["flat"] = fn
            n_flat += 1
        json.dump(result, open(os.path.join(out_dir, "manifest.json"), 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        # 只保留平铺output: manifest 移入 flat, 删除默认目录
        if os.path.isfile(os.path.join(out_dir, "manifest.json")):
            _link_or_copy(os.path.join(out_dir, "manifest.json"), os.path.join(flat, "manifest.json"))
        shutil.rmtree(out_dir, ignore_errors=True)
        print(f"[*] Flattened output (--notype): {n_flat} files -> {flat}")
    print(f"[OK] 完成 in {time.time()-t0:.0f}s, 输出: {out_dir if not notype else flat}")
    return result


# ==================== 自检 ====================
def _selftest():
    """内置自检: 密钥派生/验证一致性 + 容器分割器。无需微信与真实数据。"""
    from Crypto.Cipher import AES
    seed, wxid = 123456789, "wxid_selftest"
    key = derive_key(seed, wxid)
    assert len(key) == 16, "派生密钥长度应为 16 字节"
    assert derive_key(seed, wxid) == key, "派生必须确定性"
    plain = b"GIF89a" + b"\x00" * 10
    c0 = AES.new(key, AES.MODE_CBC, key).encrypt(plain)
    assert verify_key(key, c0), "verify_key 正例失败"
    assert not verify_key(derive_key(seed + 1, wxid), c0), "verify_key 接受了错误密钥"
    # 最小合法 GIF: 签名6 + 屏幕描述7 + 图像描述符10 + LZW码长1 + 子块4 + trailer1
    gif = (b"GIF87a" + b"\x01\x00\x01\x00\x00\x00\x00"
           + b"\x2C" + b"\x00" * 9 + b"\x02" + b"\x02\xAA\xBB" + b"\x00" + b"\x3B")
    parts = split_container(gif + b"\x89PNG" + b"junk")  # 尾部巧合魔数必须被忽略
    assert parts == [gif], f"容器分割失败: {parts!r}"
    print("[OK] 自检通过: 密钥派生/验证、容器分割")


# ==================== 入口 ====================
def main():
    ap = argparse.ArgumentParser(
        description="微信表情包独立导出模块 (不含 V2 图片与全库解密; 无参数运行 = 自动定位后全通路导出)")
    ap.add_argument("--data-dir", help="WeChat data dir (xwechat_files/wxid_xxx_b487)")
    ap.add_argument("--db", help="path to a decrypted emoticon.db")
    ap.add_argument("--key", help="provide key (hex), skip memory scan")
    ap.add_argument("--seed", type=int, help="provide account seed (skip memory scan)")
    ap.add_argument("--out", default="emoticon_export", help="output directory")
    ap.add_argument("--no-cdn", action="store_true", help="skip CDN favorites")
    ap.add_argument("--no-wxgf", action="store_true", help="skip wxgf transcoding")
    ap.add_argument("--notype", action="store_true",
                    help="flatten-only output to emoticon_export_all/ (会删除默认输出目录)")
    ap.add_argument("--keep-decrypted", action="store_true", help="keep intermediate decrypted files")
    ap.add_argument("--selftest", action="store_true", help="运行内置自检 (无需微信与真实数据)")
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return

    data_dir = args.data_dir or find_data_dir()
    if not data_dir:
        print("[!] 未找到微信数据目录, 请用 --data-dir 指定")
        return
    wxid = auto_wxid(data_dir)
    emo_dir = find_emoticon_dir(data_dir)
    print(f"[*] 数据目录: {data_dir}")
    print(f"[*] wxid: {wxid}")
    print(f"[*] 表情目录: {emo_dir}")
    run_export(data_dir, wxid, emo_dir, args.out, args.key, args.seed,
               args.db, args.no_cdn, args.no_wxgf, args.keep_decrypted, args.notype)


if __name__ == "__main__":
    main()
