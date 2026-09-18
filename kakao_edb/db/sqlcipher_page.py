"""SQLCipher 4 page-1 头特征的进程内快速校验（可选加速，依赖 cryptography）。

用途
----
Windows 运行态内存取钥时，对「探针头命中点 ±窗口」内的每个 32 字节候选密钥，
先用一次 AES-256-CBC 解密 page1 首块、校验 SQLite 头特征（~10μs/个），把极少数
「像真钥」的候选排到最前，再交给 sqlcipher 子进程精验。避免对上千候选逐个起子进程
（每个子进程 ~50ms，1024 个就是 ~50s）。

安全边界（重要）
----------------
本模块只做「优先级排序 / 预筛」，**不替代** sqlcipher verify_key 的最终判定：
  - cryptography 不可用 → available() 返回 False，调用方跳过预筛，行为退化为
    「逐个子进程验证」（与未引入本模块前完全一致）。
  - page 布局假设与真实 KakaoTalk 不符（校验恒不过）→ 预筛命不中任何候选，
    调用方仍会按原顺序把全部候选交给子进程验证，真钥不会被漏掉，仅失去加速。
即：预筛最坏情况 = 没提速，绝不会影响正确性。

SQLCipher 4 page-1 布局假设（需实机确认；参数不符时预筛自动失效但不报错）
--------------------------------------------------------------------------
    page1[0:16]                          = salt（raw key 模式下不参与 KDF，但占位）
    page1[16 : ps-reserve]               = AES-256-CBC(原始 header[16:])
    page1[ps-reserve : ps-reserve+16]    = IV（每页随机，存于 reserve 区首部）
    reserve                              = 48（IV 16 + HMAC-SHA512 截断 32）
解密首块后应得到原始 SQLite header[16:32]，其强特征字段：
    [16:18] page size ∈ 合法集合, [18] write ver ∈ {1,2}, [19] read ver ∈ {1,2},
    [20] reserved space == 48, [21]==64, [22]==32, [23]==32
这些字段联合误报率约 2^-30，足以把千万级窗口收敛到个位数候选。
"""
from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

try:  # 可选加速依赖：缺失时预筛整体降级为 no-op，不影响正确性
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - 取决于运行环境
    _HAS_CRYPTO = False

_VALID_PAGE_SIZES = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
SQLCIPHER4_RESERVE = 48
DEFAULT_PAGE_SIZE = 4096


def available() -> bool:
    """cryptography 是否可用（不可用时调用方应跳过预筛）。"""
    return _HAS_CRYPTO


def _ecb_decrypt_block(key: bytes, block: bytes) -> Optional[bytes]:
    """AES-256-ECB 解密单个 16 字节块。

    说明：这里用 ECB 只解密「一个块」，是手工实现 CBC 首块解密的标准构造
    （P0 = ECB_DEC(C0) XOR IV），并非用 ECB 模式加密业务数据，不存在
    「相同明文块→相同密文块」的结构泄露问题。SQLCipher 页本身就是 CBC，
    我们只需其首块做特征校验，故直接调用单块 ECB 原语最简洁。
    """
    if not _HAS_CRYPTO or len(block) != 16:
        return None
    try:
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return dec.update(block) + dec.finalize()
    except Exception:
        return None


def _valid_sqlite_header_tail(h: bytes) -> bool:
    """h == 原始 header[16:32]（16 字节）。校验 SQLCipher 4 强特征字段。"""
    if len(h) < 8:
        return False
    page_size = int.from_bytes(h[0:2], "big")
    if page_size == 1:  # SQLite 用 1 表示 65536
        page_size = 65536
    if page_size not in _VALID_PAGE_SIZES:
        return False
    if h[2] not in (1, 2) or h[3] not in (1, 2):  # write / read format version
        return False
    if h[4] != SQLCIPHER4_RESERVE:                # reserved space
        return False
    if h[5] != 64 or h[6] != 32 or h[7] != 32:    # payload fraction 常量
        return False
    return True


def check_page1_key(probe_page1: bytes, key: bytes,
                    page_size: int = DEFAULT_PAGE_SIZE,
                    reserve: int = SQLCIPHER4_RESERVE) -> bool:
    """用候选 key 解密探针 page1 首块并校验 SQLite 头特征。

    返回 True 表示「极可能是真钥」，应优先用 sqlcipher 子进程精验。
    返回 False 不代表一定不是真钥（布局假设不符时恒 False），调用方须保留子进程兜底。
    """
    if not _HAS_CRYPTO:
        return False
    if len(key) != 32:
        return False
    # 需要整页才能定位页尾 reserve 区的 IV；探针不足整页则预筛失效
    if len(probe_page1) < page_size:
        return False
    ct0 = probe_page1[16:32]
    iv = probe_page1[page_size - reserve: page_size - reserve + 16]
    dec = _ecb_decrypt_block(key, ct0)
    if dec is None:
        return False
    plain = bytes(a ^ b for a, b in zip(dec, iv))  # CBC 首块 = ECB_DEC(ct0) XOR IV
    return _valid_sqlite_header_tail(plain)
