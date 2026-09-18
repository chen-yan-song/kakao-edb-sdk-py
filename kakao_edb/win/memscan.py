"""Windows 运行态内存取钥（对齐 JS 版 collectKeysToCache / scanMemoryForKeys）。

原理：
    新版 KakaoTalk 每个聊天室 EDB 密钥独立，仅在打开过该房间时驻留内存。
    SQLCipher 4 密钥为 32 字节 raw key，内存里通常紧邻 cipher context 结构，
    且 context 中携带对应 EDB 的 page1 头（探针头）作为验证材料。

流程：
    1. OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) 打开 KakaoTalk.exe
    2. VirtualQueryEx 枚举 MEM_COMMIT + 可读区域
    3. ReadProcessMemory 分块（4MB）扫描，定位探针头命中点
    4. 在命中点 ±64KB 窗口内提取 32 字节对齐候选密钥（窗口即领域过滤，候选数有上限）
    5. 进程内 AES 页头预筛给候选排序（可选，依赖 cryptography；~10μs/个），
       再用 sqlcipher verify_key 对「可读副本」逐个精验，通过者入缓存
       （运行态 live 文件被反取证保护读不了，验证优先用退出态快照副本；
        预筛只调顺序不删候选，命不中时退回逐个子进程验证，正确性不受影响）

依赖：纯 ctypes（Windows API），无需 pywin32。
限制：
    - 需管理员权限或同用户会话（PROCESS_VM_READ 对同用户进程通常足够）
    - 杀软/主动防御会拦截 ReadProcessMemory（需加白名单）
    - 仅能解出「点进过」的聊天室（密钥未驻留内存的房间无法提取）
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..cache import Cache
from ..db import sqlcipher_page
from ..db.sqlcipher import verify_key
from .discover import EdbEntry, find_kakao_pids
from .probe import EdbState, build_probe_heads, probe_edb_state

log = logging.getLogger(__name__)

# ---- Win32 常量 ----
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGE_READABLE = (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)  # R / RW / RX / RWX 等

CHUNK_SIZE = 4 * 1024 * 1024      # 4MB 分块读取
KEY_WINDOW = 64 * 1024            # 探针头命中点前后扫描窗口
SQLCIPHER_KEY_LEN = 32            # SQLCipher 4 raw key 长度
MAX_CANDIDATES_PER_HIT = 1024     # 单次探针命中的候选上限（每个候选需起一次 sqlcipher 子进程验证）


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


@dataclass
class KeyHit:
    edb_name: str
    key_hex: str
    pid: int
    address: int


@dataclass
class CollectKeysResult:
    ok: bool
    hits: list[KeyHit] = field(default_factory=list)
    key_count: int = 0
    reason: str = ""
    detail: str = ""


def _is_windows() -> bool:
    return os.name == "nt"


def _open_process(pid: int) -> wt.HANDLE | None:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    return wt.HANDLE(h) if h else None


def _enum_regions(h_process: wt.HANDLE) -> list[tuple[int, int]]:
    """枚举进程内存中 MEM_COMMIT + 可读 + 非 GUARD 的区域 [(base, size), ...]。"""
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    regions: list[tuple[int, int]] = []
    max_addr = 0x7FFFFFFEFFFF  # 用户态上限（x64）
    while addr < max_addr:
        ret = kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if size == 0:
            break
        # 宽松过滤：只排除 GUARD / NOACCESS，其余交给 ReadProcessMemory 自行失败，
        # 避免 Protect 位组合异常（如 WOW64/结构截断）时把可读区域整片漏掉。
        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)):
            regions.append((base, size))
        addr = base + size
    return regions


def _read_memory(h_process: wt.HANDLE, address: int, size: int) -> bytes | None:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address),
                                    buf, size, ctypes.byref(read))
    if not ok:
        return None
    return buf.raw[: read.value]


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    """返回 needle 在 haystack 中所有出现位置。"""
    out: list[int] = []
    start = 0
    nlen = len(needle)
    if nlen == 0:
        return out
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def _extract_key_candidates(window: bytes, cap: int = MAX_CANDIDATES_PER_HIT) -> list[bytes]:
    """在窗口内提取 32 字节对齐的候选密钥（去重，最多 cap 个）。

    重要：纯统计过滤（零字节数/字节多样性/可打印占比）对加密堆区几乎没有区分力——
    KakaoTalk 500MB+ 堆里高熵随机数据天然全部通过，若对整堆做统计筛选会累积到千万级
    候选并撑爆内存。因此这里只在「探针头命中点 ±KEY_WINDOW」的小窗口内取候选（窗口本身
    就是领域过滤），并用 cap 兜底，避免每个候选都要起一次 sqlcipher 子进程验证导致耗时爆炸。
    生产优化方向：用探针页做进程内 AES-CBC 页头校验（~1μs/候选）替代子进程 verify_key。
    """
    cands: set[bytes] = set()
    wlen = len(window)
    for off in range(0, wlen - SQLCIPHER_KEY_LEN + 1, 8):
        chunk = window[off: off + SQLCIPHER_KEY_LEN]
        # 快速过滤：全零 / 全同字节 / 可打印 ASCII 占比过高 → 不像密钥
        if chunk == b"\x00" * SQLCIPHER_KEY_LEN:
            continue
        if len(set(chunk)) < 8:
            continue
        printable = sum(1 for b in chunk if 32 <= b < 127)
        if printable > SQLCIPHER_KEY_LEN * 0.75:
            continue
        cands.add(chunk)
        if len(cands) >= cap:
            break
    return list(cands)


def _prioritize_candidates(cands: list[bytes], probe_head: bytes) -> list[bytes]:
    """用进程内 AES 页头预筛给候选排序：像真钥的排前面，其余保持原序在后。

    预筛只影响验证「顺序」，不删任何候选——sqlcipher 子进程仍会逐个精验，
    因此即便预筛假设与真实 KakaoTalk 不符（命不中），真钥也不会被漏掉，
    只是退回到「逐个子进程验证」的原速。cryptography 不可用时直接原序返回。
    """
    if not cands or not sqlcipher_page.available() or len(probe_head) < 4096:
        return cands
    hits: list[bytes] = []
    miss: list[bytes] = []
    for c in cands:
        if sqlcipher_page.check_page1_key(probe_head, c):
            hits.append(c)
        else:
            miss.append(c)
    if hits:
        log.debug("AES 页头预筛命中 %d/%d 个候选，优先精验", len(hits), len(cands))
    return hits + miss


def _resolve_verify_path(edb: EdbEntry, cache: Cache) -> Path | None:
    """选择可用于 sqlcipher 验证的可读 EDB 副本。

    运行态 live 文件常被反取证保护（全零/独占锁），sqlcipher 根本读不了，
    拿 live 验证会导致「永远验不过、一把密钥都收不到」。优先用退出态快照副本，
    其次 live（仅当探测为 NORMAL 可读）。
    """
    snap = cache.snapshot_path(edb.name)
    try:
        if snap.exists() and snap.stat().st_size > 0:
            return snap
    except OSError:
        pass
    st = probe_edb_state(edb.path, read_head=False)
    if st.state == EdbState.NORMAL and edb.path.exists():
        return edb.path
    return None


def collect_keys_to_cache(
    edbs: list[EdbEntry],
    cache: Cache,
    on_progress: Callable[[str, str], None] | None = None,
    max_pids: int = 4,
) -> CollectKeysResult:
    """运行态从 KakaoTalk 进程内存提取密钥存入缓存。

    edbs: 待取钥的 EDB 清单（用于构建探针头 + 验证密钥）。
    on_progress(stage, detail): 进度回调。
    """
    if not _is_windows():
        return CollectKeysResult(False, reason="platform",
                                 detail="内存取钥仅在 Windows 平台可用")

    pids = find_kakao_pids()[:max_pids]
    if not pids:
        return CollectKeysResult(False, reason="no-process",
                                 detail="未找到 KakaoTalk.exe 进程（请先启动并登录，点开目标聊天室）")

    def _report(stage: str, detail: str) -> None:
        if on_progress:
            try:
                on_progress(stage, detail)
            except Exception:
                pass

    # 1. 构建探针头：优先实时读取（运行态可能 ZEROED/LOCKED），回退到探针缓存
    _report("probe", "构建 EDB 探针头…")
    live_probes = build_probe_heads([e.path for e in edbs])
    cached_probes = cache.load_probes()
    probes: dict[str, bytes] = {}
    verify_paths: dict[str, Path] = {}  # edbName -> 可读副本（sqlcipher 验证用）
    for edb in edbs:
        hex_head = live_probes.get(edb.name) or cached_probes.get(edb.name)
        if not hex_head:
            continue
        try:
            probes[edb.name] = bytes.fromhex(hex_head)
        except ValueError:
            continue
        vpath = _resolve_verify_path(edb, cache)
        if vpath is not None:
            verify_paths[edb.name] = vpath
    if not probes:
        return CollectKeysResult(False, reason="no-probes",
                                 detail="无可用探针头（EDB 均被运行时保护且无探针缓存，请先退出 KakaoTalk 做一次快照）")
    if not verify_paths:
        return CollectKeysResult(False, reason="edb-protected",
                                 detail="EDB 运行态被保护且无退出态快照可供验证，请先完全退出 KakaoTalk 做一次快照")

    # 合并实时探针到缓存（供后续运行态复用）
    if live_probes:
        merged = {**cached_probes, **live_probes}
        cache.save_probes(merged)

    edb_by_name = {e.name: e for e in edbs}  # 保留：供日志/调试引用
    all_hits: list[KeyHit] = []
    keys_to_cache: dict[str, str] = {}
    existing_keys = cache.load_keys()

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    for pid in pids:
        h_proc = _open_process(pid)
        if not h_proc:
            log.warning("OpenProcess 失败 pid=%d（权限不足？）", pid)
            continue
        try:
            regions = _enum_regions(h_proc)
            total_bytes = sum(sz for _, sz in regions)
            _report("scan", f"pid={pid} 枚举 {len(regions)} 个可读区域（{total_bytes/1024/1024:.0f} MB）")

            scanned = 0
            for base, size in regions:
                for off in range(0, size, CHUNK_SIZE):
                    read_size = min(CHUNK_SIZE, size - off)
                    if read_size < 64:
                        break
                    chunk = _read_memory(h_proc, base + off, read_size)
                    scanned += read_size
                    if chunk is None:
                        continue
                    # 对每个探针头在 chunk 中定位
                    for edb_name, head in probes.items():
                        if edb_name in existing_keys and edb_name not in keys_to_cache:
                            continue  # 已有缓存密钥，跳过
                        vpath = verify_paths.get(edb_name)
                        if vpath is None:
                            continue  # 无可读副本，无法验证，跳过该库
                        for hit_off in _find_all(chunk, head[:256]):  # 用前 256B 定位即可
                            abs_addr = base + off + hit_off
                            # 取命中点前后 KEY_WINDOW 窗口，并夹在本 region 内，
                            # 避免跨未映射地址导致 ReadProcessMemory 整段失败。
                            w_start = max(base, abs_addr - KEY_WINDOW)
                            w_end = min(base + size, abs_addr + KEY_WINDOW)
                            if w_end <= w_start:
                                continue
                            window = _read_memory(h_proc, w_start, w_end - w_start)
                            if not window:
                                continue
                            cands = _extract_key_candidates(window)
                            # 进程内 AES 页头预筛排序：真钥大概率排第一，子进程只需验 1 次
                            for cand in _prioritize_candidates(cands, head):
                                key_hex = cand.hex()
                                _report("verify", f"验证 {edb_name} 候选密钥 {key_hex[:16]}…")
                                if verify_key(vpath, key_hex):
                                    log.info("命中密钥 edb=%s pid=%d addr=0x%x", edb_name, pid, abs_addr)
                                    all_hits.append(KeyHit(edb_name, key_hex, pid, abs_addr))
                                    keys_to_cache[edb_name] = key_hex
                                    break
                            if edb_name in keys_to_cache:
                                break
                _report("scan", f"pid={pid} 已扫描 {scanned/1024/1024:.0f}/{total_bytes/1024/1024:.0f} MB")
        finally:
            kernel32.CloseHandle(h_proc)

    if not all_hits:
        return CollectKeysResult(False, reason="no-keys",
                                 detail="未在 KakaoTalk 进程内存中找到可验证的密钥（请确认已点开目标聊天室）")

    added = cache.merge_keys(keys_to_cache)
    total_keys = len(cache.load_keys())
    _report("done", f"命中 {len(all_hits)} 把，新增缓存 {added}，累计 {total_keys}")
    return CollectKeysResult(True, hits=all_hits, key_count=total_keys)
