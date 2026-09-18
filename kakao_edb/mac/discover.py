"""macOS 自动发现与 userId 爆破（对齐 src/mac/discover.cjs）。

- discover(): IOPlatformUUID(ioreg) + KakaoTalk 运行态(pgrep) + 偏好 plist + 数据库目录扫描
- brute_user_id(): 多进程 SHA-512 爆破还原 userId（multiprocessing + Event 中止）

plist 读取走子进程 cat + 3s 超时（TCC 未授权时系统会挂起读取，超时降级 plist=None
且 plist_timed_out=True，进程不再卡死）——与 JS 版策略一致。
"""
from __future__ import annotations

import hashlib
import logging
import multiprocessing as mp
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

KAKAO_CONTAINER = Path.home() / "Library/Containers/com.kakao.KakaoTalkMac/Data/Library"
PLIST_PATH = KAKAO_CONTAINER / "Preferences/com.kakao.KakaoTalkMac.plist"
DB_DIR = KAKAO_CONTAINER / "Application Support/com.kakao.KakaoTalkMac"

_SIDE_SUFFIX_RE = re.compile(r"-(wal|shm|journal)$", re.I)
# 主库文件名：40+ 位长十六进制（PBKDF2 派生命名）
_MAIN_NAME_RE = re.compile(r"^[0-9a-f]{40,}$", re.I)


@dataclass
class DbFile:
    name: str
    path: Path
    size: int
    is_side: bool


@dataclass
class DiscoverResult:
    uuid: str | None
    running: bool
    plist: bytes | None
    plist_exists: bool
    plist_timed_out: bool
    plist_path: Path
    db_dir: Path
    db_files: list[DbFile] = field(default_factory=list)


def get_platform_uuid(timeout: int = 8) -> str | None:
    """ioreg 读取 IOPlatformUUID。"""
    try:
        proc = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    m = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', proc.stdout or "")
    return m.group(1) if m else None


def is_kakao_running(timeout: int = 5) -> bool:
    try:
        proc = subprocess.run(["pgrep", "-xq", "KakaoTalk"],
                              capture_output=True, timeout=timeout, check=False)
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def scan_db_dir(db_dir: Path = DB_DIR) -> list[DbFile]:
    out: list[DbFile] = []
    if not db_dir.exists():
        return out
    for entry in db_dir.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        is_side = bool(_SIDE_SUFFIX_RE.search(name))
        if not is_side and not _MAIN_NAME_RE.match(name):
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        out.append(DbFile(name=name, path=entry, size=size, is_side=is_side))
    out.sort(key=lambda f: -f.size)
    return out


def _read_plist_with_timeout(path: Path, timeout: float = 3.0) -> tuple[bytes | None, bool, bool]:
    """返回 (data, exists, timed_out)。走子进程 cat 规避 TCC 挂起。"""
    if not path.exists():
        return None, False, False
    try:
        proc = subprocess.run(["/bin/cat", str(path)], capture_output=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            return None, True, False
        return proc.stdout, True, False
    except subprocess.TimeoutExpired:
        return None, True, True
    except FileNotFoundError:
        # 极端兜底：直接读
        try:
            return path.read_bytes(), True, False
        except Exception:
            return None, True, False


def discover(db_dir: Path = DB_DIR, plist_path: Path = PLIST_PATH) -> DiscoverResult:
    if sys.platform != "darwin":
        raise RuntimeError("macOS 自动发现仅在 darwin 平台可用")
    uuid = get_platform_uuid()
    running = is_kakao_running()
    plist, exists, timed_out = _read_plist_with_timeout(plist_path)
    return DiscoverResult(
        uuid=uuid, running=running, plist=plist,
        plist_exists=exists, plist_timed_out=timed_out,
        plist_path=plist_path, db_dir=db_dir, db_files=scan_db_dir(db_dir),
    )


# ============ 多进程 SHA-512 爆破 userId ============

_brute_stop: mp.Event | None = None  # 当前爆破任务的中止标志（单任务模式）


def _brute_worker(hash_hex: str, start: int, end: int,
                  stop_event: Any, progress_q: Any, result_q: Any, worker_idx: int) -> None:
    """子进程：遍历 [start, end) 找 SHA-512(str(n)) == hash_hex 的 n。"""
    target = bytes.fromhex(hash_hex)
    local_sha = hashlib.sha512
    checked = 0
    last_report = time.time()
    for n in range(start, end):
        if stop_event.is_set():
            break
        if local_sha(str(n).encode("ascii")).digest() == target:
            result_q.put(("found", worker_idx, n))
            return
        checked += 1
        now = time.time()
        if now - last_report >= 0.2:
            progress_q.put((worker_idx, checked))
            checked = 0
            last_report = now
    progress_q.put((worker_idx, checked))
    # checked 已经由 progress_q 增量上报，done 仅作完成信号（val 恒为 0），避免重复计数
    result_q.put(("done", worker_idx, 0))


@dataclass
class BruteResult:
    found: int | None
    checked: int = 0
    aborted: bool = False
    error: str | None = None


def brute_user_id(hash_hex: str, start: int = 0, end: int = 1_000_000_000,
                  on_progress: Callable[[dict[str, Any]], None] | None = None,
                  max_workers: int | None = None) -> BruteResult:
    """多进程爆破还原 userId。

    hash_hex: SHA-512(str(userId)) 的 128 位 hex 字符串。
    on_progress({"checked", "total", "elapsed"}): 进度回调（约 150ms 一次）。
    """
    global _brute_stop
    if not re.fullmatch(r"[0-9a-fA-F]{128}", hash_hex or ""):
        return BruteResult(found=None, error="哈希格式不合法（需 128 位 hex）")

    # 取消旧任务
    if _brute_stop is not None:
        try:
            _brute_stop.set()
        except Exception:
            pass

    ctx = mp.get_context("spawn")
    stop_event = ctx.Event()
    _brute_stop = stop_event

    n_workers = max_workers or min(12, max(2, (os.cpu_count() or 2) - 1))
    total = max(1, end - start)
    chunk = (total + n_workers - 1) // n_workers

    progress_q: Any = ctx.Queue()
    result_q: Any = ctx.Queue()
    procs: list[mp.Process] = []
    launched = 0
    for t in range(n_workers):
        w_start = start + t * chunk
        w_end = min(end, w_start + chunk)
        if w_start >= w_end:
            continue
        p = ctx.Process(target=_brute_worker,
                        args=(hash_hex.lower(), w_start, w_end, stop_event,
                              progress_q, result_q, t), daemon=True)
        p.start()
        procs.append(p)
        launched += 1

    if launched == 0:
        return BruteResult(found=None, checked=0)

    positions = [0] * launched
    started_at = time.time()
    last_send = 0.0
    finished = 0
    found: int | None = None
    aborted = False

    def send_progress(force: bool = False) -> None:
        nonlocal last_send
        if not on_progress:
            return
        now = time.time()
        if not force and now - last_send < 0.15:
            return
        last_send = now
        on_progress({"checked": sum(positions), "total": total,
                     "elapsed": int((now - started_at) * 1000)})

    try:
        while finished < launched:
            # 优先处理结果队列
            try:
                msg = result_q.get(timeout=0.05)
            except Exception:
                msg = None
            if msg:
                kind, idx, val = msg
                if kind == "found":
                    found = int(val)
                    positions[idx] = int(val) - (start + idx * chunk)
                    stop_event.set()
                    aborted = False
                    break
                if kind == "done":
                    finished += 1  # val 恒为 0；进度已由 progress_q 增量累加，勿重复计
            # 再消费进度
            drained = 0
            while drained < 256:
                try:
                    pidx, pchecked = progress_q.get_nowait()
                    positions[pidx] += pchecked
                    drained += 1
                except Exception:
                    break
            send_progress()
            if stop_event.is_set() and found is None:
                aborted = True
                break
    finally:
        # 收尾：把队列里剩余的进度增量全部累加，避免 sum(positions) 少计
        while True:
            try:
                pidx, pchecked = progress_q.get_nowait()
                if 0 <= pidx < len(positions):
                    positions[pidx] += pchecked
            except Exception:
                break
        send_progress(force=True)
        stop_event.set()
        for p in procs:
            p.join(timeout=1.0)
            if p.is_alive():
                p.terminate()

    return BruteResult(found=found, checked=sum(positions), aborted=aborted)


def stop_brute() -> bool:
    """中止当前爆破任务。"""
    global _brute_stop
    if _brute_stop is not None:
        _brute_stop.set()
        return True
    return False
