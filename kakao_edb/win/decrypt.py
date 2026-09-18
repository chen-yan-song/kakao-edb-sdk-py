"""缓存密钥解密（对齐 JS 版 decryptWithCachedKeys）。

用 cache 中已存的 {edbName: keyHex} 对一组 EDB 逐个解密为明文 SQLite，
WAL 重放由 db.sqlcipher.decrypt_to_plain 内部处理（复制伴随文件后 sqlcipher 自动 checkpoint）。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..cache import Cache
from ..db.sqlcipher import decrypt_to_plain
from .discover import EdbEntry

log = logging.getLogger(__name__)


@dataclass
class DecryptedFile:
    name: str
    plain_path: Path
    size: int
    source: Path  # 原始 EDB 路径


@dataclass
class DecryptFilesResult:
    ok: bool
    files: list[DecryptedFile] = field(default_factory=list)
    reason: str = ""
    detail: str = ""
    key_count: int = 0


def decrypt_with_cached_keys(
    edbs: list[EdbEntry],
    cache: Cache,
    out_dir: Path | None = None,
    on_progress: Callable[[str, str], None] | None = None,
) -> DecryptFilesResult:
    """用缓存密钥解密 EDB 清单。

    out_dir: 明文产物目录；None 时使用 cache.root/decrypted/。
    on_progress(stage, detail): 进度回调。
    """
    keys = cache.load_keys()
    if not keys:
        return DecryptFilesResult(False, reason="no-keys",
                                  detail="缓存中无任何密钥，请先运行 collect-keys")

    out_dir = Path(out_dir) if out_dir else cache.root / "decrypted"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _report(stage: str, detail: str) -> None:
        if on_progress:
            try:
                on_progress(stage, detail)
            except Exception:
                pass

    files: list[DecryptedFile] = []
    missing: list[str] = []
    failed: list[str] = []

    for edb in edbs:
        key = keys.get(edb.name)
        if not key:
            missing.append(edb.name)
            continue
        if not edb.path.exists():
            missing.append(f"{edb.name}(file-gone)")
            continue
        _report("decrypt", f"解密 {edb.name}（{edb.size/1024/1024:.1f} MB）…")
        plain = out_dir / (Path(edb.name).stem + ".plain.db")
        r = decrypt_to_plain(edb.path, key, plain)
        if not r.ok or r.plain_path is None:
            log.warning("解密 %s 失败: %s", edb.name, r.reason)
            failed.append(f"{edb.name}({r.reason})")
            continue
        files.append(DecryptedFile(
            name=edb.name, plain_path=r.plain_path,
            size=r.plain_path.stat().st_size, source=edb.path,
        ))

    if not files:
        return DecryptFilesResult(
            False, reason="all-failed",
            detail=f"全部解密失败 missing={missing} failed={failed}",
            key_count=len(keys),
        )
    return DecryptFilesResult(
        True, files=files, key_count=len(keys),
        detail=f"成功 {len(files)}，缺密钥 {len(missing)}，失败 {len(failed)}",
    )
