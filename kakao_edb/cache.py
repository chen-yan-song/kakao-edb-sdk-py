"""缓存目录读写（对齐 JS 版 winKakao.initCacheDir / loadJson / saveJson）。

默认缓存目录 ~/.kakao-edb-sdk，可通过 create_session(cache_dir=...) 或环境变量覆盖。
缓存内容：
    win-key-cache.json       Windows 内存取钥结果（{edbName: keyHex}，明文敏感）
    win-probe-cache.json     每库页1前 4096B 探针头（退出态快照时写入）
    snapshot/                退出态 EDB 快照副本（含 -wal/-shm/-journal）
    mac-userid-cache.json    macOS userId 还原结果（{userId, uuid, source, cachedAt}）
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path.home() / ".kakao-edb-sdk"

WIN_KEY_CACHE = "win-key-cache.json"
WIN_PROBE_CACHE = "win-probe-cache.json"
MAC_USERID_CACHE = "mac-userid-cache.json"
SNAPSHOT_DIR = "snapshot"


class Cache:
    def __init__(self, root: str | Path | None = None) -> None:
        env = os.environ.get("KAKAO_EDB_CACHE_DIR")
        self.root = Path(root or env or DEFAULT_CACHE_DIR).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / SNAPSHOT_DIR).mkdir(parents=True, exist_ok=True)

    # ---- JSON 读写 ----
    def load_json(self, name: str, default: Any = None) -> Any:
        p = self.root / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as ex:
            log.warning("缓存 %s 解析失败: %s", name, ex)
            return default

    def save_json(self, name: str, data: Any) -> None:
        p = self.root / name
        try:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as ex:
            log.warning("缓存 %s 写入失败: %s", name, ex)

    # ---- 密钥缓存 ----
    def load_keys(self) -> dict[str, str]:
        return self.load_json(WIN_KEY_CACHE, {}) or {}

    def save_keys(self, keys: dict[str, str]) -> None:
        self.save_json(WIN_KEY_CACHE, keys)

    def merge_keys(self, new_keys: dict[str, str]) -> int:
        cur = self.load_keys()
        before = len(cur)
        cur.update(new_keys)
        self.save_keys(cur)
        return len(cur) - before

    # ---- 探针缓存 ----
    def load_probes(self) -> dict[str, str]:
        """{edbName: hex(page1[:4096])}"""
        return self.load_json(WIN_PROBE_CACHE, {}) or {}

    def save_probes(self, probes: dict[str, str]) -> None:
        self.save_json(WIN_PROBE_CACHE, probes)

    # ---- 快照 ----
    @property
    def snapshot_dir(self) -> Path:
        return self.root / SNAPSHOT_DIR

    def snapshot_path(self, name: str) -> Path:
        return self.snapshot_dir / name

    def list_snapshot(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.snapshot_dir.exists():
            return out
        for p in sorted(self.snapshot_dir.iterdir()):
            if p.is_file():
                out.append({"name": p.name, "path": p, "size": p.stat().st_size,
                            "mtime": int(p.stat().st_mtime * 1000)})
        return out

    def clear_snapshot(self) -> None:
        if self.snapshot_dir.exists():
            shutil.rmtree(self.snapshot_dir, ignore_errors=True)
            self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def snapshot_at(self) -> int | None:
        files = self.list_snapshot()
        return max((f["mtime"] for f in files), default=None)

    # ---- macOS userId 缓存 ----
    def load_mac_userid(self) -> dict[str, Any] | None:
        return self.load_json(MAC_USERID_CACHE, None)

    def save_mac_userid(self, user_id: str | int, uuid: str, source: str) -> None:
        self.save_json(MAC_USERID_CACHE, {
            "userId": str(user_id), "uuid": uuid, "source": source,
            "cachedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
