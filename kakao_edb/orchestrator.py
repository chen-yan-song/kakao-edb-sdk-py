"""无头编排器（对齐 src/orchestrator.mjs）。

把 JS 版的 Session 状态机移植为 Python：
    - Windows 两步流：status → snapshot/collect-keys/decrypt 分支，最多 4 轮用户引导防死循环
    - macOS 全自动：UUID → userId（缓存→plist直取→爆破→候选）→ 多主库 HMAC 验证选库 → 解密

用户交互点通过 confirm(guide_text, ok_label) 钩子注入：
    CLI 用 input() 实现，程序化调用可自行实现（返回 False 即中止）。
"""
from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .cache import Cache
from .db.kakao_db import EdbFile, KakaoDB
from .db.key_derivation import derive_database_name, derive_secure_key
from .db.plist_parser import extract_user_id_info, parse_plist

log = logging.getLogger(__name__)

ConfirmFn = Callable[[str, str], bool]
StepFn = Callable[[str, str, str], None]
ProgressFn = Callable[[str, str], None]


@dataclass
class RunResult:
    ok: bool
    db: KakaoDB | None = None
    stats: dict[str, int] = field(default_factory=dict)
    reason: str = ""
    detail: str = ""
    user_id: str | int | None = None
    uuid: str | None = None


def create_session(
    cache_dir: str | Path | None = None,
    on_step: StepFn | None = None,
    on_progress: ProgressFn | None = None,
    confirm: ConfirmFn | None = None,
    platform: str | None = None,
    win_discover: Callable[[], Any] | None = None,
    mac_discover: Callable[[], Any] | None = None,
) -> "Session":
    return Session(
        cache_dir=cache_dir, on_step=on_step, on_progress=on_progress,
        confirm=confirm, platform=platform,
        win_discover=win_discover, mac_discover=mac_discover,
    )


class Session:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        on_step: StepFn | None = None,
        on_progress: ProgressFn | None = None,
        confirm: ConfirmFn | None = None,
        platform: str | None = None,
        win_discover: Callable[[], Any] | None = None,
        mac_discover: Callable[[], Any] | None = None,
    ) -> None:
        self.on_step = on_step or (lambda *_a, **_k: None)
        self.on_progress = on_progress or (lambda *_a, **_k: None)
        self.confirm = confirm or (lambda *_a, **_k: True)
        self.platform = platform or sys.platform
        self.cache = Cache(cache_dir)
        self._win_discover_override = win_discover
        self._mac_discover_override = mac_discover
        self.db: KakaoDB | None = None

    # ---- 底层引擎暴露（细粒度控制用） ----
    @property
    def win(self):
        from . import win as _win
        return _win

    @property
    def mac(self):
        from . import mac as _mac
        return _mac

    def _set_step(self, name: str, state: str, detail: str = "") -> None:
        try:
            self.on_step(name, state, detail)
        except Exception:
            pass

    # ============ 细粒度 API（Windows） ============

    def status(self):
        return self.win.win_two_step_status(self.cache)

    def snapshot(self):
        info = self.win.list_edb_files()
        return self.win.snapshot_core_edbs(info, self.cache)

    def snapshot_edbs(self):
        return self.win.load_snapshot_edbs(self.cache)

    def collect_keys(self, edbs=None):
        edbs = edbs if edbs is not None else self.win.list_edb_files()
        return self.win.collect_keys_to_cache(edbs, self.cache, self.on_progress)

    def decrypt_cached(self, edbs=None, out_dir: Path | None = None):
        edbs = edbs if edbs is not None else self.win.list_edb_files()
        return self.win.decrypt_with_cached_keys(edbs, self.cache, out_dir, self.on_progress)

    def open_unified(self, files: Iterable[EdbFile] | Iterable[Any],
                     user_id_ish: str | int, salt: str | int | None = None) -> KakaoDB:
        """把解密产物汇总为统一查询库（对齐 JS 版 openUnified）。"""
        seed = str(salt or user_id_ish or "kakao-edb-sdk")
        key = derive_secure_key(str(user_id_ish), seed)
        db = KakaoDB()
        edb_files = [self._to_edb_file(f) for f in files]
        db.open_windows(edb_files, {e.name: key for e in edb_files}, my_id=_safe_int(user_id_ish))
        self.db = db
        return db

    @staticmethod
    def _to_edb_file(f: Any) -> EdbFile:
        if isinstance(f, EdbFile):
            return f
        # 兼容 DecryptedFile / Path / dict
        if hasattr(f, "plain_path"):
            return EdbFile(name=Path(f.plain_path).name, path=Path(f.plain_path),
                           size=getattr(f, "size", 0))
        if isinstance(f, (str, Path)):
            p = Path(f)
            return EdbFile(name=p.name, path=p, size=p.stat().st_size if p.exists() else 0)
        if isinstance(f, dict):
            p = Path(f["path"])
            return EdbFile(name=f.get("name", p.name), path=p,
                           size=f.get("size", p.stat().st_size if p.exists() else 0),
                           data=f.get("data"))
        raise TypeError(f"无法识别的文件对象: {type(f)}")

    # ============ 全自动编排 ============

    def run(self) -> RunResult:
        if self.platform == "win32":
            return self.run_windows()
        if self.platform == "darwin":
            return self.run_mac()
        return RunResult(False, reason=f"不支持的平台 {self.platform}（仅 win32 / darwin）")

    # ---- Windows 两步流状态机 ----

    def run_windows(self) -> RunResult:
        from . import win as _win

        self._set_step("uuid", "active", "正在读取注册表设备信息（DeviceInfo → dev_id）…")
        try:
            disc = self._win_discover_override() if self._win_discover_override else _win.discover_windows()
        except Exception as ex:
            self._set_step("uuid", "fail", f"Windows 自动发现失败：{ex}")
            return RunResult(False, reason=str(ex))

        if not disc.dev_ok:
            self._set_step("uuid", "active", "注册表未找到设备材料——不影响新版 SQLCipher 解密，继续…")
        else:
            self._set_step("uuid", "ok", f"{len(disc.dev_ids)} 组设备材料")

        if not disc.edbs:
            self._set_step("plist", "fail",
                           f"未找到 EDB 数据文件（{disc.users_dir or disc.base_dir}）——请确认已在 KakaoTalk 中同步过聊天记录")
            return RunResult(False, reason="no-edbs")

        total_mb = sum(e.size for e in disc.edbs) / 1024 / 1024
        self._set_step("plist", "ok", f"找到 {len(disc.edbs)} 个 EDB 文件（共 {total_mb:.1f} MB）")
        self._set_step("db", "ok", f"已定位 {len(disc.edbs)} 个 EDB 文件")

        for _round in range(4):
            try:
                st = _win.win_two_step_status(self.cache)
            except Exception as ex:
                self._set_step("uid", "warn", f"状态检测失败（{ex}），回退传统解密流程…")
                return self._legacy_windows_decrypt(disc)

            self._set_step("uid", "active",
                           f"保护状态检测：运行中={'是' if st.running else '否'}，"
                           f"可读库 {st.readable}/{st.core_count}，已存密钥 {st.key_count}，快照 {st.snapshot_count}")

            # A. 文件可读且有密钥：直接解密最新落盘数据
            if st.advice == "decrypt-now":
                self._set_step("uid", "ok", f"已缓存 {st.key_count} 把密钥，数据文件可读")
                return self._legacy_windows_decrypt(disc)

            # B. 有密钥有快照：解密快照
            if st.advice == "decrypt-snapshot":
                self._set_step("uid", "ok", f"已缓存 {st.key_count} 把密钥")
                r = self._decrypt_snapshot_and_open(st)
                if r.ok:
                    return r
                self._set_step("decrypt", "warn", "快照解密失败（key 可能已轮换），重新检测状态…")
                continue

            # C. 文件可读但无密钥：先快照，再引导启动 KakaoTalk 取密钥
            if st.advice == "snapshot":
                self._set_step("db", "active", "正在复制数据快照（KakaoTalk 退出态，仅一次机会窗口）…")
                snap = self.snapshot()
                if not snap.ok:
                    self._set_step("db", "fail", f"快照复制失败：{snap.reason}")
                    return RunResult(False, reason="snapshot-failed", detail=snap.reason)
                self._set_step("db", "ok", f"快照完成：{snap.count} 个核心库（含未落盘的 WAL 数据）")
                go = self.confirm(
                    "数据快照已保存。现在请：\n"
                    "① 启动 KakaoTalk 并完成登录\n"
                    "② 点开左侧「聊天」列表\n"
                    "③ 逐个进入你需要导出的聊天室（每个房间密钥独立，进入过才会驻留内存）\n"
                    "完成后确认继续。",
                    "已完成，开始提取密钥",
                )
                if not go:
                    return RunResult(False, reason="user-aborted")
                return self._collect_and_decrypt_snapshot(disc)

            # D. 运行中、有探针缓存、无密钥：确认登录状态后直接取密钥
            if st.advice == "collect-keys":
                if not st.running:
                    go = self.confirm(
                        "请启动 KakaoTalk 并完成登录，点开「聊天」列表和需要导出的聊天室。完成后确认继续。",
                        "已启动并登录",
                    )
                    if not go:
                        return RunResult(False, reason="user-aborted")
                    continue
                go = self.confirm(
                    "KakaoTalk 运行中。请确认：已登录，且已点开「聊天」列表和需要导出的聊天室"
                    "（密钥只在打开过的房间驻留内存）。",
                    "已确认，开始提取密钥",
                )
                if not go:
                    return RunResult(False, reason="user-aborted")
                self._set_step("decrypt", "active", "正在从 KakaoTalk 进程内存提取解密密钥（约 2-5 分钟）…")
                ck = self.collect_keys(disc.edbs)
                if not ck.ok:
                    if ck.reason == "edb-protected":
                        self._set_step("decrypt", "warn", ck.detail)
                        go2 = self.confirm(
                            "需要刷新数据探针。请完全退出 KakaoTalk（右键托盘图标 → 退出，不是关窗口）。",
                            "已完全退出 KakaoTalk",
                        )
                        if not go2:
                            return RunResult(False, reason="user-aborted")
                        continue
                    self._set_step("decrypt", "fail", ck.detail or ck.reason)
                    return RunResult(False, reason=ck.reason or "collect-failed", detail=ck.detail)
                self._set_step("uid", "ok",
                               f"密钥提取完成（命中 {len(ck.hits)} 把，累计缓存 {ck.key_count} 把）")
                st2 = _win.win_two_step_status(self.cache)
                if st2.has_snapshot:
                    return self._decrypt_snapshot_and_open(st2)
                go3 = self.confirm(
                    "密钥已保存。现在请完全退出 KakaoTalk（右键托盘图标 → 退出），让聊天数据落盘。",
                    "已完全退出 KakaoTalk",
                )
                if not go3:
                    return RunResult(False, reason="user-aborted")
                continue

            # E. 文件被保护：引导退出 KakaoTalk
            if st.advice == "exit-kakao":
                go = self.confirm(
                    "新版 KakaoTalk 运行时会锁死并清空数据文件（反取证保护）。\n"
                    "请完全退出 KakaoTalk：右键右下角托盘图标 → 「退出」（仅关窗口无效）。",
                    "已完全退出 KakaoTalk",
                )
                if not go:
                    return RunResult(False, reason="user-aborted")
                continue

        self._set_step("decrypt", "fail", "两步流编排超出最大轮次")
        return RunResult(False, reason="max-rounds")

    def _collect_and_decrypt_snapshot(self, disc) -> RunResult:
        self._set_step("decrypt", "active", "正在从 KakaoTalk 进程内存提取解密密钥（约 2-5 分钟）…")
        ck = self.collect_keys(disc.edbs)
        if not ck.ok:
            self._set_step("decrypt", "fail", ck.detail or ck.reason)
            return RunResult(False, reason=ck.reason or "collect-failed", detail=ck.detail)
        self._set_step("uid", "ok", f"密钥提取完成（命中 {len(ck.hits)} 把，累计缓存 {ck.key_count} 把）")
        from . import win as _win
        st = _win.win_two_step_status(self.cache)
        return self._decrypt_snapshot_and_open(st)

    def _decrypt_snapshot_and_open(self, st) -> RunResult:
        from . import win as _win
        ok, snap_edbs, reason = _win.load_snapshot_edbs(self.cache)
        if not ok:
            self._set_step("decrypt", "fail", f"快照为空：{reason}")
            return RunResult(False, reason="no-snapshot", detail=reason)
        self._set_step("decrypt", "active",
                       f"用已缓存密钥解密快照（{len(snap_edbs)} 个库，快照时间 {st.snapshot_at or '未知'}）…")
        dec = _win.decrypt_with_cached_keys(snap_edbs, self.cache, on_progress=self.on_progress)
        if not dec.ok:
            self._set_step("decrypt", "fail", dec.detail or dec.reason)
            return RunResult(False, reason=dec.reason, detail=dec.detail)
        return self._finish_windows(dec, f"win-snapshot-{int(time.time())}", st)

    def _legacy_windows_decrypt(self, disc) -> RunResult:
        """传统路径：用缓存密钥解密当前落盘 EDB（decrypt-now 分支）。"""
        from . import win as _win
        self._set_step("decrypt", "active", "用缓存密钥解密落盘 EDB…")
        dec = _win.decrypt_with_cached_keys(disc.edbs, self.cache, on_progress=self.on_progress)
        if not dec.ok:
            self._set_step("decrypt", "fail", dec.detail or dec.reason)
            return RunResult(False, reason=dec.reason, detail=dec.detail)
        self._set_step("uid", "ok", f"SQLCipher 密钥已恢复（共 {dec.key_count} 把，新版加密，无需 userId）")
        return self._finish_windows(dec, f"sqlcipher-{int(time.time())}", None)

    def _finish_windows(self, dec, seed: str, st) -> RunResult:
        self._set_step("decrypt", "active", f"解密成功 {len(dec.files)} 个 EDB，正在汇总为统一查询库…")
        try:
            db = KakaoDB()
            edb_files = [EdbFile(name=f.name, path=f.plain_path, size=f.size) for f in dec.files]
            # Windows 每库密钥独立，但汇总层走明文 ATTACH，无需再传 key
            db.open_windows(edb_files, key_hex_map={})
            self.db = db
            self._set_step("decrypt", "ok",
                           f"汇总完成{f'（数据为 {st.snapshot_at} 的快照）' if st and st.snapshot_at else ''}")
            return RunResult(True, db=db, stats=db.stats())
        except Exception as ex:
            self._set_step("decrypt", "fail", f"汇总失败：{ex}")
            return RunResult(False, reason="unify-failed", detail=str(ex))

    # ---- macOS 全自动 ----

    def run_mac(self) -> RunResult:
        from . import mac as _mac

        try:
            disc = self._mac_discover_override() if self._mac_discover_override else _mac.discover()
        except Exception as ex:
            self._set_step("uuid", "fail", f"自动发现失败：{ex}")
            return RunResult(False, reason=str(ex))

        if not disc.uuid:
            self._set_step("uuid", "fail", "无法读取本机 IOPlatformUUID")
            return RunResult(False, reason="no-uuid")
        self._set_step("uuid", "ok", disc.uuid)

        mains = [f for f in disc.db_files if not f.is_side and f.size > 0]
        if not mains:
            self._set_step("db", "fail", f"数据库目录中没有可用的主库文件（{disc.db_dir}）")
            return RunResult(False, reason="no-main-db")

        # 1. 缓存快速通道
        cache_entry = self.cache.load_mac_userid()
        if cache_entry and cache_entry.get("userId") and str(cache_entry.get("uuid")) == str(disc.uuid):
            self._set_step("uid", "active", f"发现缓存的 userId {cache_entry['userId']}，直接验证…")
            hit = self._try_open_mac(cache_entry["userId"], disc)
            if hit:
                self._set_step("uid", "ok", f"缓存 userId {cache_entry['userId']} 验证通过（跳过还原流程）")
                return self._finish_mac(hit, cache_entry["userId"], disc)
            self._set_step("uid", "warn", "缓存的 userId 已失效（可能重装 KakaoTalk 或更换账号），重新还原…")

        # 2. plist 解析
        user_id_info: dict[str, Any] = {"direct": None, "hash": None, "candidates": []}
        if disc.plist:
            try:
                plist = parse_plist(disc.plist)
                if plist:
                    user_id_info = extract_user_id_info(plist)
                    self._set_step("plist", "ok", "已读取 com.kakao.KakaoTalkMac.plist")
                else:
                    self._set_step("plist", "warn", "plist 解析失败，尝试其他途径还原用户 ID")
            except Exception as ex:
                self._set_step("plist", "warn", f"plist 解析异常：{ex}")
        elif disc.plist_timed_out:
            self._set_step("plist", "warn",
                           "读取 KakaoTalk 偏好设置被系统权限拦截（TCC）——"
                           "请在「系统设置 → 隐私与安全性 → 完全磁盘访问」放行终端后重试；本次先靠缓存/候选继续")
        else:
            self._set_step("plist", "warn", "未找到 KakaoTalk 偏好设置文件（可能尚未登录过 KakaoTalk）")

        # 3. userId 候选依次试开
        self._set_step("uid", "active", "正在定位用户 ID…")

        def try_and_cache(user_id: Any, source: str) -> RunResult | None:
            r = self._try_open_mac(user_id, disc)
            if r:
                self._set_step("uid", "ok", f"用户 ID {user_id}")
                self.cache.save_mac_userid(user_id, disc.uuid, source)
                return self._finish_mac(r, user_id, disc)
            return None

        if user_id_info.get("direct"):
            r = try_and_cache(user_id_info["direct"], "plist-direct")
            if r:
                return r
            self._set_step("uid", "warn",
                           f"plist 直取的 userId {user_id_info['direct']} 未能解开任何主库，继续尝试…")

        if user_id_info.get("hash"):
            self._set_step("uid", "active", "偏好设置中仅有用户 ID 哈希，正在多进程爆破还原（最多 10 亿个候选）…")
            br = _mac.brute_user_id(
                hash_hex=user_id_info["hash"], start=0, end=1_000_000_000,
                on_progress=lambda d: self._set_step(
                    "uid", "active",
                    f"爆破中：{d['checked']:,} / {d['total']:,}（{min(99.9, d['checked']/d['total']*100):.1f}%）…"),
            )
            if br.found is not None:
                rr = try_and_cache(br.found, "brute")
                if rr:
                    return rr
                self._set_step("uid", "warn", f"爆破还原的 userId {br.found} 未能解开任何主库，继续尝试…")
            else:
                self._set_step("uid", "warn", "在 0 ~ 10 亿范围内未还原出用户 ID，尝试 plist 候选…")

        for c in user_id_info.get("candidates") or []:
            r = try_and_cache(c, "plist-candidate")
            if r:
                return r

        self._set_step("uid", "fail", "无法从本机信息还原 KakaoTalk 用户 ID")
        return RunResult(False, reason="no-userid")

    def _try_open_mac(self, user_id: Any, disc) -> dict[str, Any] | None:
        """用指定 userId 尝试解密：派生密钥后对全部候选主库逐个 HMAC 验证，第一个通过者胜出。"""
        mains = [f for f in disc.db_files if not f.is_side and f.size > 0]
        try:
            derived = derive_database_name(str(user_id), disc.uuid)
        except Exception:
            derived = None

        def score(f) -> int:
            if derived and f.name == derived:
                return 0
            if derived and derived in f.name:
                return 1
            return 2

        ordered = sorted(mains, key=lambda f: (score(f), -f.size))
        self._set_step("decrypt", "active",
                       f"派生密钥（PBKDF2 100,000 次）并验证 {len(ordered)} 个候选主库…")
        key = derive_secure_key(str(user_id), disc.uuid)

        for main in ordered:
            sides = [f for f in disc.db_files if f.is_side and f.name.startswith(main.name)]
            db = KakaoDB()
            try:
                # 把主库 + 伴随文件复制到临时目录（sqlcipher 自动 WAL checkpoint）
                db.open_mac(main.path, key_hex=key, my_id=_safe_int(user_id))
                return {"db": db, "main": main, "sides": sides}
            except Exception:
                db.close()
                continue
        return None

    def _finish_mac(self, hit: dict[str, Any], user_id: Any, disc) -> RunResult:
        db: KakaoDB = hit["db"]
        main = hit["main"]
        sides = hit["sides"]
        self._set_step("db", "ok",
                       f"已选中主库 {main.name[:16]}…（经 HMAC 验证{f'，含 {len(sides)} 个伴随文件' if sides else ''}）")
        if disc.running:
            self._set_step("db", "warn", "KakaoTalk 正在运行：最新消息可能仍在 -wal 缓存中（伴随文件已一并载入）")
        self.db = db
        self._set_step("decrypt", "ok", "解密成功")
        return RunResult(True, db=db, stats=db.stats(), user_id=user_id, uuid=disc.uuid)


def _safe_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
