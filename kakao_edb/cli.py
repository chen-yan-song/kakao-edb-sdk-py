"""kakao-edb CLI（对齐 bin/kkv.mjs）。

子命令：
    status                          两步流状态检测（advice/密钥数/快照数）
    snapshot                        退出态快照核心 EDB（含 WAL）到缓存目录
    collect-keys                    运行态从 KakaoTalk 进程内存提取密钥存缓存
    decrypt [--out DIR]             用缓存密钥解密当前落盘 EDB（可写明文副本）
    run [--yes] [--export DIR]      全自动编排（平台自适应，交互点走终端确认）
    unify --files f1,f2 [--export DIR] [--user-id N]
                                    把已解密的明文 EDB 汇总为统一查询库

全局选项：
    --cache-dir DIR   缓存目录（默认 ~/.kakao-edb-sdk）
    --json            机器可读输出（status/run 摘要）
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path

from .cache import Cache
from .db.kakao_db import EdbFile, KakaoDB
from .orchestrator import Session, create_session

log = logging.getLogger("kakao_edb")


def _ask_confirm(auto_yes: bool):
    def _confirm(guide_text: str, ok_label: str) -> bool:
        if auto_yes:
            print(f"\n[自动确认] {guide_text.replace(chr(10), ' ')}\n")
            return True
        print(f"\n{guide_text}\n")
        try:
            ans = input(f"{ok_label}？[y/N] ").strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")
    return _confirm


def _step_printer(step: str, state: str, detail: str) -> None:
    icon = {"ok": "✓", "active": "…", "warn": "⚠", "fail": "✗"}.get(state, "·")
    print(f"[{step}] {icon} {detail or state}")


def _progress_printer(as_json: bool):
    def _p(stage: str, detail: str) -> None:
        if not as_json:
            sys.stderr.write(f"\r  ({stage}) {detail}   ")
            sys.stderr.flush()
    return _p


def _export_chats(db: KakaoDB, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    chats = db.list_chats(500)
    summary = {"exportedAt": _now_iso(), "stats": db.stats(), "chats": []}
    for c in chats:
        safe_name = _safe_filename(str(c.chat_name or c.chat_id))[:60]
        file = out_dir / f"{c.chat_id}_{safe_name}.txt"
        lines: list[str] = []
        offset = 0
        while True:
            rows, has_more = db.get_messages(c.chat_id, offset=offset, limit=500)
            for m in reversed(rows):  # 查询按时间倒序，导出转正序
                t = _iso_from_epoch(m.sent_at) if m.sent_at else "?"
                who = m.sender_name or m.sender_account_id or (str(m.author_id) if m.author_id else "?")
                body = f"[非文本消息 type={m.type}]" if m.message is None else str(m.message)
                lines.append(f"[{t}] {who}: {body}")
            if not has_more:
                break
            offset += 500
        file.write_text("\n".join(lines), encoding="utf-8")
        summary["chats"].append({
            "chatId": c.chat_id, "chatName": c.chat_name,
            "messages": len(lines), "file": file.name,
        })
    summary["chats"].sort(key=lambda x: -x["messages"])
    (out_dir / "_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n导出完成：{len(summary['chats'])} 个聊天室 → {out_dir}")
    return summary


def _write_decrypted(dec, out_dir: Path) -> None:
    import shutil
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in dec.files:
        dst = out_dir / (Path(f.name).stem + ".plain.db")
        shutil.copy2(f.plain_path, dst)
    print(f"已写出 {len(dec.files)} 个明文库 → {out_dir}")


def _now_iso() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_from_epoch(sec: int | None) -> str:
    if not sec:
        return "?"
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sec))


def _safe_filename(s: str) -> str:
    import re
    return re.sub(r'[\\/:*?"<>|\s]+', "_", s)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kakao-edb",
                                description="KakaoTalk 本地聊天数据库解密 SDK CLI（Python 版）")
    p.add_argument("--cache-dir", default=None, help="缓存目录（默认 ~/.kakao-edb-sdk）")
    p.add_argument("--json", action="store_true", help="机器可读输出")
    p.add_argument("-y", "--yes", action="store_true", help="自动确认所有交互点")
    p.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("status", help="两步流状态检测（先看这个）")
    sub.add_parser("snapshot", help="退出态快照核心 EDB 到缓存目录")
    sub.add_parser("collect-keys", help="运行态从内存提取密钥存缓存")

    sp_dec = sub.add_parser("decrypt", help="用缓存密钥解密当前落盘 EDB")
    sp_dec.add_argument("--out", default=None, help="明文副本输出目录")

    sp_run = sub.add_parser("run", help="全自动编排（推荐）")
    sp_run.add_argument("--export", default=None, help="导出每聊天室 txt + _summary.json 到目录")

    sp_uni = sub.add_parser("unify", help="汇总已解密明文库")
    sp_uni.add_argument("--files", required=True, help="逗号分隔的明文库路径")
    sp_uni.add_argument("--export", default=None)
    sp_uni.add_argument("--user-id", default=None)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.cmd:
        parser.print_help()
        return 0

    session: Session = create_session(
        cache_dir=args.cache_dir,
        on_step=_step_printer,
        on_progress=_progress_printer(args.json),
        confirm=_ask_confirm(args.yes),
    )

    if args.cmd == "status":
        st = session.status()
        if args.json:
            print(json.dumps(_status_to_dict(st), ensure_ascii=False, indent=2))
            return 0
        print(f"KakaoTalk 运行中 : {'是' if st.running else '否'}")
        print(f"核心库可读       : {st.readable}/{st.core_count}")
        print(f"已缓存密钥       : {st.key_count} 把")
        snap_at = _iso_from_epoch(st.snapshot_at // 1000) if st.snapshot_at else ""
        print(f"快照             : {st.snapshot_count} 个{f'（{snap_at}）' if snap_at else ''}")
        print(f"建议动作         : {st.advice}")
        tips = {
            "decrypt-now": "数据文件可读且密钥齐全 → 运行 `kakao-edb run` 直接解密",
            "decrypt-snapshot": "有密钥有快照 → 运行 `kakao-edb run` 解密快照",
            "snapshot": "文件可读但无密钥 → 运行 `kakao-edb run`（会先快照，再引导启动 KakaoTalk 取密钥）",
            "collect-keys": "有探针缓存无密钥 → 启动并登录 KakaoTalk 后运行 `kakao-edb collect-keys`",
            "exit-kakao": "文件被运行时保护 → 完全退出 KakaoTalk 后重新检测",
        }
        if st.core_count == 0:
            # 压根没发现 EDB：未安装 / 未登录过 / 自定义安装路径，与“运行时保护”是两回事
            print("说明             : 未发现任何 KakaoTalk 数据库 → 确认已安装并登录过 KakaoTalk；"
                  "若为自定义安装路径，设 KKV_WIN_BASE_DIR 指向数据目录后重试")
        elif st.advice in tips:
            print(f"说明             : {tips[st.advice]}")
        return 0

    if args.cmd == "snapshot":
        snap = session.snapshot()
        if not snap.ok:
            print(f"快照失败：{snap.reason}", file=sys.stderr)
            return 1
        print(f"快照完成：{snap.count} 个核心库 → {snap.dir}")
        return 0

    if args.cmd == "collect-keys":
        ck = session.collect_keys()
        if not ck.ok:
            print(f"密钥提取失败：{ck.detail or ck.reason}", file=sys.stderr)
            return 1
        print(f"密钥提取完成：本次命中 {len(ck.hits)} 把，累计缓存 {ck.key_count} 把")
        return 0

    if args.cmd == "decrypt":
        dec = session.decrypt_cached()
        if not dec.ok:
            print(f"解密失败：{dec.detail or dec.reason}", file=sys.stderr)
            return 1
        print(f"解密成功：{len(dec.files)} 个 EDB")
        if args.out:
            _write_decrypted(dec, Path(args.out))
        return 0

    if args.cmd == "run":
        r = session.run()
        sys.stderr.write("\n")
        if not r.ok:
            print(f"流程中止：{r.reason}{f'（{r.detail}）' if r.detail else ''}", file=sys.stderr)
            return 1
        s = r.stats or {}
        if args.json:
            print(json.dumps({"ok": True, "stats": s,
                              "chatRooms": s.get("chatCount"),
                              "messages": s.get("messageCount")}, ensure_ascii=False, indent=2))
        else:
            print(f"\n解密并汇总完成：{s.get('chatCount','?')} 个聊天室 / "
                  f"{s.get('messageCount','?')} 条消息 / {s.get('userCount','?')} 个联系人")
        if args.export and r.db:
            _export_chats(r.db, Path(args.export))
        return 0

    if args.cmd == "unify":
        files_arg = args.files
        files = [f.strip() for f in files_arg.split(",") if f.strip()]
        edb_files: list[EdbFile] = []
        for f in files:
            p = Path(f).expanduser().resolve()
            if not p.exists():
                print(f"文件不存在：{p}", file=sys.stderr)
                return 1
            edb_files.append(EdbFile(name=p.name, path=p, size=p.stat().st_size))
        user_id = args.user_id or "kakao-edb-sdk"
        db = session.open_unified(edb_files, user_id, user_id)
        s = db.stats()
        print(f"汇总完成：{s.get('chatCount','?')} 个聊天室 / "
              f"{s.get('messageCount','?')} 条消息 / {s.get('userCount','?')} 个联系人")
        if args.export:
            _export_chats(db, Path(args.export))
        return 0

    parser.print_help()
    return 0


def _status_to_dict(st) -> dict:
    d = asdict(st)
    d.pop("edbs", None)  # 路径对象不可序列化，且 status 输出不需要
    return d


if __name__ == "__main__":
    sys.exit(main())
