#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KakaoTalk 聊天记录一键导出（Windows）。

这是面向「干净 Windows 机器」的单文件入口：
  - 源码模式：在项目根执行  `python kakao_export.py`
  - 打包模式：用 build.bat / PyInstaller 打成单文件 KakaoChatExport.exe，
              拷到没有 Python 环境的电脑双击即可运行（运行时自带 Python）。

流程（复用 kakao_edb SDK 的 Session 两步流编排）：
  检测环境 → 引导取密钥/解密 → 汇总为统一查询库 → 导出聊天记录文件

导出产物（默认写到 ./KakaoChat_导出_<时间戳>/）：
  - 每个聊天室一个 .txt（[时间] 发送者: 内容，人类可读）
  - 每个聊天室一个 .json（结构化，含 authorId/type/sentAt 等字段）
  - _summary.json（总览索引）

依赖：解密需要外部 sqlcipher.exe（放在程序同级 bin/ 目录，或装进 PATH，
      或用环境变量 KKV_SQLCIPHER 指定）。详见同目录《打包与运行说明.md》。
"""
from __future__ import annotations

import argparse
import ctypes
import json
import sys
import time
from pathlib import Path

# 让源码模式下能 import 到同目录的 kakao_edb 包
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from kakao_edb import create_session  # noqa: E402
from kakao_edb.db.kakao_db import KakaoDB  # noqa: E402
from kakao_edb.db.sqlcipher import SqlCipherNotFound, find_sqlcipher  # noqa: E402


# --------------------------------------------------------------------------- #
# 控制台 / 环境辅助
# --------------------------------------------------------------------------- #

def _setup_console() -> None:
    """Windows 控制台默认 GBK，强制切 UTF-8 避免中文乱码。"""
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
            except Exception:
                pass


def _is_admin() -> bool:
    """当前进程是否具备管理员权限（内存取钥对同用户进程通常无需管理员，仅作提示）。"""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _pause(code: int, no_pause: bool) -> int:
    """双击运行时避免窗口一闪而过：结束前等待回车。"""
    if not no_pause:
        try:
            input("\n按回车键退出…")
        except (EOFError, KeyboardInterrupt):
            pass
    return code


def _iso(sec: int | None) -> str:
    if not sec:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec))
    except (OverflowError, OSError, ValueError):
        return str(sec)


def _safe_filename(s: str) -> str:
    import re
    return re.sub(r'[\\/:*?"<>|\s]+', "_", s).strip("_") or "chat"


# --------------------------------------------------------------------------- #
# 交互钩子
# --------------------------------------------------------------------------- #

def _make_confirm(auto_yes: bool):
    def _confirm(guide_text: str, ok_label: str) -> bool:
        print(f"\n{guide_text}\n")
        if auto_yes:
            print(f"[自动确认] {ok_label}\n")
            return True
        try:
            ans = input(f"➤ {ok_label}？[y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes", "")  # 直接回车默认继续，降低操作负担
    return _confirm


def _on_step(step: str, state: str, detail: str) -> None:
    icon = {"ok": "✓", "active": "›", "warn": "⚠", "fail": "✗"}.get(state, "·")
    print(f"[{step}] {icon} {detail or state}")


def _on_progress(stage: str, detail: str) -> None:
    sys.stderr.write(f"\r  ({stage}) {detail}        ")
    sys.stderr.flush()


# --------------------------------------------------------------------------- #
# 导出
# --------------------------------------------------------------------------- #

def _fetch_all_messages(db: KakaoDB, chat_id: int) -> list:
    """分页取完一个聊天室的全部消息（get_messages 按时间倒序，返回时转正序）。"""
    out: list = []
    offset = 0
    while True:
        rows, has_more = db.get_messages(chat_id, offset=offset, limit=500)
        out.extend(reversed(rows))  # 倒序 → 正序
        if not has_more:
            break
        offset += 500
    return out


def _sender_of(m) -> str:
    return m.sender_name or m.sender_account_id or (str(m.author_id) if m.author_id else "?")


def _body_of(m) -> str:
    if m.message is None:
        return f"[非文本消息 type={m.type}]"
    return str(m.message)


def export_chats(db: KakaoDB, out_dir: Path, fmt: str) -> dict:
    """把统一查询库导出为 txt / json 文件，返回 _summary 字典。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    chats = db.list_chats(2000)
    stats = db.stats()
    summary = {
        "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "format": fmt,
        "stats": stats,
        "chats": [],
    }

    want_txt = fmt in ("txt", "both")
    want_json = fmt in ("json", "both")

    for idx, c in enumerate(chats, 1):
        msgs = _fetch_all_messages(db, c.chat_id)
        title = str(c.chat_name or c.chat_id)
        base = f"{c.chat_id}_{_safe_filename(title)[:60]}"
        print(f"  [{idx}/{len(chats)}] 导出「{title}」{len(msgs)} 条…")

        entry = {"chatId": c.chat_id, "chatName": c.chat_name,
                 "memberCount": c.member_count, "messages": len(msgs)}

        if want_txt:
            lines = [f"[{_iso(m.sent_at)}] {_sender_of(m)}: {_body_of(m)}" for m in msgs]
            txt_path = out_dir / f"{base}.txt"
            txt_path.write_text("\n".join(lines), encoding="utf-8")
            entry["txtFile"] = txt_path.name

        if want_json:
            payload = {
                "chatId": c.chat_id, "chatName": c.chat_name,
                "memberCount": c.member_count, "messageCount": len(msgs),
                "messages": [{
                    "logId": m.log_id, "authorId": m.author_id,
                    "senderName": m.sender_name, "senderAccountId": m.sender_account_id,
                    "message": m.message, "attachment": m.attachment,
                    "type": m.type, "sentAt": m.sent_at, "sentAtLocal": _iso(m.sent_at),
                } for m in msgs],
            }
            json_path = out_dir / f"{base}.json"
            json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
            entry["jsonFile"] = json_path.name

        summary["chats"].append(entry)

    summary["chats"].sort(key=lambda x: -x["messages"])
    (out_dir / "_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def _precheck() -> int | None:
    """环境自检；返回非 None 表示需以该退出码终止。"""
    if sys.platform != "win32":
        print("✗ 本导出工具仅支持 Windows（KakaoTalk PC 版聊天记录）。")
        print(f"  当前平台：{sys.platform}")
        return 2
    try:
        path = find_sqlcipher()
        print(f"✓ sqlcipher：{path}")
    except SqlCipherNotFound as ex:
        print(f"✗ {ex}")
        print("  最简单：把 sqlcipher.exe 放到本程序同级的 bin\\ 目录后重试。")
        return 3
    if not _is_admin():
        print("⚠ 当前非管理员权限。内存取钥对「同用户」的 KakaoTalk 通常够用；")
        print("  若稍后取钥失败，请右键「以管理员身份运行」重试。")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="KakaoChatExport",
        description="KakaoTalk 聊天记录一键导出（Windows，解密后保存为 txt/json 文件）",
    )
    parser.add_argument("--out", default=None,
                        help="导出目录（默认 ./KakaoChat_导出_<时间戳>）")
    parser.add_argument("--format", choices=("txt", "json", "both"), default="both",
                        help="导出格式（默认 both：txt + json）")
    parser.add_argument("--yes", action="store_true",
                        help="全自动：跳过所有交互确认（仅适合已缓存过密钥的日常导出）")
    parser.add_argument("--cache-dir", default=None,
                        help="密钥/快照缓存目录（默认 ~/.kakao-edb-sdk）")
    parser.add_argument("--no-pause", action="store_true",
                        help="结束后不等待回车（命令行/CI 用）")
    args = parser.parse_args(argv)

    _setup_console()
    print("=" * 60)
    print("  KakaoTalk 聊天记录导出工具")
    print("=" * 60)

    code = _precheck()
    if code is not None:
        return _pause(code, args.no_pause)

    out_dir = Path(args.out) if args.out else \
        Path.cwd() / f"KakaoChat_导出_{time.strftime('%Y%m%d_%H%M%S')}"

    print("\n开始检测 KakaoTalk 数据状态…\n")
    session = create_session(
        cache_dir=args.cache_dir,
        on_step=_on_step,
        on_progress=_on_progress,
        confirm=_make_confirm(args.yes),
    )

    try:
        r = session.run()
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        print("\n✗ 已被用户中断。")
        return _pause(130, args.no_pause)
    except Exception as ex:  # noqa: BLE001
        sys.stderr.write("\n")
        print(f"\n✗ 运行异常：{ex}")
        return _pause(1, args.no_pause)

    sys.stderr.write("\n")
    if not r.ok:
        print(f"\n✗ 流程中止：{r.reason}{f'（{r.detail}）' if r.detail else ''}")
        return _pause(1, args.no_pause)

    s = r.stats or {}
    print(f"\n✓ 解密并汇总完成：{s.get('chatCount', '?')} 个聊天室 / "
          f"{s.get('messageCount', '?')} 条消息 / {s.get('userCount', '?')} 个联系人")

    if not r.db:
        print("✗ 未获得可导出的数据库句柄。")
        return _pause(1, args.no_pause)

    print(f"\n正在导出到：{out_dir}\n")
    try:
        summary = export_chats(r.db, out_dir, args.format)
    finally:
        try:
            r.db.close()
        except Exception:
            pass

    print("\n" + "=" * 60)
    print(f"  导出完成！共 {len(summary['chats'])} 个聊天室 → {out_dir}")
    print("=" * 60)
    return _pause(0, args.no_pause)


if __name__ == "__main__":
    raise SystemExit(main())
