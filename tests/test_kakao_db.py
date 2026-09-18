"""KakaoDB 统一查询库回归测试（纯 stdlib sqlite3，走明文 ATTACH 路径，无需 sqlcipher）。

锁定两个历史 bug：
  - Bug A：open_windows 在 key_hex_map 为空时跳过所有文件 → Windows 汇总库恒为空。
           （_finish_windows 传入的是已解密明文，本就不带 key）
  - Bug 16：NTChatMessage 用各 EDB 自带的 logId 当 PK → 跨库 logId 冲突触发
            IntegrityError → 整库导入被中断、消息丢失。
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kakao_edb.db.kakao_db import EdbFile, KakaoDB


def _make_edb(path: Path, rooms, logs, users=None) -> None:
    """造一个模仿 KakaoTalk 方言的明文 SQLite（chat_rooms / chat_logs / users）。"""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE chat_rooms (
            chatId INTEGER PRIMARY KEY, chatName TEXT, activeMembersCount INTEGER,
            lastLogId INTEGER, lastUpdatedAt INTEGER, type INTEGER);
        CREATE TABLE chat_logs (
            logId INTEGER PRIMARY KEY, chatId INTEGER, authorId INTEGER,
            message TEXT, attachment TEXT, type INTEGER, sentAt INTEGER);
        CREATE TABLE users (
            userId INTEGER PRIMARY KEY, displayName TEXT, nickName TEXT,
            friendNickName TEXT, accountId TEXT, linkId INTEGER);
    """)
    conn.executemany(
        "INSERT INTO chat_rooms (chatId, chatName, activeMembersCount, lastLogId, "
        "lastUpdatedAt, type) VALUES (?,?,?,?,?,?)", rooms)
    conn.executemany(
        "INSERT INTO chat_logs (logId, chatId, authorId, message, attachment, type, "
        "sentAt) VALUES (?,?,?,?,?,?,?)", logs)
    if users:
        conn.executemany(
            "INSERT INTO users (userId, displayName, nickName, friendNickName, accountId, "
            "linkId) VALUES (?,?,?,?,?,?)", users)
    conn.commit()
    conn.close()


class TestOpenWindowsPlaintext(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _edb(self, p: Path) -> EdbFile:
        return EdbFile(name=p.name, path=p, size=p.stat().st_size)

    def test_empty_keymap_still_imports_plaintext(self) -> None:
        """Bug A：key_hex_map={} 时明文 EDB 仍应被汇总（修复前恒为空库）。"""
        a = self.dir / "chatLogs_1.edb"
        _make_edb(a,
                  rooms=[(100, "Room A", 2, 3, 1700000000, 2)],
                  logs=[(1, 100, 999, "hello", None, 1, 1700000000),
                        (2, 100, 999, "world", None, 1, 1700000001)])
        db = KakaoDB()
        try:
            db.open_windows([self._edb(a)], key_hex_map={})
            st = db.stats()
            self.assertEqual(st["chatCount"], 1)
            self.assertEqual(st["messageCount"], 2)
        finally:
            db.close()

    def test_overlapping_logid_no_message_loss(self) -> None:
        """Bug 16：两个 EDB 的 logId 空间重叠时，消息不得因 PK 冲突丢失。"""
        a = self.dir / "chatLogs_1.edb"
        b = self.dir / "chatLogs_2.edb"
        # 两库都用 logId 1,2,3（完全重叠），chatId 不同
        _make_edb(a, rooms=[(100, "A", 2, 3, 1700000000, 2)],
                  logs=[(1, 100, 1, "a1", None, 1, 1700000001),
                        (2, 100, 1, "a2", None, 1, 1700000002),
                        (3, 100, 2, "a3", None, 1, 1700000003)])
        _make_edb(b, rooms=[(200, "B", 3, 3, 1700000010, 2)],
                  logs=[(1, 200, 3, "b1", None, 1, 1700000011),
                        (2, 200, 3, "b2", None, 1, 1700000012),
                        (3, 200, 4, "b3", None, 1, 1700000013)])
        db = KakaoDB()
        try:
            db.open_windows([self._edb(a), self._edb(b)], key_hex_map={})
            st = db.stats()
            self.assertEqual(st["chatCount"], 2)
            # 修复前：第二库 logId 1,2,3 与第一库冲突 → IntegrityError → 只剩 3 条
            self.assertEqual(st["messageCount"], 6)
            msgs_a, _ = db.get_messages(100, limit=50)
            msgs_b, _ = db.get_messages(200, limit=50)
            self.assertEqual(len(msgs_a), 3)
            self.assertEqual(len(msgs_b), 3)
        finally:
            db.close()

    def test_same_chatid_across_edb_dedup_room(self) -> None:
        """同一 chatId 出现在多个 EDB：聊天室 REPLACE 去重，消息累加不丢。"""
        a = self.dir / "chatLogs_1.edb"
        b = self.dir / "chatLogs_2.edb"
        _make_edb(a, rooms=[(100, "A-old", 2, 1, 1700000000, 2)],
                  logs=[(1, 100, 1, "m1", None, 1, 1700000001)])
        _make_edb(b, rooms=[(100, "A-new", 2, 2, 1700000020, 2)],
                  logs=[(1, 100, 1, "m2", None, 1, 1700000021)])
        db = KakaoDB()
        try:
            db.open_windows([self._edb(a), self._edb(b)], key_hex_map={})
            st = db.stats()
            self.assertEqual(st["chatCount"], 1)       # 去重
            self.assertEqual(st["messageCount"], 2)    # 两条都在（修复前只剩 1 条）
            chats = db.list_chats(limit=10)
            self.assertEqual(chats[0].chat_name, "A-new")  # 后导入覆盖
        finally:
            db.close()

    def test_non_plaintext_without_key_skipped(self) -> None:
        """无 key 且非明文的文件应被安全跳过（不抛异常、不污染库）。"""
        bad = self.dir / "chatLogs_9.edb"
        bad.write_bytes(b"\x00" * 4096)  # 全零，非明文 SQLite
        db = KakaoDB()
        try:
            db.open_windows([self._edb(bad)], key_hex_map={})
            st = db.stats()
            self.assertEqual(st["chatCount"], 0)
            self.assertEqual(st["messageCount"], 0)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
