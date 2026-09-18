"""统一查询库（对齐 src/db/kakaoDb.js）。

JS 版用 SQLCipher wasm 在内存里解密 + ATTACH 多库汇总为 NTUser/NTChatRoom/NTChatMessage。
Python 版走「sqlcipher3 外部二进制先把每个 EDB 解密为明文 SQLite → stdlib sqlite3 ATTACH 汇总」，
产物 schema 与查询 API 完全一致。

核心表（与 JS 版逐字段对齐）：
    NTUser(userId PK, displayName, nickName, friendNickName, accountId, linkId)
    NTChatRoom(chatId PK, type, chatName, activeMembersCount, lastLogId, lastUpdatedAt,
               countOfNewMessage, directChatMemberUserId)
    NTChatMessage(logId PK AUTOINCREMENT, chatId, authorId, message, attachment, type, sentAt)
    NTChatContext(userId)
"""
from __future__ import annotations

import logging
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .sqlcipher import decrypt_to_plain

log = logging.getLogger(__name__)

# KakaoTalk EDB 内部方言表名（不同版本略有差异，按优先级尝试）
_CHAT_TABLES = ("chat_rooms", "ChatRoom", "chat_room")
_MSG_TABLES = ("chat_logs", "ChatMessage", "chat_message", "chatlog")
_USER_TABLES = ("users", "NTUser", "user", "friends")

_SIDE_SUFFIX_RE = re.compile(r"-(wal|shm|journal)$", re.I)


@dataclass
class EdbFile:
    """一个待汇总的 EDB 文件（加密或明文）。"""
    name: str
    path: Path
    size: int = 0
    data: bytes | None = None  # 可选：内存字节（与 path 二选一）


@dataclass
class ChatRow:
    chat_id: int
    chat_name: str | None
    member_count: int | None
    last_updated_at: int | None
    last_log_id: int | None
    type: int | None = None


@dataclass
class MessageRow:
    log_id: int
    chat_id: int
    author_id: int | None
    sender_name: str | None
    sender_account_id: str | None
    message: str | None
    attachment: str | None
    type: int | None
    sent_at: int | None


@dataclass
class KakaoDB:
    """统一查询库：把多个解密后的明文 SQLite ATTACH 到一个内存主库并汇总。"""

    conn: sqlite3.Connection | None = field(default=None, repr=False)
    _tmpdir: tempfile.TemporaryDirectory | None = field(default=None, repr=False)
    _attached: list[str] = field(default_factory=list, repr=False)

    # ---------- 打开 ----------

    def open_mac(self, main_plain: Path, key_hex: str | None = None,
                 my_id: int | None = None) -> None:
        """macOS：主库已是明文（或先用 key_hex 解密），直接 ATTACH 汇总。"""
        self._ensure_conn()
        plain = self._ensure_plain(main_plain, key_hex)
        self._attach(plain, "mac_main")
        self._create_unified_schema()
        self._import_from_dialect("mac_main", my_id=my_id)

    def open_windows(self, edbs: Iterable[EdbFile], key_hex_map: dict[str, str],
                     my_id: int | None = None) -> None:
        """Windows：每个 EDB 用各自缓存密钥解密后 ATTACH 汇总。

        key_hex_map: {edb_name: key_hex}，缺失密钥的 EDB 跳过。
        """
        self._ensure_conn()
        self._create_unified_schema()
        for idx, edb in enumerate(edbs):
            src = edb.path
            if edb.data is not None and (src is None or not Path(src).exists()):
                # 内存字节：落临时文件
                tmp = Path(self._tmpdir.name) / edb.name  # type: ignore[union-attr]
                tmp.write_bytes(edb.data)
                src = tmp
            if src is None or not Path(src).exists():
                continue
            key = key_hex_map.get(edb.name)
            # 无密钥时仅当文件已是明文才继续：Windows 汇总路径（_finish_windows）
            # 传入的是 decrypt 阶段产出的明文 SQLite，本就无需再传 key；
            # 若既无 key 又非明文则无法解密，跳过。
            if not key and not self._is_plain(Path(src)):
                log.warning("EDB %s 无缓存密钥且非明文，跳过", edb.name)
                continue
            alias = f"win_{idx}"
            try:
                plain = self._ensure_plain(Path(src), key)
                self._attach(plain, alias)
                self._import_from_dialect(alias, my_id=my_id)
            except Exception as ex:
                log.warning("EDB %s 解密/汇总失败: %s", edb.name, ex)

    def open_unified_windows(self, edbs: Iterable[EdbFile], key_hex: str,
                             my_id: int | None = None) -> None:
        """JS 版 openUnifiedWindows 等价：所有 EDB 共用一把 SQLCipher 密钥（旧版兼容路径）。"""
        self.open_windows(edbs, {e.name: key_hex for e in edbs}, my_id=my_id)

    # ---------- 查询 API（与 JS 版签名一致） ----------

    def list_chats(self, limit: int = 100) -> list[ChatRow]:
        assert self.conn
        cur = self.conn.execute(
            "SELECT chatId, chatName, activeMembersCount, lastUpdatedAt, lastLogId, type "
            "FROM NTChatRoom ORDER BY COALESCE(lastUpdatedAt,0) DESC LIMIT ?", (limit,)
        )
        return [ChatRow(r[0], r[1], r[2], r[3], r[4], r[5]) for r in cur.fetchall()]

    def get_messages(self, chat_id: int, offset: int = 0, limit: int = 50
                     ) -> tuple[list[MessageRow], bool]:
        assert self.conn
        cur = self.conn.execute(
            "SELECT m.logId, m.chatId, m.authorId, u.displayName, u.accountId, "
            "       m.message, m.attachment, m.type, m.sentAt "
            "FROM NTChatMessage m LEFT JOIN NTUser u ON u.userId = m.authorId "
            "WHERE m.chatId = ? ORDER BY m.sentAt DESC, m.logId DESC LIMIT ? OFFSET ?",
            (chat_id, limit + 1, offset),
        )
        rows = cur.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return [MessageRow(*r) for r in rows], has_more

    def search_messages(self, keyword: str, limit: int = 100) -> list[MessageRow]:
        assert self.conn
        cur = self.conn.execute(
            "SELECT m.logId, m.chatId, m.authorId, u.displayName, u.accountId, "
            "       m.message, m.attachment, m.type, m.sentAt "
            "FROM NTChatMessage m LEFT JOIN NTUser u ON u.userId = m.authorId "
            "WHERE m.message LIKE ? ORDER BY m.sentAt DESC LIMIT ?",
            (f"%{keyword}%", limit),
        )
        return [MessageRow(*r) for r in cur.fetchall()]

    def stats(self) -> dict[str, int]:
        assert self.conn
        c = self.conn.execute("SELECT COUNT(*) FROM NTChatRoom").fetchone()[0]
        m = self.conn.execute("SELECT COUNT(*) FROM NTChatMessage").fetchone()[0]
        u = self.conn.execute("SELECT COUNT(*) FROM NTUser").fetchone()[0]
        return {"chatCount": c, "messageCount": m, "userCount": u}

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None
        self._attached.clear()

    # ---------- 内部 ----------

    def _ensure_conn(self) -> None:
        if self.conn is None:
            self._tmpdir = tempfile.TemporaryDirectory(prefix="kkv-unified-")
            self.conn = sqlite3.connect(":memory:")
            self.conn.execute("PRAGMA journal_mode = MEMORY")
            self.conn.execute("PRAGMA synchronous = OFF")

    def _ensure_plain(self, path: Path, key_hex: str | None) -> Path:
        """若 path 已是明文 SQLite 直接返回；否则用 key_hex 解密到临时目录。"""
        with path.open("rb") as f:
            head = f.read(16)
        if head == b"SQLite format 3\x00":
            return path
        if not key_hex:
            raise ValueError(f"{path.name} 非明文且无密钥")
        assert self._tmpdir
        out = Path(self._tmpdir.name) / (path.stem + ".plain.db")
        r = decrypt_to_plain(path, key_hex, out)
        if not r.ok:
            raise RuntimeError(f"解密 {path.name} 失败: {r.reason}")
        return r.plain_path  # type: ignore[return-value]

    @staticmethod
    def _is_plain(path: Path) -> bool:
        """判断文件是否已是明文 SQLite（头 16 字节为 magic）。"""
        try:
            with path.open("rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def _attach(self, plain: Path, alias: str) -> None:
        assert self.conn
        self.conn.execute(f"ATTACH DATABASE ? AS {alias}", (str(plain),))
        self._attached.append(alias)

    def _create_unified_schema(self) -> None:
        assert self.conn
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS NTUser (
                userId INTEGER PRIMARY KEY, displayName TEXT, nickName TEXT,
                friendNickName TEXT, accountId TEXT, linkId INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS NTChatRoom (
                chatId INTEGER PRIMARY KEY, type INTEGER DEFAULT 2, chatName TEXT,
                activeMembersCount INTEGER, lastLogId INTEGER, lastUpdatedAt INTEGER,
                countOfNewMessage INTEGER DEFAULT 0, directChatMemberUserId INTEGER);
            CREATE TABLE IF NOT EXISTS NTChatMessage (
                logId INTEGER PRIMARY KEY AUTOINCREMENT, chatId INTEGER, authorId INTEGER,
                message TEXT, attachment TEXT, type INTEGER, sentAt INTEGER);
            CREATE TABLE IF NOT EXISTS NTChatContext (userId INTEGER);
            CREATE INDEX IF NOT EXISTS idx_msg_chat ON NTChatMessage(chatId, sentAt);
            CREATE INDEX IF NOT EXISTS idx_msg_sent ON NTChatMessage(sentAt);
        """)

    def _find_table(self, alias: str, candidates: tuple[str, ...]) -> str | None:
        assert self.conn
        cur = self.conn.execute(
            f"SELECT name FROM {alias}.sqlite_master WHERE type='table'")
        names = {r[0].lower(): r[0] for r in cur.fetchall()}
        for c in candidates:
            if c.lower() in names:
                return names[c.lower()]
        return None

    def _import_from_dialect(self, alias: str, my_id: int | None = None) -> None:
        """从一个 ATTACH 的明文库把数据导入统一 schema（方言自适应）。"""
        assert self.conn
        chat_t = self._find_table(alias, _CHAT_TABLES)
        msg_t = self._find_table(alias, _MSG_TABLES)
        user_t = self._find_table(alias, _USER_TABLES)

        # 用户
        if user_t:
            cols = self._columns(alias, user_t)
            sel_id = _pick(cols, ("userId", "id", "user_id"))
            sel_name = _pick(cols, ("displayName", "name", "nickName", "nickname"))
            sel_nick = _pick(cols, ("nickName", "nickname"))
            sel_friend = _pick(cols, ("friendNickName", "friendNickname"))
            sel_account = _pick(cols, ("accountId", "account_id", "account"))
            if sel_id:
                self.conn.execute(f"""
                    INSERT OR IGNORE INTO NTUser
                        (userId, displayName, nickName, friendNickName, accountId, linkId)
                    SELECT {sel_id}, {sel_name or 'NULL'}, {sel_nick or 'NULL'},
                           {sel_friend or 'NULL'}, {sel_account or 'NULL'}, 0
                    FROM {alias}.{user_t}
                """)

        # 聊天室
        if chat_t:
            cols = self._columns(alias, chat_t)
            sel_id = _pick(cols, ("chatId", "id", "chat_id"))
            sel_name = _pick(cols, ("chatName", "name", "chat_name"))
            sel_members = _pick(cols, ("activeMembersCount", "memberCount", "members"))
            sel_last_log = _pick(cols, ("lastLogId", "last_log_id"))
            sel_updated = _pick(cols, ("lastUpdatedAt", "updatedAt", "last_updated_at"))
            sel_type = _pick(cols, ("type",))
            if sel_id:
                self.conn.execute(f"""
                    INSERT OR REPLACE INTO NTChatRoom
                        (chatId, type, chatName, activeMembersCount, lastLogId,
                         lastUpdatedAt, countOfNewMessage, directChatMemberUserId)
                    SELECT {sel_id}, {sel_type or '2'}, {sel_name or 'NULL'},
                           {sel_members or 'NULL'}, {sel_last_log or 'NULL'},
                           {sel_updated or 'NULL'}, 0, NULL
                    FROM {alias}.{chat_t}
                """)

        # 消息
        if msg_t:
            cols = self._columns(alias, msg_t)
            sel_chat = _pick(cols, ("chatId", "chat_id", "chatRoomId"))
            sel_author = _pick(cols, ("authorId", "userId", "senderId", "user_id"))
            sel_msg = _pick(cols, ("message", "msg", "content"))
            sel_attach = _pick(cols, ("attachment", "attach"))
            sel_type = _pick(cols, ("type", "msgType"))
            sel_sent = _pick(cols, ("sentAt", "createdAt", "timestamp", "sent_at"))
            if sel_chat and sel_msg:
                # 不写 logId：各 EDB 的 logId 空间相互独立，直接当 PK 会跨库冲突触发
                # IntegrityError，导致整库导入被中断、消息丢失。交由 AUTOINCREMENT 分配；
                # 排序以 sentAt 为主，logId 仅作同秒内的稳定 tiebreak。
                self.conn.execute(f"""
                    INSERT INTO NTChatMessage
                        (chatId, authorId, message, attachment, type, sentAt)
                    SELECT {sel_chat}, {sel_author or 'NULL'},
                           {sel_msg}, {sel_attach or 'NULL'}, {sel_type or 'NULL'},
                           {sel_sent or 'NULL'}
                    FROM {alias}.{msg_t}
                """)

        if my_id is not None:
            self.conn.execute("INSERT INTO NTChatContext (userId) VALUES (?)", (my_id,))
        self.conn.commit()

    def _columns(self, alias: str, table: str) -> list[str]:
        assert self.conn
        cur = self.conn.execute(f"PRAGMA {alias}.table_info({table})")
        return [r[1] for r in cur.fetchall()]


def _pick(cols: list[str], names: tuple[str, ...]) -> str | None:
    lower = {c.lower(): c for c in cols}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def is_side_file(name: str) -> bool:
    return bool(_SIDE_SUFFIX_RE.search(name))
