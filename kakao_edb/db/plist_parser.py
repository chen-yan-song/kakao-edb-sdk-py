"""二进制 plist 解析 + KakaoTalk userId 信息提取（对齐 src/db/plistParser.js）。

Python 标准库 plistlib 已原生支持 binary/xml plist，比 JS 版简单得多。

extract_user_id_info 返回：
    {
        "direct":     int | None,       # plist 直接可读的 userId
        "hash":       str | None,       # 仅有哈希时（需爆破还原）
        "candidates": list[int],        # 兜底候选（从 plist 各种键位扫描到的数字）
    }
"""
from __future__ import annotations

import plistlib
import re
from typing import Any


def parse_plist(data: bytes) -> dict[str, Any] | None:
    """解析 plist 字节流；失败返回 None。"""
    if not data:
        return None
    try:
        return plistlib.loads(data)
    except Exception:
        return None


# KakaoTalk plist 中可能承载 userId 的键（不同版本命名不一）
_USER_ID_KEYS = (
    "userId", "UserID", "user_id", "kUserId",
    "lastUserId", "LastUserID", "currentUserId",
    "kakaoUserId", "KakaoUserID",
)

# 仅存哈希时的键（值为 SHA-256(userId) 的 hex/base64）
_USER_ID_HASH_KEYS = (
    "userIdHash", "UserIDHash", "user_id_hash",
    "hashedUserId", "HashedUserID",
)

# 数字扫描的兜底范围：KakaoTalk userId 通常在 [1e8, 1e10]
_CANDIDATE_MIN = 100_000_000
_CANDIDATE_MAX = 10_000_000_000


def _walk(obj: Any):
    """深度遍历 plist 结构，yield 所有 (key, value) 对；列表/元组中的裸值以 (None, item) 形式 yield。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield None, item
            yield from _walk(item)


def extract_user_id_info(plist: dict[str, Any] | None) -> dict[str, Any]:
    """从 plist 中提取 userId 直取值 / 哈希 / 候选列表。"""
    result: dict[str, Any] = {"direct": None, "hash": None, "candidates": []}
    if not plist:
        return result

    candidates: set[int] = set()

    for key, value in _walk(plist):
        # 1. 直取：键名匹配且值为整数/纯数字字符串
        if isinstance(key, str) and key in _USER_ID_KEYS:
            if isinstance(value, int) and _CANDIDATE_MIN <= value < _CANDIDATE_MAX:
                if result["direct"] is None:
                    result["direct"] = value
                candidates.add(value)
            elif isinstance(value, str) and value.isdigit():
                n = int(value)
                if _CANDIDATE_MIN <= n < _CANDIDATE_MAX:
                    if result["direct"] is None:
                        result["direct"] = n
                    candidates.add(n)

        # 2. 哈希：键名匹配且值为字符串（hex 或 base64）
        if isinstance(key, str) and key in _USER_ID_HASH_KEYS and isinstance(value, str):
            if result["hash"] is None and len(value) >= 16:
                result["hash"] = value.strip()

        # 3. 兜底候选：任何在合理范围内的整数
        if isinstance(value, int) and _CANDIDATE_MIN <= value < _CANDIDATE_MAX:
            candidates.add(value)
        elif isinstance(value, str) and value.isdigit():
            n = int(value)
            if _CANDIDATE_MIN <= n < _CANDIDATE_MAX:
                candidates.add(n)

    # 从字符串值中扫描嵌入的数字（如 "user_123456789" 之类）
    for key, value in _walk(plist):
        if isinstance(value, str) and len(value) < 256:
            for m in re.finditer(r"\d{9,10}", value):
                n = int(m.group())
                if _CANDIDATE_MIN <= n < _CANDIDATE_MAX:
                    candidates.add(n)

    if result["direct"] is not None:
        candidates.discard(result["direct"])
    result["candidates"] = sorted(candidates, key=lambda n: -n)[:32]
    return result
