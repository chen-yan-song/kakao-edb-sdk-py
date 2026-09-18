"""KakaoTalk Mac 数据库密钥派生（对齐 src/db/keyDerivation.js）。

算法与 kakaocli（silver-flight-group/kakaocli）的 KeyDerivation.swift 完全一致：
  secureKey    = PBKDF2-HMAC-SHA256(reverse(hawawa), salt, 100_000, 128B).hex()
  databaseName = 同上 PBKDF2，取 hex[28:28+78]（78 字符）
  hawawa       = "A" + hashedUUID + "|" + "F" + uuid[:5] + "H" + userId + "|" + uuid[7:]，以 "F" 连接
  hashedUUID   = base64(SHA1(uuid) || SHA256(uuid))
  salt         = uuid[floor(len(uuid) * 0.3):]
"""
from __future__ import annotations

import base64
import hashlib
import re

PBKDF2_ITERATIONS = 100_000
PBKDF2_KEY_LEN = 128  # 字节


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _pbkdf2_sha256(password: str, salt: str, iterations: int = PBKDF2_ITERATIONS,
                   key_length: int = PBKDF2_KEY_LEN) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations, key_length
    )


def hashed_device_uuid(uuid: str) -> str:
    """SHA1(uuid) || SHA256(uuid) → base64（与 Swift hashedDeviceUUID 一致）。"""
    data = uuid.encode("utf-8")
    return bytes_to_base64(hashlib.sha1(data).digest() + hashlib.sha256(data).digest())


def _reverse(s: str) -> str:
    return s[::-1]


def derive_secure_key(user_id: int | str, uuid: str) -> str:
    """派生 SQLCipher 加密密钥（hex 字符串，256 字符）。"""
    hashed = hashed_device_uuid(uuid)
    parts = ["A", hashed, "|", "F", uuid[:5], "H", str(user_id), "|", uuid[7:]]
    hawawa = "F".join(parts)
    salt_start = int(len(uuid) * 0.3)
    salt = uuid[salt_start:]
    return bytes_to_hex(_pbkdf2_sha256(_reverse(hawawa), salt))


def derive_database_name(user_id: int | str, uuid: str) -> str:
    """派生加密数据库文件名（不含扩展名，78 字符）。"""
    hawawa = ".".join([".", "F", str(user_id), "A", "F", _reverse(uuid), ".", "|"])
    salt = _reverse(hashed_device_uuid(uuid))
    hex_str = bytes_to_hex(_pbkdf2_sha256(hawawa, salt))
    return hex_str[28: 28 + 78]


_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


def is_valid_uuid(uuid: str) -> bool:
    return bool(_UUID_RE.match(uuid.strip()))
