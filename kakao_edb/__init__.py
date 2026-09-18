"""kakao-edb-sdk 的 Python 版本。

对齐 JS 版模块划分：
    kakao_edb.db.key_derivation   ↔ src/db/keyDerivation.js
    kakao_edb.db.plist_parser     ↔ src/db/plistParser.js
    kakao_edb.db.kakao_db         ↔ src/db/kakaoDb.js（统一查询库）
    kakao_edb.db.sqlcipher        ↔ vendor/sqlcipher.mjs（外部 sqlcipher3 二进制桥）
    kakao_edb.mac.discover        ↔ src/mac/discover.cjs
    kakao_edb.win.*               ↔ src/win/winKakao.cjs（按职责拆分）
    kakao_edb.orchestrator        ↔ src/orchestrator.mjs
    kakao_edb.cli                 ↔ bin/kkv.mjs

外部依赖：sqlcipher3 可执行文件（brew/choco/scoop/apt 安装）。
运行时：Python ≥ 3.10，零 pip 依赖。
"""
from .orchestrator import Session, create_session
from .db.key_derivation import (
    derive_secure_key,
    derive_database_name,
    hashed_device_uuid,
    is_valid_uuid,
    bytes_to_hex,
)
from .db.plist_parser import parse_plist, extract_user_id_info
from .db.kakao_db import KakaoDB

__all__ = [
    "Session",
    "create_session",
    "KakaoDB",
    "derive_secure_key",
    "derive_database_name",
    "hashed_device_uuid",
    "is_valid_uuid",
    "bytes_to_hex",
    "parse_plist",
    "extract_user_id_info",
]
__version__ = "0.1.0"
