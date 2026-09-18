# kakao-edb-sdk-py

[kakao-edb-sdk](../kakao-edb-sdk) 的 **Python 版本**——KakaoTalk 本地聊天数据库（EDB / SQLCipher）无头解密 SDK + CLI，模块划分与 JS 版一一对齐。

- **来源**：port of kakao-edb-sdk v0.1.0（JS/Node 版）
- **平台**：Windows（新版 KakaoTalk 两步流）/ macOS（UUID+userId 派生）
- **运行时**：Python ≥ 3.10，**零 pip 硬依赖**（核心全走标准库 + 外部 `sqlcipher` 可执行文件；内存取钥的 AES 预筛可选装 `cryptography` 加速）

---

## 与 JS 版的对应关系

| JS 版 | Python 版 | 说明 |
| --- | --- | --- |
| `src/db/keyDerivation.js` | `kakao_edb/db/key_derivation.py` | PBKDF2-HMAC-SHA256 / SHA-1+256 / base64，算法逐字节一致 |
| `src/db/plistParser.js` | `kakao_edb/db/plist_parser.py` | 改用 stdlib `plistlib`，更简洁 |
| `src/db/kakaoDb.js` | `kakao_edb/db/kakao_db.py` | 统一查询库 NTUser/NTChatRoom/NTChatMessage；走「sqlcipher 外部二进制解密 → stdlib sqlite3 ATTACH 汇总」 |
| `vendor/sqlcipher.mjs` | `kakao_edb/db/sqlcipher.py` | 不再内嵌 4MB wasm，改调外部 `sqlcipher` CLI |
| （JS 版在 wasm 内验证） | `kakao_edb/db/sqlcipher_page.py` | Python 版新增：进程内 AES 页头预筛，给内存取钥候选排序提速（可选依赖 `cryptography`，缺失时安全降级） |
| `src/mac/discover.cjs` | `kakao_edb/mac/discover.py` | ioreg + plist + 多进程 SHA-512 爆破（`multiprocessing` 替代 `worker_threads`） |
| `src/win/winKakao.cjs` | `kakao_edb/win/{discover,probe,snapshot,memscan,decrypt,status}.py` | 按职责拆分；内存取钥走纯 `ctypes`（无需 pywin32） |
| `src/orchestrator.mjs` | `kakao_edb/orchestrator.py` | Session 状态机，confirm/onStep/onProgress 钩子签名一致 |
| `bin/kkv.mjs` | `kakao_edb/cli.py` | argparse 子命令，`--json` / `--yes` / `--cache-dir` 全保留 |

---

## 外部依赖

**sqlcipher 可执行文件**（必需，不在 pip 里）：

```bash
# macOS
brew install sqlcipher

# Windows
choco install sqlcipher
# 或
scoop install sqlcipher

# Linux
sudo apt install sqlcipher
```

**可选**：Windows 内存取钥使用 `pywin32` 提升稳定性（未安装时回退纯 ctypes，功能等价）：

```bash
pip install pywin32   # 仅 Windows
```

**可选**：Windows 内存取钥的「进程内 AES 页头预筛」加速（`sqlcipher_page`）。未安装时自动降级为逐个 `sqlcipher` 子进程验证，**正确性不受影响**，仅慢一些：

```bash
pip install cryptography
```

---

## 安装

```bash
cd kakao-edb-sdk-py
pip install -e .          # 注册 kakao-edb 命令
# 或直接运行
python -m kakao_edb.cli --help
```

---

## 快速开始

### CLI

```bash
# 1. 先看状态（会告诉你下一步做什么）
kakao-edb status
#   KakaoTalk 运行中 : 是
#   已缓存密钥       : 0 把
#   建议动作         : exit-kakao   ← 按提示操作

# 2. 全自动编排（推荐；交互点终端确认，脚本场景加 --yes）
kakao-edb run --export ./out

# 3. 之后日常使用：密钥已缓存，退出 KakaoTalk 即可重复解密导出
kakao-edb run --yes --export ./out
```

子命令一览（与 JS 版完全一致）：

| 命令 | 作用 |
| --- | --- |
| `status` | 两步流状态检测（advice：decrypt-now / decrypt-snapshot / snapshot / collect-keys / exit-kakao） |
| `snapshot` | 退出态快照核心 EDB（含 WAL）到缓存目录 |
| `collect-keys` | 运行态从 KakaoTalk 进程内存提取密钥存缓存（需已登录并点开目标聊天室） |
| `decrypt [--out DIR]` | 用缓存密钥解密当前落盘 EDB，可写明文副本 |
| `run [--yes] [--export DIR]` | 全自动编排（平台自适应），`--export` 导出每聊天室 txt + `_summary.json` |
| `unify --files f1,f2 [--export DIR] [--user-id N]` | 把已解密明文库汇总为统一查询库 |
| 全局 `--cache-dir DIR` / `--json` | 自定义缓存目录 / 机器可读输出 |

### API

```python
from kakao_edb import create_session

def my_confirm(guide_text: str, ok_label: str) -> bool:
    print(guide_text)
    return input(f"{ok_label}？[y/N] ").strip().lower() in ("y", "yes")

session = create_session(
    cache_dir="~/.kakao-edb-sdk",
    on_step=lambda step, state, detail: print(f"[{step}:{state}] {detail}"),
    on_progress=lambda stage, detail: print(f"\r{stage}: {detail}", end=""),
    confirm=my_confirm,
)

r = session.run()             # 平台自适应全自动
if r.ok:
    db = r.db                 # KakaoDB 统一查询库
    print(r.stats)            # {'chatCount': ..., 'messageCount': ..., 'userCount': ...}
    chats = db.list_chats(500)
    rows, has_more = db.get_messages(chats[0].chat_id, offset=0, limit=50)
    hits = db.search_messages("关键词", 100)
    db.close()
else:
    print(r.reason, r.detail)  # user-aborted / no-edbs / max-rounds / ...
```

细粒度控制（自行编排两步流）：

```python
st = session.status()                       # 同步返回两步流状态
session.snapshot()                          # 退出态快照
session.collect_keys(edbs)                  # 运行态取钥
dec = session.decrypt_cached(edbs)          # 缓存密钥解密
db = session.open_unified(dec.files, seed)  # 汇总统一库
```

低层引擎直接可用：

```python
from kakao_edb import win, mac, KakaoDB, derive_secure_key, parse_plist, extract_user_id_info
# win: discover_windows / list_edb_files / win_two_step_status / snapshot_core_edbs /
#      collect_keys_to_cache / decrypt_with_cached_keys / probe_edb_state / ...
# mac: discover() / brute_user_id() / stop_brute()
```

---

## 工作原理

### Windows 两步流

新版 KakaoTalk 运行时把核心 EDB 锁死且磁盘全零（反取证），完全退出后才真实落盘；而解密密钥只在运行时驻留内存，且**每房间独立**。因此：

```
退出态：复制 EDB 快照 + 缓存探针  →  运行态：内存提取密钥存缓存  →  退出后：用密钥解密快照/落盘文件
```

密钥缓存后，日常只需「退出 KakaoTalk → run」即可拿到最新数据。状态机（`run_windows`）按 `win_two_step_status()` 的 advice 分支，最多 4 轮用户引导防死循环。

内存取钥（`kakao_edb/win/memscan.py`）：
1. `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` 打开 KakaoTalk.exe
2. `VirtualQueryEx` 枚举 `MEM_COMMIT` + 可读 + 非 GUARD 区域
3. `ReadProcessMemory` 分块（4MB）扫描，定位探针头（page1 前 4096B）命中点
4. 在命中点 ±64KB 窗口内提取 32 字节对齐候选密钥（窗口即领域过滤 + 数量上限兜底）
5. 进程内 AES 页头预筛给候选排序（`sqlcipher_page`，可选依赖 `cryptography`），再用 `sqlcipher verify_key` 对「退出态快照副本」逐个精验，通过者入缓存。预筛只调顺序不删候选，命不中时退回逐个子进程验证，正确性不受影响

### macOS 全自动

IOPlatformUUID + userId（缓存优先 → plist 直取 / 哈希爆破 / 候选，还原结果自动缓存）→ PBKDF2 100,000 次派生密钥 → 候选主库逐个 HMAC 验证选库（残留旧库/多账号不会选错）→ 解密主库 + `-wal/-shm/-journal` 伴随文件。

---

## 目录结构

```
kakao_edb/
  __init__.py            公共入口（create_session / KakaoDB / derive_secure_key / ...）
  orchestrator.py        无头编排器（Session：两步流状态机 + confirm 钩子）
  cli.py                 CLI（argparse，对齐 bin/kkv.mjs）
  cache.py               缓存目录 JSON 读写（密钥/探针/快照/userId）
  db/
    key_derivation.py    PBKDF2-HMAC-SHA256 / SHA-1+256 / base64
    plist_parser.py      plistlib 封装 + extract_user_id_info
    kakao_db.py          统一查询库（sqlite3 ATTACH 汇总）
    sqlcipher.py         外部 sqlcipher 二进制桥（解密 + WAL 重放 + verify_key）
    sqlcipher_page.py    进程内 AES 页头预筛（内存取钥候选排序提速，可选 cryptography）
  mac/
    discover.py          ioreg + plist + 多进程 SHA-512 爆破
  win/
    discover.py          注册表设备材料 + KakaoTalk 目录发现 + 进程检测
    probe.py             全零页/独占锁三态检测 + 探针头缓存
    snapshot.py          退出态 EDB 快照（含伴随文件）
    memscan.py           ctypes ReadProcessMemory + AES 页头预筛 + 快照副本验证
    decrypt.py           缓存密钥解密
    status.py            win_two_step_status 两步流状态机
tests/
  test_key_derivation.py 密钥派生回归（与 JS 版测试向量一致）
  test_plist_parser.py   plist 解析 + userId 提取
  test_kakao_db.py       统一汇总回归（明文空 key map / 跨库 logId 冲突不丢消息）
  test_sqlcipher_page.py AES 页头预筛 roundtrip（正确钥判真 / 随机钥零误报 / 降级安全）
```

---

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `KKV_WIN_BASE_DIR` | 覆盖 KakaoTalk 数据根目录（默认 `%LocalAppData%\Kakao\KakaoTalk`） |
| `KAKAO_EDB_CACHE_DIR` | 覆盖缓存目录（默认 `~/.kakao-edb-sdk`） |

---

## 使用限制（与 JS 版一致）

### 平台差异速览

| 限制项 | Windows | macOS |
| --- | --- | --- |
| 解密前必须退出 KakaoTalk | **必须**（运行时反取证：文件全零+独占锁） | **不需要** |
| 密钥获取方式 | 运行时**内存扫描提取**（每房间一把独立密钥） | 本地**派生计算**（userId + IOPlatformUUID → PBKDF2） |
| 「没点开的聊天室」能解吗 | **不能**（密钥未驻留内存） | **能**（单密钥开整个库） |
| 首次使用耗时 | 取钥约 2–5 分钟 | 秒级（userId 还原结果有缓存） |
| 杀软/主动防御拦截 | **会**（dump 进程内存是敏感行为） | 不涉及 |
| 密钥是否落盘缓存 | **是**（明文 JSON，敏感） | 否（仅缓存 userId 还原结果） |

### 通用限制

1. **仅本机数据**——只解密当前系统账户下 KakaoTalk 的本地数据库
2. **以文本消息为主**——不还原图片/视频/文件本体
3. **统一库为磁盘态**——Python 版汇总产物落在临时目录（`tempfile.TemporaryDirectory`），进程退出即清理；JS 版为内存态
4. **外部 sqlcipher 二进制**——不再内嵌 wasm，需系统安装 sqlcipher
5. **KakaoTalk 升级风险**——内存布局、加密参数、目录结构随客户端版本变化
6. **仅限本人数据**——用于导出/备份**自己账号**的聊天记录

---

## 测试

```bash
pip install -e ".[dev]"
pytest tests/
```

- `tests/test_key_derivation.py`：密钥派生回归（与 JS 版测试向量一致）
- `tests/test_plist_parser.py`：plist 解析 + userId 提取

实机回归（需本机 KakaoTalk + 真实样本）：

```bash
kakao-edb status
kakao-edb run --export ./out
```

---

## 与 JS 版的差异说明

1. **SQLCipher 实现**：JS 版内嵌 4.1MB wasm（`vendor/sqlcipher.mjs`），Python 版改调外部 `sqlcipher` 二进制。产物 schema 与查询 API 完全一致，但 Python 版需要系统安装 sqlcipher。
2. **统一库存储**：JS 版汇总库为纯内存态（MEMFS），Python 版走 `tempfile.TemporaryDirectory` + stdlib `sqlite3`，进程退出自动清理。
3. **内存取钥**：JS 版用 Node `Buffer` + 自实现模式匹配，Python 版用纯 `ctypes`（`OpenProcess` / `VirtualQueryEx` / `ReadProcessMemory`），无需 pywin32。
4. **多线程爆破**：JS 版 `worker_threads` + `SharedArrayBuffer`，Python 版 `multiprocessing` + `Event`。
5. **plist 解析**：JS 版自实现二进制 plist 解析器（334 行），Python 版直接用 stdlib `plistlib`（~10 行）。
