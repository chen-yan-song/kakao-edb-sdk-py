"""sqlcipher_page 进程内 AES 页头预筛的回归测试。

用 cryptography 构造一个符合 SQLCipher 4 布局假设的合成 page1
（salt + CBC 密文 + reserve/IV），验证 check_page1_key：
  - 对「正确密钥」判 True
  - 对「错误 / 随机密钥」判 False（强特征字段联合误报率 ~2^-59）
  - 探针不足整页 / 密钥长度不对时安全返回 False
  - available() 与 cryptography 是否可导入一致

注意：本测试证明「AES 原语 + 页头特征校验」逻辑自洽（加解密 roundtrip 正确），
不证明真实 KakaoTalk 一定用这套参数——后者需实机确认。但预筛是安全兜底设计：
参数不符只会退化为「无加速」，绝不影响 collect-keys 的正确性。
"""
from __future__ import annotations

import os
import unittest

from kakao_edb.db import sqlcipher_page

PAGE = 4096
RESERVE = 48

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False


def _build_fake_page1(key: bytes, iv: bytes, reserve: int = RESERVE,
                      page_size: int = PAGE) -> bytes:
    """按 SQLCipher 4 布局假设合成一个 page1（首块密文由 key/iv 加密真实头特征）。"""
    tail = bytearray(16)
    # page size 字段：65536 在 SQLite 头里编码为 1
    ps_field = 1 if page_size == 65536 else page_size
    tail[0:2] = ps_field.to_bytes(2, "big")
    tail[2] = 2            # write format version
    tail[3] = 2            # read format version
    tail[4] = reserve      # reserved space
    tail[5] = 64           # max embedded payload fraction
    tail[6] = 32           # min embedded payload fraction
    tail[7] = 32           # leaf payload fraction
    tail[8:12] = (7).to_bytes(4, "big")    # file change counter
    tail[12:16] = (42).to_bytes(4, "big")  # db size in pages
    # CBC 加密首块（16 字节，块对齐）
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct0 = enc.update(bytes(tail[0:16])) + enc.finalize()
    # 组装：salt(16) + ct0(16) + 填充 + reserve(IV + HMAC 占位)
    body = bytearray()
    body += b"\xaa" * 16                          # salt
    body += ct0                                    # 首块密文
    body += b"\x00" * (page_size - reserve - len(body))  # 填充到 ps-reserve
    body += iv                                     # reserve 首 16 = IV
    body += b"\x00" * (reserve - 16)               # HMAC 占位
    assert len(body) == page_size, len(body)
    return bytes(body)


@unittest.skipUnless(HAS_CRYPTO, "cryptography 不可用，跳过预筛测试")
class TestCheckPage1Key(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(32))
        self.iv = bytes(range(200, 216))
        self.page1 = _build_fake_page1(self.key, self.iv)

    def test_correct_key_passes(self) -> None:
        self.assertTrue(sqlcipher_page.check_page1_key(self.page1, self.key))

    def test_wrong_key_fails(self) -> None:
        wrong = bytes((b + 1) % 256 for b in self.key)
        self.assertFalse(sqlcipher_page.check_page1_key(self.page1, wrong))

    def test_random_keys_no_false_positive(self) -> None:
        """大量随机错误密钥不应误报（联合误报率 ~2^-59）。"""
        fp = sum(1 for _ in range(3000)
                 if sqlcipher_page.check_page1_key(self.page1, os.urandom(32)))
        self.assertEqual(fp, 0)

    def test_short_probe_returns_false(self) -> None:
        # 探针不足整页 → 无法定位页尾 IV → 预筛失效返回 False（安全降级）
        self.assertFalse(sqlcipher_page.check_page1_key(self.page1[:1024], self.key))

    def test_wrong_length_key_returns_false(self) -> None:
        self.assertFalse(sqlcipher_page.check_page1_key(self.page1, self.key[:16]))

    def test_header_field_mismatch_fails(self) -> None:
        """把 reserve 字段改成非 48 的合法页，用默认 reserve 校验应判 False。"""
        page1 = _build_fake_page1(self.key, self.iv, reserve=32)
        # check 默认按 reserve=48 定位 IV 且要求 header[20]==48 → 不匹配
        self.assertFalse(sqlcipher_page.check_page1_key(page1, self.key))


class TestAvailableFlag(unittest.TestCase):
    def test_available_matches_import(self) -> None:
        self.assertEqual(sqlcipher_page.available(), HAS_CRYPTO)


if __name__ == "__main__":
    unittest.main()
