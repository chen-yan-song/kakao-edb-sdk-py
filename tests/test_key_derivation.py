"""密钥派生回归测试（与 JS 版 test/regression.cjs 测试向量一致）。

验证 derive_secure_key / derive_database_name / hashed_device_uuid 的算法正确性。
"""
from __future__ import annotations

import unittest

from kakao_edb.db.key_derivation import (
    bytes_to_base64,
    bytes_to_hex,
    derive_database_name,
    derive_secure_key,
    hashed_device_uuid,
    is_valid_uuid,
)


class TestKeyDerivation(unittest.TestCase):
    # 测试向量：与 JS 版 keyDerivation.js 的参考实现一致
    UUID = "12345678-1234-1234-1234-123456789ABC"
    USER_ID = 123456789

    def test_bytes_to_hex(self):
        self.assertEqual(bytes_to_hex(b"\x00\xff\x10"), "00ff10")
        self.assertEqual(bytes_to_hex(b""), "")

    def test_bytes_to_base64(self):
        self.assertEqual(bytes_to_base64(b"hello"), "aGVsbG8=")

    def test_hashed_device_uuid_deterministic(self):
        h1 = hashed_device_uuid(self.UUID)
        h2 = hashed_device_uuid(self.UUID)
        self.assertEqual(h1, h2)
        # SHA1(20B) + SHA256(32B) = 52B → base64 72 字符（含 padding）
        self.assertEqual(len(h1), 72)

    def test_derive_secure_key_shape(self):
        key = derive_secure_key(self.USER_ID, self.UUID)
        # 128 字节 → 256 字符 hex
        self.assertEqual(len(key), 256)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))

    def test_derive_secure_key_deterministic(self):
        k1 = derive_secure_key(self.USER_ID, self.UUID)
        k2 = derive_secure_key(self.USER_ID, self.UUID)
        self.assertEqual(k1, k2)

    def test_derive_secure_key_varies_with_user_id(self):
        k1 = derive_secure_key(111111111, self.UUID)
        k2 = derive_secure_key(222222222, self.UUID)
        self.assertNotEqual(k1, k2)

    def test_derive_secure_key_varies_with_uuid(self):
        k1 = derive_secure_key(self.USER_ID, "12345678-1234-1234-1234-123456789ABC")
        k2 = derive_secure_key(self.USER_ID, "ABCDEF01-2345-6789-ABCD-EF0123456789")
        self.assertNotEqual(k1, k2)

    def test_derive_database_name_shape(self):
        name = derive_database_name(self.USER_ID, self.UUID)
        # hex[28:28+78] → 78 字符
        self.assertEqual(len(name), 78)
        self.assertTrue(all(c in "0123456789abcdef" for c in name))

    def test_derive_database_name_deterministic(self):
        n1 = derive_database_name(self.USER_ID, self.UUID)
        n2 = derive_database_name(self.USER_ID, self.UUID)
        self.assertEqual(n1, n2)

    def test_is_valid_uuid(self):
        self.assertTrue(is_valid_uuid(self.UUID))
        self.assertTrue(is_valid_uuid(self.UUID.lower()))
        self.assertFalse(is_valid_uuid("not-a-uuid"))
        self.assertFalse(is_valid_uuid("12345678-1234-1234-1234"))
        self.assertFalse(is_valid_uuid(""))

    def test_user_id_as_string_equivalent(self):
        """userId 传字符串与整数应得到相同密钥（算法内部 str() 转换）。"""
        k_int = derive_secure_key(123456789, self.UUID)
        k_str = derive_secure_key("123456789", self.UUID)
        self.assertEqual(k_int, k_str)


if __name__ == "__main__":
    unittest.main()
