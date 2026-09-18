"""plist 解析 + userId 提取测试。"""
from __future__ import annotations

import plistlib
import unittest

from kakao_edb.db.plist_parser import extract_user_id_info, parse_plist


class TestPlistParser(unittest.TestCase):
    def test_parse_plist_binary(self):
        data = plistlib.dumps({"userId": 123456789}, fmt=plistlib.FMT_BINARY)
        result = parse_plist(data)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["userId"], 123456789)

    def test_parse_plist_xml(self):
        data = plistlib.dumps({"userId": 123456789}, fmt=plistlib.FMT_XML)
        result = parse_plist(data)
        self.assertEqual(result["userId"], 123456789)

    def test_parse_plist_invalid(self):
        self.assertIsNone(parse_plist(b"not a plist"))
        self.assertIsNone(parse_plist(b""))

    def test_extract_direct_user_id(self):
        plist = {"userId": 444339421}
        info = extract_user_id_info(plist)
        self.assertEqual(info["direct"], 444339421)
        self.assertIsNone(info["hash"])

    def test_extract_user_id_string(self):
        plist = {"UserID": "444339421"}
        info = extract_user_id_info(plist)
        self.assertEqual(info["direct"], 444339421)

    def test_extract_hash(self):
        h = "a" * 128
        plist = {"userIdHash": h}
        info = extract_user_id_info(plist)
        self.assertIsNone(info["direct"])
        self.assertEqual(info["hash"], h)

    def test_candidates_from_nested(self):
        plist = {
            "someKey": "user_987654321",
            "nested": {"list": [111111111, 222222222]},
        }
        info = extract_user_id_info(plist)
        self.assertIn(987654321, info["candidates"])
        self.assertIn(111111111, info["candidates"])
        self.assertIn(222222222, info["candidates"])

    def test_out_of_range_excluded(self):
        plist = {"userId": 12345}  # 太小，不在 [1e8, 1e10)
        info = extract_user_id_info(plist)
        self.assertIsNone(info["direct"])

    def test_empty_plist(self):
        info = extract_user_id_info({})
        self.assertIsNone(info["direct"])
        self.assertIsNone(info["hash"])
        self.assertEqual(info["candidates"], [])

    def test_none_plist(self):
        info = extract_user_id_info(None)
        self.assertIsNone(info["direct"])


if __name__ == "__main__":
    unittest.main()
