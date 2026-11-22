# -*- coding: utf-8 -*-
"""zte_factory 的离线自测：不联网，只校验纯函数。

运行：python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ontkit import zte_factory as zf


class TestKeyPool(unittest.TestCase):
    def test_all_versions_are_24_bytes(self):
        for ver in (1, 2, 3):
            self.assertEqual(len(zf.key_pool(ver, 0)), 24, "v%d 密钥长度" % ver)

    def test_v3_slice_is_xor_a5(self):
        """v3 取 RE_RAND_KEY_POOL[index:index+24] 后整体异或 0xA5。"""
        expected = bytes((b ^ 0xA5) & 0xFF for b in zf.AES_KEY_POOL_RERAND[17:41])
        self.assertEqual(zf.key_pool(3, 17), expected)

    def test_v3_index_zero_hex(self):
        """回归锚点：v3 索引 0 派生出的会话密钥。"""
        self.assertEqual(
            zf.key_pool(3, 0).hex(),
            "3996d074b9e7e092bded34d6b2e0dce1e67270d696f1d377",
        )

    def test_pools_are_96_bytes(self):
        for name in ("AES_KEY_POOL", "AES_KEY_POOL_NEW", "AES_KEY_POOL_RERAND"):
            self.assertEqual(len(getattr(zf, name)), 96, name)


class TestPad(unittest.TestCase):
    def test_pads_a_full_block_when_aligned(self):
        """固件侧按 NUL 结尾取串，16 字节也必须再补一块。"""
        self.assertEqual(len(zf._pad(b"a" * 16)), 32)
        self.assertEqual(len(zf._pad(b"a" * 32)), 48)

    def test_pads_to_next_block(self):
        self.assertEqual(len(zf._pad(b"a" * 15)), 16)
        self.assertEqual(len(zf._pad(b"SendInfo.gch?info=6|")), 32)

    def test_roundtrip(self):
        raw = b"SendInfo.gch?info=6|"
        self.assertEqual(zf.ecb_decrypt(zf.ecb_encrypt(raw, zf.key_pool(3, 0)),
                                        zf.key_pool(3, 0)), raw)


class TestMagicBytes(unittest.TestCase):
    def test_payload_passes_device_check(self):
        for mac in ("000729553557", "88c78f10e240"):
            raw = bytes.fromhex(mac)
            self.assertTrue(zf.verify_payload(zf.magic_bytes(raw), raw))


if __name__ == "__main__":
    unittest.main()
