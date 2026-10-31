from __future__ import annotations

import re
import unittest

from node_desk import formats
from node_desk.messages import format_message, test_message


class FormatMessageTests(unittest.TestCase):
    def test_static_messages_are_chinese(self):
        self.assertEqual(format_message("UUID must use the 8-4-4-4-12 hexadecimal form."),
                         "UUID 必须是 8-4-4-4-12 的十六进制格式。")
        self.assertEqual(format_message("WireGuard keys must be 32-byte Base64."),
                         "WireGuard 密钥必须是 32 字节的 Base64。")

    def test_label_patterns_and_nested_node_prefix(self):
        self.assertEqual(format_message("Port must be between 1 and 65535."), "端口必须在 1 到 65535 之间。")
        self.assertEqual(format_message("Share URI is required."), "链接不能为空。")
        self.assertEqual(format_message("Trojan password is required."), "缺少Trojan 密码。")
        self.assertEqual(format_message("Name is too long."), "名称过长。")
        self.assertEqual(
            format_message("VMess id must be a UUID or a custom string of at most 30 bytes."),
            "VMess 的 id 必须是 UUID，或不超过 30 字节的自定义字符串。")
        self.assertEqual(format_message("The sni option cannot be empty."), "参数 sni 不能为空。")
        self.assertEqual(format_message("Node 3: Unsupported VMess cipher."),
                         "第 3 个节点：不支持的 VMess 加密方式。")
        self.assertEqual(format_message("Node 2 must be a record."), "第 2 个节点的记录格式无效。")

    def test_unknown_or_empty_text_passes_through(self):
        self.assertEqual(format_message("custom diagnostic"), "custom diagnostic")
        self.assertEqual(format_message(None), "")
        self.assertEqual(test_message("Test cancelled."), "测试已取消。")

    def test_every_static_format_error_has_a_translation(self):
        source = open(formats.__file__, encoding="utf-8").read()
        for literal in re.findall(r'FormatError\("([^"]+)"\)', source):
            with self.subTest(message=literal):
                self.assertNotEqual(format_message(literal), literal)


if __name__ == "__main__":
    unittest.main()
