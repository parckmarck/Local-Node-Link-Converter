"""Rule model and Clash rule export tests; offline and deterministic."""

import unittest

import yaml

from node_desk.formats import export_clash, parse_uri
from node_desk.rules import (
    MAX_RULES, NO_RESOLVE_TYPES, RULE_ACTIONS, RULE_TYPES,
    RuleError, default_rules, new_rule, render_rule, render_rules, validate_rule,
)


class ValidateTests(unittest.TestCase):
    def test_supported_types_and_actions_are_exposed(self):
        self.assertEqual(set(RULE_ACTIONS), {"PROXY", "AUTO", "DIRECT", "REJECT"})
        self.assertTrue(
            {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOIP",
             "GEOSITE", "IP-CIDR", "IP-CIDR6", "PROCESS-NAME"} <= set(RULE_TYPES)
        )

    def test_domain_values_are_normalized_and_validated(self):
        rule = validate_rule({"type": "DOMAIN-SUFFIX", "value": "  WWW.Example.COM ", "action": "DIRECT"})
        self.assertEqual(rule["value"], "www.example.com")
        self.assertIs(rule["enabled"], True)
        self.assertIs(rule["no_resolve"], False)
        for bad in ("bad domain.com", "a,b.com", "*", "..", "example/com"):
            with self.subTest(bad=bad):
                with self.assertRaises(RuleError):
                    validate_rule({"type": "DOMAIN", "value": bad, "action": "DIRECT"})

    def test_ip_cidr_normalizes_hosts_and_single_addresses(self):
        self.assertEqual(
            validate_rule({"type": "IP-CIDR", "value": "192.168.1.7/24", "action": "DIRECT"})["value"],
            "192.168.1.0/24",
        )
        self.assertEqual(
            validate_rule({"type": "IP-CIDR", "value": "10.0.0.5", "action": "DIRECT"})["value"],
            "10.0.0.5/32",
        )
        self.assertEqual(
            validate_rule({"type": "IP-CIDR6", "value": "fc00::/7", "action": "DIRECT"})["value"],
            "fc00::/7",
        )
        for rule_type, bad in (
            ("IP-CIDR", "fc00::/7"), ("IP-CIDR6", "10.0.0.0/8"),
            ("IP-CIDR", "999.1.1.1/24"), ("IP-CIDR", "10.0.0.0/33"),
        ):
            with self.subTest(rule_type=rule_type, bad=bad):
                with self.assertRaises(RuleError):
                    validate_rule({"type": rule_type, "value": bad, "action": "DIRECT"})

    def test_geo_keyword_and_process_values(self):
        self.assertEqual(validate_rule({"type": "GEOIP", "value": "cn", "action": "DIRECT"})["value"], "CN")
        self.assertEqual(
            validate_rule({"type": "GEOSITE", "value": "Category-Ads-ALL", "action": "REJECT"})["value"],
            "category-ads-all",
        )
        self.assertEqual(
            validate_rule({"type": "PROCESS-NAME", "value": "Telegram.exe", "action": "PROXY"})["value"],
            "Telegram.exe",
        )
        self.assertEqual(
            validate_rule({"type": "DOMAIN-KEYWORD", "value": "double click", "action": "DIRECT"})["value"],
            "double click",
        )
        for rule_type, bad in (
            ("GEOIP", "China"), ("GEOSITE", "a b"), ("PROCESS-NAME", "a,b"), ("DOMAIN-KEYWORD", "a,b"),
        ):
            with self.subTest(rule_type=rule_type):
                with self.assertRaises(RuleError):
                    validate_rule({"type": rule_type, "value": bad, "action": "DIRECT"})

    def test_action_enabled_and_no_resolve_are_strict(self):
        with self.assertRaises(RuleError):
            validate_rule({"type": "DOMAIN", "value": "a.com", "action": "PROXY-ish"})
        with self.assertRaises(RuleError):
            validate_rule({"type": "DOMAIN", "value": "a.com", "action": "DIRECT", "enabled": "yes"})
        normalized = validate_rule(
            {"type": "DOMAIN", "value": "a.com", "action": "DIRECT", "no_resolve": True}
        )
        self.assertIs(normalized["no_resolve"], False)  # 仅 IP / GEOIP 规则支持 no-resolve
        kept = validate_rule(
            {"type": "GEOIP", "value": "CN", "action": "DIRECT", "no_resolve": True}
        )
        self.assertIs(kept["no_resolve"], True)
        self.assertNotIn("GEOSITE", NO_RESOLVE_TYPES)


class RenderTests(unittest.TestCase):
    def test_render_skips_disabled_rules_and_keeps_order(self):
        enabled = new_rule("DOMAIN-SUFFIX", "example.com", "PROXY")
        disabled = new_rule("DOMAIN", "blocked.example", "REJECT", enabled=False)
        self.assertEqual(render_rules([disabled, enabled]), ["DOMAIN-SUFFIX,example.com,PROXY"])

    def test_no_resolve_suffix(self):
        rule = new_rule("IP-CIDR", "192.168.0.0/16", "DIRECT", no_resolve=True)
        self.assertEqual(render_rule(rule), "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")

    def test_invalid_entries_raise_with_position(self):
        ok = new_rule("DOMAIN", "ok.example", "DIRECT")
        bad = {"type": "DOMAIN", "value": "bad value", "action": "DIRECT", "enabled": True}
        with self.assertRaises(RuleError) as caught:
            render_rules([ok, bad])
        self.assertIn("2", str(caught.exception))

    def test_non_dict_entries_are_skipped_and_oversized_lists_rejected(self):
        self.assertEqual(render_rules([1, "x", None]), [])
        with self.assertRaises(RuleError):
            render_rules([{} for _ in range(MAX_RULES + 1)])

    def test_none_renders_empty(self):
        self.assertEqual(render_rules(None), [])


class DefaultsTests(unittest.TestCase):
    def test_defaults_are_valid_unique_and_independent(self):
        first = default_rules()
        self.assertGreaterEqual(len(first), 20)
        self.assertEqual(len({rule["id"] for rule in first}), len(first))
        for rule in first:
            validate_rule(rule)
            render_rule(rule)
        first.pop()
        self.assertEqual(len(default_rules()), len(first) + 1)

    def test_defaults_cover_lan_ads_cn_and_services(self):
        rendered = render_rules(default_rules())
        self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", rendered)
        self.assertIn("GEOSITE,category-ads-all,REJECT", rendered)
        self.assertIn("GEOSITE,cn,DIRECT", rendered)
        self.assertIn("GEOIP,CN,DIRECT", rendered)
        self.assertIn("DOMAIN-SUFFIX,t.me,PROXY", rendered)
        self.assertIn("DOMAIN-SUFFIX,netflix.com,PROXY", rendered)
        self.assertLess(
            rendered.index("GEOSITE,category-ads-all,REJECT"),
            rendered.index("GEOSITE,cn,DIRECT"),
        )


class ClashExportTests(unittest.TestCase):
    def node(self):
        return parse_uri("socks5://test:test-pass@127.0.0.1:1080#Subscription")

    def test_rules_are_inserted_before_the_fallback(self):
        rules = [
            new_rule("DOMAIN-SUFFIX", "example.com", "PROXY"),
            new_rule("IP-CIDR", "192.168.0.0/16", "DIRECT", no_resolve=True, enabled=False),
            new_rule("GEOIP", "CN", "DIRECT"),
        ]
        config = yaml.safe_load(export_clash([self.node()], rules=rules))
        self.assertEqual(config["rules"], [
            "DOMAIN-SUFFIX,example.com,PROXY",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ])

    def test_default_export_keeps_only_the_fallback(self):
        config = yaml.safe_load(export_clash([self.node()]))
        self.assertEqual(config["rules"], ["MATCH,PROXY"])

    def test_invalid_rules_reject_the_export(self):
        with self.assertRaises(ValueError):
            export_clash([self.node()], rules=[{"type": "NOPE", "value": "x", "action": "PROXY"}])


if __name__ == "__main__":
    unittest.main()
