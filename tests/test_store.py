from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from node_desk.formats import export_clash, parse_uri
from node_desk.security import SecretCodec
from node_desk.store import Store


def node(port=1080, name="Example"):
    return parse_uri(f"socks5://test:super-secret-node-password@127.0.0.1:{port}#{name}")


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path, protected=False)
    yield value
    value.close()


def test_fresh_settings_and_persistence(tmp_path):
    value = Store(tmp_path, protected=False)
    settings = value.settings()
    assert settings["port"] == 17890
    assert len(settings["token"]) >= 40
    assert value.add_nodes([node()], "one") == (1, 0)
    value.close()
    again = Store(tmp_path, protected=False)
    assert again.settings() == settings
    assert again.list_nodes()[0]["group"] == "one"
    again.close()


def test_name_independent_deduplication(store):
    assert store.add_nodes([node(), node(name="Renamed")]) == (1, 1)
    assert store.add_nodes([node()]) == (0, 1)
    assert store.list_nodes()[0]["name"] == "Example"


def test_edit_and_rename_are_exportable(store):
    store.add_nodes([node()])
    item = store.list_nodes()[0]
    changed = store.update_node(item["id"], name="New Name", note="memo", group="group", enabled=False)
    assert changed["name"] == "New Name"
    assert changed["enabled"] is False
    assert "New Name" in export_clash([changed])
    assert changed["note"] == "memo"


def test_changing_uri_resets_old_tests(store):
    store.add_nodes([node()])
    item = store.list_nodes()[0]
    store.save_test_result({
        "node_id": item["id"], "name": item["name"], "mode": "proxy", "status": "ok",
        "latency_ms": 1, "checked_at": "2026-10-28T00:00:00Z", "message": "ok",
    })
    renamed = store.update_node(item["id"], name="Only Name")
    assert renamed["tests"]["proxy"]["status"] == "ok"
    changed = store.update_node(item["id"], uri=node(1081)["uri"])
    assert changed["tests"] == {}
    assert changed["port"] == 1081


def test_edit_to_duplicate_is_atomic(store):
    store.add_nodes([node(1080), node(1081)])
    items = sorted(store.list_nodes(), key=lambda entry: entry["port"])
    with pytest.raises(ValueError):
        store.update_node(items[1]["id"], uri=items[0]["uri"])
    assert store.get_node(items[1]["id"])["port"] == 1081


def test_targeted_batch_enable_and_delete(store):
    store.add_nodes([node(1080), node(1081), node(1082)])
    ids = [item["id"] for item in store.list_nodes()]
    assert store.set_enabled(ids[:2], False) == 2
    assert sum(item["enabled"] for item in store.list_nodes()) == 1
    assert store.delete_nodes([ids[0], ids[0], "' OR 1=1; --"]) == 1
    assert len(store.list_nodes()) == 2


def test_import_cap_rolls_back_entire_transaction(store, monkeypatch):
    monkeypatch.setattr("node_desk.store.MAX_NODES", 2)
    with pytest.raises(ValueError):
        store.add_nodes([node(1080), node(1081), node(1082)])
    assert store.list_nodes() == []


def test_backup_merge_revalidates_and_preserves_metadata(store, tmp_path):
    store.add_nodes([node(1080), node(1081)], "local")
    item = store.list_nodes()[0]
    store.update_node(item["id"], enabled=False, note="retained", name="New Name")
    backup = store.export_backup()
    assert store.settings()["token"] not in backup
    other = Store(tmp_path / "other", protected=False)
    assert other.import_backup(backup) == (2, 0)
    assert other.import_backup(backup) == (0, 2)
    restored = next(item for item in other.list_nodes() if item["name"] == "New Name")
    assert restored["note"] == "retained"
    assert restored["enabled"] is False
    assert restored["group"] == "local"
    other.close()


def test_invalid_backup_is_all_or_nothing(store):
    data = {
        "format": "node-desk-backup", "version": 1,
        "nodes": [
            {"name": "valid", "uri": node()["uri"]},
            {"name": "invalid", "uri": "vless://broken"},
        ],
    }
    with pytest.raises(ValueError):
        store.import_backup(json.dumps(data))
    assert store.list_nodes() == []


@pytest.mark.parametrize("changes", [
    {"port": 0}, {"port": True}, {"port": 65536}, {"timeout_ms": 5},
    {"concurrency": 99}, {"start_service": "yes"}, {"test_url": "file:///x"},
    {"test_url": "https://user:pass@example.com/"}, {"test_url": "https://example.com:abc"},
    {"test_url": "https://example.com/#secret"}, {"core_path": 123}, {"token": "override"},
])
def test_settings_validation(store, changes):
    original = store.settings()
    with pytest.raises(ValueError):
        store.update_settings(changes)
    assert store.settings() == original


def test_rotating_token_does_not_change_other_settings(store):
    old = store.settings()
    token = store.rotate_token()
    assert token != old["token"]
    assert {**old, "token": token} == store.settings()


def test_rules_seed_edit_reorder_and_delete(store):
    rules = store.list_rules()
    assert len(rules) >= 20
    assert any(rule["value"] == "category-ads-all" for rule in rules)
    created = store.add_rule({"type": "DOMAIN", "value": " Example.COM ", "action": "DIRECT"})
    assert created["value"] == "example.com"
    assert created["enabled"] is True
    assert store.move_rule(created["id"], -1) is True
    assert store.list_rules()[-2]["id"] == created["id"]
    assert store.move_rule(rules[0]["id"], -1) is False
    changed = store.update_rule(created["id"], enabled=False, no_resolve=True)
    assert changed["enabled"] is False
    assert changed["no_resolve"] is False  # 非 IP 规则自动忽略 no-resolve
    assert store.delete_rule(created["id"]) is True
    assert store.delete_rule(created["id"]) is False
    with pytest.raises(ValueError):
        store.add_rule({"type": "NOPE", "value": "x", "action": "DIRECT"})
    with pytest.raises(KeyError):
        store.update_rule("missing", enabled=True)


def test_rules_survive_backup_round_trip_and_reset(store, tmp_path):
    rules = store.list_rules()
    store.update_rule(rules[0]["id"], enabled=False)
    backup = json.loads(store.export_backup())
    assert len(backup["rules"]) == len(rules)
    assert all("id" not in entry for entry in backup["rules"])
    other = Store(tmp_path / "other", protected=False)
    try:
        other.import_backup(json.dumps(backup))
        restored = other.list_rules()
        assert len(restored) == len(rules)
        assert restored[0]["enabled"] is False
        assert restored[0]["id"] != rules[0]["id"]
    finally:
        other.close()
    store.reset_rules()
    assert len(store.list_rules()) == len(rules)
    assert all(rule["enabled"] for rule in store.list_rules())


def test_invalid_backup_rules_reject_the_whole_backup(store):
    before = store.list_rules()
    data = {
        "format": "node-desk-backup", "version": 1,
        "nodes": [{"name": "valid", "uri": node()["uri"]}],
        "rules": [
            {"type": "DOMAIN-SUFFIX", "value": "ok.example", "action": "DIRECT"},
            {"type": "NOPE", "value": "x", "action": "DIRECT"},
        ],
    }
    with pytest.raises(ValueError):
        store.import_backup(json.dumps(data))
    assert store.list_nodes() == []
    assert store.list_rules() == before


def test_test_session_lifecycle_summary_and_prune(store, monkeypatch):
    monkeypatch.setattr("node_desk.store.MAX_TEST_SESSIONS", 3)
    session_id = store.start_test_session("proxy", 3)
    for index, status in enumerate(("ok", "failed", "cancelled")):
        store.add_test_session_item(session_id, {
            "node_id": f"node-{index}", "name": f"Node {index}", "mode": "proxy",
            "status": status, "latency_ms": 20 if status == "ok" else None,
            "message": "Synthetic result.", "checked_at": "2026-10-29T10:00:00+00:00",
        })
    with pytest.raises(ValueError):
        store.add_test_session_item(session_id, {"status": "bogus"})
    store.finish_test_session(session_id, cancelled=True)
    store.finish_test_session(session_id)  # 重复收尾不会覆盖取消标记
    listed = store.list_test_sessions()
    assert len(listed) == 1
    assert listed[0]["counts"] == {"ok": 1, "failed": 1, "unsupported": 0, "cancelled": 1}
    assert listed[0]["tested"] == 3 and listed[0]["cancelled"] is True
    assert "items" not in listed[0]
    assert len(store.get_test_session(session_id)["items"]) == 3

    newer = [store.start_test_session("tcp", 1) for _ in range(4)]
    remaining = [item["id"] for item in store.list_test_sessions()]
    assert remaining == list(reversed(newer[-3:]))
    assert session_id not in remaining
    store.add_test_session_item(session_id, {"status": "ok"})  # 已清理的记录被静默忽略
    with pytest.raises(KeyError):
        store.get_test_session(session_id)


def test_concurrent_service_reads_and_ui_writes(store):
    store.add_nodes([node(port) for port in range(1080, 1100)])
    ids = [item["id"] for item in store.list_nodes()]

    def read():
        for _ in range(25):
            assert len(store.list_nodes()) == 20
            assert store.settings()["port"] == 17890

    def write():
        for turn in range(25):
            store.set_enabled(ids, turn % 2 == 0)

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(read), executor.submit(read), executor.submit(write)]
        for future in futures:
            future.result()


def test_deleted_node_result_is_ignored(store):
    store.save_test_result({"node_id": "missing", "mode": "proxy", "status": "ok"})
    assert store.list_nodes() == []


def test_newer_database_version_is_not_overwritten(tmp_path):
    path = tmp_path / "nodes.sqlite3"
    database = sqlite3.connect(path)
    database.execute("PRAGMA user_version=2")
    database.close()
    with pytest.raises(ValueError, match="newer"):
        Store(tmp_path, protected=False)
    database = sqlite3.connect(path)
    assert database.execute("PRAGMA user_version").fetchone()[0] == 2
    database.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI")
def test_dpapi_round_trip_and_no_plaintext_database(tmp_path):
    codec = SecretCodec()
    secret = b"super-secret-node-password"
    encrypted = codec.encode(secret)
    assert secret not in encrypted
    assert codec.decode(encrypted) == secret
    with pytest.raises(OSError):
        codec.decode(b"DPAPI1:corrupt")
    with pytest.raises(ValueError):
        codec.decode(b"PLAIN1:secret")
    protected = Store(tmp_path)
    protected.add_nodes([node()])
    assert protected.list_nodes()[0]["server"] == "127.0.0.1"
    protected.close()
    assert secret not in (tmp_path / "nodes.sqlite3").read_bytes()
