from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .rules import MAX_RULES, default_rules, validate_rule
from .security import SecretCodec

MAX_NODES = 5000
MAX_TEST_SESSIONS = 50
MAX_BACKUP_BYTES = 8 * 1024 * 1024
DEFAULT_SETTINGS = {
    "port": 17890,
    "start_service": True,
    "timeout_ms": 8000,
    "concurrency": 4,
    "test_url": "https://www.gstatic.com/generate_204",
    "core_path": "",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint(node: dict) -> str:
    config = {key: value for key, value in node["clash"].items() if key != "name"}
    encoded = json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def clean_label(value: str, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("Text value required.")
    result = value.strip()
    if (not result and not allow_empty) or len(result) > limit:
        raise ValueError(f"Text must contain 1 to {limit} characters.")
    if any(ord(char) < 32 and char not in "\n\t" for char in result):
        raise ValueError("Control characters are not allowed.")
    return result


class Store:
    def __init__(self, data_dir: Path | str, *, protected: bool = True):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "nodes.sqlite3"
        self.codec = SecretCodec(protected)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self._db.close()
            raise ValueError("This database requires a newer version of Node Desk.")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS test_sessions (
                id TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            );
            PRAGMA user_version=1;
            """
        )
        with self._lock, self._db:
            row = self._db.execute("SELECT payload FROM settings WHERE id=1").fetchone()
            if row is None:
                self._save_settings({**DEFAULT_SETTINGS, "token": secrets.token_urlsafe(32)})
                row = self._db.execute("SELECT payload FROM settings WHERE id=1").fetchone()
            payload = self._decode(row[0])
            if not isinstance(payload.get("rules"), list):
                # Seed the built-in rule set once; deletions are respected later.
                payload["rules"] = default_rules()
                self._save_settings(payload)

    def _encode(self, value: dict) -> bytes:
        return self.codec.encode(json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def _decode(self, value: bytes) -> dict:
        return json.loads(self.codec.decode(value).decode("utf-8"))

    def _save_settings(self, value: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO settings (id, payload) VALUES (1, ?)",
            (self._encode(value),),
        )

    def settings(self) -> dict:
        with self._lock:
            row = self._db.execute("SELECT payload FROM settings WHERE id=1").fetchone()
            return {**DEFAULT_SETTINGS, **self._decode(row[0])}

    def update_settings(self, changes: dict) -> dict:
        if not isinstance(changes, dict) or set(changes) - set(DEFAULT_SETTINGS):
            raise ValueError("Unknown settings.")
        with self._lock, self._db:
            settings = {**self.settings(), **changes}
            for key, minimum, maximum in (
                ("port", 1024, 65535),
                ("timeout_ms", 1000, 30000),
                ("concurrency", 1, 16),
            ):
                value = settings[key]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"Invalid {key}.")
                if not minimum <= value <= maximum:
                    raise ValueError(f"{key} must be between {minimum} and {maximum}.")
            if not isinstance(settings["start_service"], bool):
                raise ValueError("Invalid startup option.")
            url = urlsplit(settings["test_url"])
            if (
                url.scheme not in ("http", "https")
                or not url.hostname
                or url.username is not None
                or url.password is not None
                or url.fragment
                or len(settings["test_url"]) > 2048
            ):
                raise ValueError("A valid HTTP(S) test URL without credentials is required.")
            try:
                url.port
            except ValueError as error:
                raise ValueError("Invalid test URL port.") from error
            if any(ord(char) < 32 for char in settings["test_url"]):
                raise ValueError("Invalid test URL.")
            if not isinstance(settings["core_path"], str) or len(settings["core_path"]) > 4096:
                raise ValueError("Invalid core path.")
            self._save_settings(settings)
            return settings

    def rotate_token(self) -> str:
        with self._lock, self._db:
            settings = self.settings()
            settings["token"] = secrets.token_urlsafe(32)
            self._save_settings(settings)
            return settings["token"]

    def _load_rules(self) -> list:
        # Caller holds the lock. Rules live inside the settings payload so they
        # share the existing encrypted store without a schema migration.
        row = self._db.execute("SELECT payload FROM settings WHERE id=1").fetchone()
        payload = self._decode(row[0])
        rules = payload.get("rules")
        if not isinstance(rules, list):
            rules = default_rules()
            payload["rules"] = rules
            self._save_settings(payload)
        return rules

    def _save_rules(self, rules: list) -> None:
        row = self._db.execute("SELECT payload FROM settings WHERE id=1").fetchone()
        payload = self._decode(row[0])
        payload["rules"] = rules
        self._save_settings(payload)

    def list_rules(self) -> list[dict]:
        with self._lock:
            return [dict(rule) for rule in self._load_rules()]

    def add_rule(self, rule: dict) -> dict:
        if not isinstance(rule, dict):
            raise ValueError("Rule must be a mapping.")
        with self._lock, self._db:
            rules = self._load_rules()
            if len(rules) >= MAX_RULES:
                raise ValueError(f"规则数量已达上限（最多 {MAX_RULES} 条）。")
            created = validate_rule(rule)
            created["id"] = str(uuid.uuid4())
            rules.append(created)
            self._save_rules(rules)
            return dict(created)

    def update_rule(self, rule_id: str, **changes) -> dict:
        if set(changes) - {"type", "value", "action", "no_resolve", "enabled"}:
            raise ValueError("Unknown rule property.")
        with self._lock, self._db:
            rules = self._load_rules()
            for index, rule in enumerate(rules):
                if rule.get("id") == rule_id:
                    updated = validate_rule({**rule, **changes})
                    updated["id"] = rule_id
                    rules[index] = updated
                    self._save_rules(rules)
                    return dict(updated)
            raise KeyError("Rule no longer exists.")

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock, self._db:
            rules = self._load_rules()
            remaining = [rule for rule in rules if rule.get("id") != rule_id]
            if len(remaining) == len(rules):
                return False
            self._save_rules(remaining)
            return True

    def move_rule(self, rule_id: str, delta: int) -> bool:
        if delta not in (-1, 1):
            raise ValueError("Rule movement must be -1 or 1.")
        with self._lock, self._db:
            rules = self._load_rules()
            index = next((i for i, rule in enumerate(rules) if rule.get("id") == rule_id), None)
            if index is None:
                raise KeyError("Rule no longer exists.")
            target = index + delta
            if not 0 <= target < len(rules):
                return False
            rules[index], rules[target] = rules[target], rules[index]
            self._save_rules(rules)
            return True

    def reset_rules(self) -> list[dict]:
        with self._lock, self._db:
            rules = default_rules()
            self._save_rules(rules)
            return [dict(rule) for rule in rules]

    def list_nodes(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT payload FROM nodes ORDER BY rowid DESC").fetchall()
            return [self._decode(row[0]) for row in rows]

    def get_node(self, node_id: str) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM nodes WHERE id=?", (node_id,)
            ).fetchone()
            if row is None:
                raise KeyError("Node no longer exists.")
            return self._decode(row[0])

    def add_nodes(self, parsed: list[dict], group: str = "") -> tuple[int, int]:
        group = clean_label(group, 80, allow_empty=True)
        with self._lock, self._db:
            current_count = self._db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            added, duplicates = 0, 0
            for source in parsed:
                identity = fingerprint(source)
                if self._db.execute(
                    "SELECT id FROM nodes WHERE fingerprint=?", (identity,)
                ).fetchone():
                    duplicates += 1
                    continue
                if current_count + added >= MAX_NODES:
                    raise ValueError(f"The library cannot exceed {MAX_NODES} nodes.")
                node = {
                    **source,
                    "name": clean_label(source["name"], 256),
                    "id": str(uuid.uuid4()),
                    "group": group,
                    "enabled": True,
                    "note": "",
                    "created_at": utc_now(),
                    "updated_at": utc_now(),
                    "tests": {},
                }
                self._db.execute(
                    "INSERT INTO nodes (id, fingerprint, payload) VALUES (?, ?, ?)",
                    (node["id"], identity, self._encode(node)),
                )
                added += 1
            return added, duplicates

    def update_node(self, node_id: str, **changes) -> dict:
        if set(changes) - {"name", "group", "enabled", "note", "uri"}:
            raise ValueError("Unknown node property.")
        with self._lock, self._db:
            node = self.get_node(node_id)
            if "uri" in changes and changes["uri"].strip() != node["uri"]:
                from .formats import parse_uri

                parsed = parse_uri(changes["uri"].strip())
                node.update(parsed)
                node["tests"] = {}
            for key, limit in (("name", 256), ("group", 80), ("note", 2000)):
                if key in changes:
                    node[key] = clean_label(changes[key], limit, allow_empty=key != "name")
            if "enabled" in changes:
                if not isinstance(changes["enabled"], bool):
                    raise ValueError("Enabled must be a boolean.")
                node["enabled"] = changes["enabled"]
            node["updated_at"] = utc_now()
            try:
                self._db.execute(
                    "UPDATE nodes SET fingerprint=?, payload=? WHERE id=?",
                    (fingerprint(node), self._encode(node), node_id),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("This node already exists.") from error
            return node

    def set_enabled(self, node_ids: list[str], enabled: bool) -> int:
        if not isinstance(enabled, bool):
            raise ValueError("Enabled must be a boolean.")
        count = 0
        with self._lock, self._db:
            for node_id in set(node_ids):
                try:
                    node = self.get_node(node_id)
                except KeyError:
                    continue
                node.update(enabled=enabled, updated_at=utc_now())
                self._db.execute(
                    "UPDATE nodes SET payload=? WHERE id=?", (self._encode(node), node_id)
                )
                count += 1
        return count

    def delete_nodes(self, node_ids: list[str]) -> int:
        count = 0
        with self._lock, self._db:
            for node_id in set(node_ids):
                count += self._db.execute(
                    "DELETE FROM nodes WHERE id=?", (node_id,)
                ).rowcount
        return count

    def save_test_result(self, result: dict) -> None:
        if result["mode"] not in ("tcp", "proxy"):
            raise ValueError("Invalid test mode.")
        if result["status"] not in ("ok", "failed", "unsupported", "cancelled"):
            raise ValueError("Invalid test status.")
        with self._lock, self._db:
            try:
                node = self.get_node(result["node_id"])
            except KeyError:
                return
            node.setdefault("tests", {})[result["mode"]] = {
                key: result.get(key)
                for key in (
                    "node_id", "name", "mode", "status", "latency_ms",
                    "message", "checked_at",
                )
            }
            self._db.execute(
                "UPDATE nodes SET payload=? WHERE id=?",
                (self._encode(node), node["id"]),
            )

    def start_test_session(self, mode: str, total: int) -> str:
        """Open a batch record for one test run; oldest records are pruned."""
        if mode not in ("tcp", "proxy"):
            raise ValueError("Invalid test mode.")
        if isinstance(total, bool) or not isinstance(total, int) or not 0 <= total <= MAX_NODES:
            raise ValueError("Invalid node count.")
        session = {
            "id": str(uuid.uuid4()), "mode": mode, "started_at": utc_now(),
            "finished_at": None, "cancelled": False, "total": total, "items": [],
        }
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO test_sessions (id, payload) VALUES (?, ?)",
                (session["id"], self._encode(session)),
            )
            self._db.execute(
                "DELETE FROM test_sessions WHERE rowid NOT IN "
                "(SELECT rowid FROM test_sessions ORDER BY rowid DESC LIMIT ?)",
                (MAX_TEST_SESSIONS,),
            )
        return session["id"]

    def add_test_session_item(self, session_id: str, result: dict) -> None:
        status = result.get("status")
        if status not in ("ok", "failed", "unsupported", "cancelled"):
            raise ValueError("Invalid test status.")
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT payload FROM test_sessions WHERE id=?", (session_id,)
            ).fetchone()
            if row is None:
                return
            session = self._decode(row[0])
            if session.get("finished_at"):
                return
            session["items"].append({
                key: result.get(key)
                for key in ("node_id", "name", "status", "latency_ms", "message", "checked_at")
            })
            self._db.execute(
                "UPDATE test_sessions SET payload=? WHERE id=?",
                (self._encode(session), session_id),
            )

    def finish_test_session(self, session_id: str, *, cancelled: bool = False) -> None:
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT payload FROM test_sessions WHERE id=?", (session_id,)
            ).fetchone()
            if row is None:
                return
            session = self._decode(row[0])
            if session.get("finished_at"):
                return
            session["finished_at"] = utc_now()
            session["cancelled"] = bool(cancelled)
            self._db.execute(
                "UPDATE test_sessions SET payload=? WHERE id=?",
                (self._encode(session), session_id),
            )

    def list_test_sessions(self) -> list[dict]:
        """Newest first; summaries only (per-item results stay in the store)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM test_sessions ORDER BY rowid DESC"
            ).fetchall()
        summaries = []
        for row in rows:
            session = self._decode(row[0])
            counts = {"ok": 0, "failed": 0, "unsupported": 0, "cancelled": 0}
            for item in session.get("items", []):
                if item.get("status") in counts:
                    counts[item["status"]] += 1
            summary = {
                key: session.get(key)
                for key in ("id", "mode", "started_at", "finished_at", "cancelled", "total")
            }
            summary["counts"] = counts
            summary["tested"] = len(session.get("items", []))
            summaries.append(summary)
        return summaries

    def get_test_session(self, session_id: str) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM test_sessions WHERE id=?", (session_id,)
            ).fetchone()
        if row is None:
            raise KeyError("Test session no longer exists.")
        return self._decode(row[0])
        nodes = []
        for node in self.list_nodes():
            nodes.append(
                {key: node[key] for key in ("name", "uri", "group", "enabled", "note")}
            )
        rules = [
            {key: rule[key] for key in ("type", "value", "action", "no_resolve", "enabled")}
            for rule in self.list_rules()
        ]
        return json.dumps(
            {"format": "node-desk-backup", "version": 1, "created_at": utc_now(),
             "nodes": nodes, "rules": rules},
            ensure_ascii=False,
            indent=2,
        )

    def import_backup(self, text: str) -> tuple[int, int]:
        from .formats import parse_uri

        if len(text.encode("utf-8")) > MAX_BACKUP_BYTES:
            raise ValueError("Backup is too large.")
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as error:
            raise ValueError("Invalid backup JSON.") from error
        if (
            not isinstance(data, dict)
            or data.get("format") != "node-desk-backup"
            or data.get("version") != 1
            or not isinstance(data.get("nodes"), list)
            or len(data["nodes"]) > MAX_NODES
        ):
            raise ValueError("Unsupported backup format.")
        validated = []
        for index, source in enumerate(data["nodes"], 1):
            try:
                parsed = parse_uri(source["uri"])
                parsed["name"] = clean_label(source["name"], 256)
                parsed["group"] = clean_label(source.get("group", ""), 80, allow_empty=True)
                parsed["note"] = clean_label(source.get("note", ""), 2000, allow_empty=True)
                if not isinstance(source.get("enabled", True), bool):
                    raise ValueError("Invalid enabled flag.")
                parsed["enabled"] = source.get("enabled", True)
                validated.append(parsed)
            except (ValueError, TypeError, KeyError, AttributeError) as error:
                raise ValueError(f"Invalid node in backup at item {index}.") from error
        imported_rules = None
        if data.get("rules") is not None:
            source_rules = data["rules"]
            if not isinstance(source_rules, list) or len(source_rules) > MAX_RULES:
                raise ValueError("Invalid rules in backup.")
            imported_rules = []
            for index, source in enumerate(source_rules, 1):
                try:
                    rule = validate_rule(source)
                except ValueError as error:
                    raise ValueError(f"Invalid rule in backup at item {index}.") from error
                rule["id"] = str(uuid.uuid4())
                imported_rules.append(rule)
        added, duplicates = 0, 0
        with self._lock, self._db:
            current = self._db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            for parsed in validated:
                identity = fingerprint(parsed)
                if self._db.execute(
                    "SELECT id FROM nodes WHERE fingerprint=?", (identity,)
                ).fetchone():
                    duplicates += 1
                    continue
                if current + added >= MAX_NODES:
                    raise ValueError(f"The library cannot exceed {MAX_NODES} nodes.")
                node = {
                    **parsed, "id": str(uuid.uuid4()), "created_at": utc_now(),
                    "updated_at": utc_now(), "tests": {},
                }
                self._db.execute(
                    "INSERT INTO nodes (id, fingerprint, payload) VALUES (?, ?, ?)",
                    (node["id"], identity, self._encode(node)),
                )
                added += 1
            if imported_rules is not None:
                # A backup that carries rules replaces the current rule list.
                self._save_rules(imported_rules)
        return added, duplicates

    def close(self) -> None:
        with self._lock:
            self._db.close()
