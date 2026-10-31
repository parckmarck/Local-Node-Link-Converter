from __future__ import annotations

import base64
import http.client
import json
import socket
from urllib.parse import urlsplit

import pytest
import yaml

from node_desk.formats import parse_uri
from node_desk.service import SubscriptionService
from node_desk.store import Store


def request(service, path, method="GET", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", service.port, timeout=3)
    connection.request(method, path, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    result = response.status, dict(response.getheaders()), body
    connection.close()
    return result


def target(service, format="clash", group=None):
    url = urlsplit(service.url(format, group))
    return url.path + ("?" + url.query if url.query else "")


@pytest.fixture
def service(tmp_path):
    store = Store(tmp_path, protected=False)
    server = SubscriptionService(store)
    server.start(0)
    yield server
    server.stop()
    store.close()


def add_nodes(service):
    service.store.add_nodes([parse_uri("socks5://a:b@127.0.0.1:1080#Alpha")], "group A")
    service.store.add_nodes([parse_uri("socks5://a:b@127.0.0.1:1081#Beta")], "group B")


def test_health_discloses_no_secrets(service):
    status, headers, body = request(service, "/health")
    assert status == 200
    assert json.loads(body)["status"] == "running"
    assert service.store.settings()["token"].encode() not in body
    assert headers["Cache-Control"] == "no-store"
    assert "Access-Control-Allow-Origin" not in headers


def test_complete_clash_subscription(service):
    add_nodes(service)
    status, headers, body = request(service, target(service))
    assert status == 200
    data = yaml.safe_load(body)
    assert len(data["proxies"]) == 2
    assert data["allow-lan"] is False
    assert data["rules"][-1] == "MATCH,PROXY"
    assert len(data["rules"]) == len(service.store.list_rules()) + 1
    assert "GEOSITE,category-ads-all,REJECT" in data["rules"]
    assert len(data["proxy-groups"]) == 2


def test_user_rules_flow_into_the_clash_subscription(service):
    add_nodes(service)
    created = service.store.add_rule(
        {"type": "DOMAIN-SUFFIX", "value": "example.com", "action": "DIRECT"}
    )
    service.store.update_rule(created["id"], enabled=False)
    rules = yaml.safe_load(request(service, target(service))[2])["rules"]
    assert "DOMAIN-SUFFIX,example.com,DIRECT" not in rules
    service.store.update_rule(created["id"], enabled=True)
    rules = yaml.safe_load(request(service, target(service))[2])["rules"]
    assert rules[-2:] == ["DOMAIN-SUFFIX,example.com,DIRECT", "MATCH,PROXY"]


def test_v2ray_subscription_and_names(service):
    add_nodes(service)
    status, _, body = request(service, target(service, "v2ray"))
    assert status == 200
    uris = base64.b64decode(body).decode("utf-8").splitlines()
    assert len(uris) == 2
    assert all(uri.startswith("socks://") for uri in uris)
    assert {parse_uri(uri)["name"] for uri in uris} == {"Alpha", "Beta"}


def test_sing_box_subscription(service):
    add_nodes(service)
    status, headers, body = request(service, target(service, "singbox"))
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    data = json.loads(body)
    assert data["route"]["final"] == "PROXY"
    assert len([entry for entry in data["outbounds"] if entry["type"] == "socks"]) == 2
    assert [entry["tag"] for entry in data["outbounds"]][-3:] == ["PROXY", "AUTO", "DIRECT"]
    tags = {entry["tag"] for entry in data["outbounds"]}
    assert {"Alpha", "Beta"} <= tags


def test_disabled_and_group_filtering(service):
    add_nodes(service)
    beta = next(node for node in service.store.list_nodes() if node["name"] == "Beta")
    service.store.update_node(beta["id"], enabled=False)
    status, _, body = request(service, target(service))
    assert status == 200
    assert len(yaml.safe_load(body)["proxies"]) == 1
    status, _, _ = request(service, target(service, group="group B"))
    assert status == 409
    status, _, body = request(service, target(service, group="group A"))
    assert status == 200
    assert yaml.safe_load(body)["proxies"][0]["name"] == "Alpha"


def test_utf8_group_filter(service):
    service.store.add_nodes([parse_uri("socks5://127.0.0.1:1080#Local")], "\u672c\u5730")
    status, _, body = request(service, target(service, group="\u672c\u5730"))
    assert status == 200
    assert len(yaml.safe_load(body)["proxies"]) == 1


def test_empty_subscription_is_not_a_broken_profile(service):
    assert request(service, target(service))[0] == 409


@pytest.mark.parametrize("path", ["/", "/nodes.sqlite3", "/../nodes.sqlite3", "/sub/invalid/clash.yaml", "/api/nodes"])
def test_unknown_paths_are_closed(service, path):
    status, _, body = request(service, path)
    assert status == 404
    assert body == b"Not found."


def test_rebinding_and_browser_requests_are_rejected(service):
    add_nodes(service)
    assert request(service, target(service), headers={"Host": "evil.example"})[0] == 403
    assert request(service, target(service), headers={"Origin": "https://evil.example"})[0] == 403


def test_service_has_no_management_write_api(service):
    add_nodes(service)
    assert request(service, target(service), method="POST")[0] == 405
    assert len(service.store.list_nodes()) == 2


def test_token_rotation_invalidates_old_links(service):
    add_nodes(service)
    old = target(service)
    service.store.rotate_token()
    assert request(service, old)[0] == 404
    assert request(service, target(service))[0] == 200


def test_filter_rejects_unknown_and_duplicate_keys(service):
    add_nodes(service)
    assert request(service, target(service) + "?node=all")[0] == 400
    assert request(service, target(service) + "?group=x&group=y")[0] == 400


def test_head_has_headers_but_no_body(service):
    add_nodes(service)
    status, headers, body = request(service, target(service), "HEAD")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_pause_releases_listener_and_restarts_with_same_url(service):
    add_nodes(service)
    port = service.port
    service.store.update_settings({"port": port})
    url = service.url("clash")
    service.stop()
    assert not service.running
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.3)
    service.start()
    assert service.url("clash") == url
    assert request(service, target(service))[0] == 200


def test_collision_does_not_replace_existing_service(service, tmp_path):
    other_store = Store(tmp_path / "other", protected=False)
    other = SubscriptionService(other_store)
    try:
        with pytest.raises(OSError):
            other.start(service.port)
        assert not other.running
        assert request(service, "/health")[0] == 200
    finally:
        other.stop()
        other_store.close()
