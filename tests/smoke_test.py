#!/usr/bin/env python3
"""Minimal offline smoke test for OAuth PKCE and MCP initialization."""

import hashlib
import http.client
import importlib.util
import json
import os
import threading
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


ROOT = Path(__file__).resolve().parents[1]
TEMPORARY_DATA = tempfile.TemporaryDirectory()
DATA = Path(TEMPORARY_DATA.name)
(DATA / "options.json").write_text(json.dumps({
    "owner_password": "correct-horse-battery-staple",
    "enable_service_execution": False,
}))
os.environ["HA_COPILOT_DATA_DIR"] = str(DATA)

spec = importlib.util.spec_from_file_location("bridge", ROOT / "ha_copilot_bridge/app/server.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

server = bridge.ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
server.allow_admin = False
threading.Thread(target=server.serve_forever, daemon=True).start()
port = server.server_port


def request(method, path, payload=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port)
    body = None if payload is None else payload.encode()
    request_headers = {"Host": "bridge.test"}
    request_headers.update(headers or {})
    if body is not None:
        request_headers["Content-Length"] = str(len(body))
    connection.request(method, path, body, request_headers)
    response = connection.getresponse()
    content = response.read()
    result = response.status, dict(response.getheaders()), content
    connection.close()
    return result


try:
    status, _, content = request("GET", "/.well-known/oauth-authorization-server")
    metadata = json.loads(content)
    assert status == 200 and metadata["code_challenge_methods_supported"] == ["S256"]

    redirect_uri = "https://chatgpt.com/connector/oauth/test"
    registration = json.dumps({"redirect_uris": [redirect_uri]})
    status, _, content = request("POST", "/oauth/register", registration, {"Content-Type": "application/json"})
    client_id = json.loads(content)["client_id"]
    verifier = "A" * 64
    challenge = bridge.b64url(hashlib.sha256(verifier.encode()).digest())
    authorize = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": "state-value",
        "code_challenge_method": "S256",
        "code_challenge": challenge,
        "password": "correct-horse-battery-staple",
    })
    status, headers, _ = request("POST", "/auth/authorize", authorize, {"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 302
    callback = parse_qs(urlparse(headers["Location"]).query)
    token_request = urlencode({
        "grant_type": "authorization_code",
        "code": callback["code"][0],
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    })
    status, _, content = request("POST", "/auth/token", token_request, {"Content-Type": "application/x-www-form-urlencoded"})
    access_token = json.loads(content)["access_token"]
    initialize = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
    status, headers, content = request("POST", "/mcp", initialize, {"Content-Type": "application/json", "Authorization": f"Bearer {access_token}"})
    response = json.loads(content)
    assert status == 200 and headers["Mcp-Session-Id"] and response["result"]["serverInfo"]["name"] == "ha-copilot-bridge"
    status, _, _ = request("GET", "/admin", headers={"X-Remote-User-Id": "forged"})
    assert status == 404
    print("smoke test passed")
finally:
    server.shutdown()
    TEMPORARY_DATA.cleanup()
