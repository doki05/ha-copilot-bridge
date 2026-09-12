#!/usr/bin/env python3
"""Single-owner Home Assistant MCP bridge.

This module deliberately uses Python's standard library only. It implements the
small HTTP/OAuth/MCP surface that is required by a remote ChatGPT connection and
keeps all Home Assistant access inside the add-on through the Supervisor proxy.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DATA_DIR = Path(os.environ.get("HA_COPILOT_DATA_DIR", "/data"))
OPTIONS_PATH = DATA_DIR / "options.json"
STATE_PATH = DATA_DIR / "bridge_state.json"
HA_API = "http://supervisor/core/api"
SESSION_TTL = 8 * 60 * 60
AUTH_CODE_TTL = 180
PREPARED_TTL = 30 * 60


def now() -> int:
    return int(time.time())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class BridgeState:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {
            "clients": {}, "codes": {}, "tokens": {}, "sessions": {}, "prepared": {}
        }
        if STATE_PATH.exists():
            try:
                self.data.update(json.loads(STATE_PATH.read_text()))
            except (OSError, json.JSONDecodeError):
                pass
        self.prune()

    def save(self) -> None:
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, separators=(",", ":")))
        tmp.replace(STATE_PATH)

    def prune(self) -> None:
        with self.lock:
            current = now()
            for key in ("codes", "tokens", "sessions", "prepared"):
                self.data[key] = {
                    item_id: item
                    for item_id, item in self.data[key].items()
                    if item.get("expires_at", current + 1) > current
                }
            self.save()


STATE = BridgeState()


def options() -> dict[str, Any]:
    return json.loads(OPTIONS_PATH.read_text())


def owner_password_is_valid(candidate: str) -> bool:
    configured = str(options().get("owner_password", ""))
    return bool(configured) and secrets.compare_digest(candidate, configured)


def base_url(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-Proto", "https")
    host = handler.headers.get("Host", "")
    return f"{forwarded}://{host}".rstrip("/")


def protected_resource_metadata_url(handler: BaseHTTPRequestHandler) -> str:
    """Return the endpoint-specific RFC 9728 metadata URL for /mcp."""
    return base_url(handler) + "/.well-known/oauth-protected-resource/mcp"


def ha_request(path: str, method: str = "GET", body: Any | None = None) -> Any:
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise RuntimeError("Supervisor token is unavailable")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json_bytes(body)
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(HA_API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            payload = response.read()
            return json.loads(payload) if payload else {"ok": True}
    except urllib.error.HTTPError as exc:
        details = exc.read().decode(errors="replace")
        raise RuntimeError(f"Home Assistant API {exc.code}: {details[:500]}") from exc


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "ha_system_inventory",
            "description": "Read-only summary of this Home Assistant instance: version, configured components, entity counts by domain, and service domains.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "ha_get_states",
            "description": "Read current entity states. Use entity_ids for an exact request or domain for a domain-level overview. Results are limited to 250 entities.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_ids": {"type": "array", "items": {"type": "string"}},
                    "domain": {"type": "string"},
                    "include_attributes": {"type": "boolean", "default": false},
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "ha_list_automations",
            "description": "Read-only list of Home Assistant automation entities and their enabled state and last trigger time.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "ha_list_services",
            "description": "Read-only list of available Home Assistant services, optionally limited to one domain.",
            "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}},
        },
        {
            "name": "ha_entity_history",
            "description": "Read recent state history for exactly one entity. Start is ISO 8601; if omitted, the last 24 hours are returned.",
            "inputSchema": {
                "type": "object",
                "required": ["entity_id"],
                "properties": {"entity_id": {"type": "string"}, "start": {"type": "string"}},
                "additionalProperties": false,
            },
        },
        {
            "name": "ha_prepare_service_call",
            "description": "Does not execute anything. Stages a Home Assistant service call for owner review in the add-on page. Physical or security-related changes must always be staged, never improvised.",
            "inputSchema": {
                "type": "object",
                "required": ["domain", "service", "reason"],
                "properties": {
                    "domain": {"type": "string"},
                    "service": {"type": "string"},
                    "entity_id": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                    "service_data": {"type": "object"},
                    "reason": {"type": "string", "minLength": 5},
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "ha_apply_approved_service_call",
            "description": "Executes only a previously prepared service call that the owner has separately approved in the HA Copilot Bridge add-on page. Never call this without the user explicitly confirming that the add-on approval was completed.",
            "inputSchema": {
                "type": "object",
                "required": ["change_id"],
                "properties": {"change_id": {"type": "string"}},
                "additionalProperties": false,
            },
        },
    ]


def tool_result(value: Any, is_error: bool = False) -> dict[str, Any]:
    text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def run_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_system_inventory":
        config = ha_request("/config")
        states = ha_request("/states")
        services = ha_request("/services")
        domains = Counter(item["entity_id"].split(".", 1)[0] for item in states if "." in item.get("entity_id", ""))
        return tool_result({
            "config": {key: config.get(key) for key in ("version", "location_name", "time_zone", "unit_system", "components")},
            "entity_counts_by_domain": dict(sorted(domains.items())),
            "service_domains": sorted(item.get("domain") for item in services),
        })

    if name == "ha_get_states":
        states = ha_request("/states")
        entity_ids = arguments.get("entity_ids")
        domain = arguments.get("domain")
        if entity_ids:
            wanted = set(entity_ids)
            states = [item for item in states if item.get("entity_id") in wanted]
        elif domain:
            states = [item for item in states if item.get("entity_id", "").startswith(domain + ".")]
        selected = []
        for item in states[:250]:
            result = {key: item.get(key) for key in ("entity_id", "state", "last_changed", "last_updated")}
            if arguments.get("include_attributes"):
                result["attributes"] = item.get("attributes", {})
            else:
                result["name"] = item.get("attributes", {}).get("friendly_name")
            selected.append(result)
        return tool_result({"count": len(selected), "truncated": len(states) > 250, "states": selected})

    if name == "ha_list_automations":
        states = ha_request("/states")
        automations = []
        for item in states:
            if item.get("entity_id", "").startswith("automation."):
                attributes = item.get("attributes", {})
                automations.append({
                    "entity_id": item["entity_id"], "state": item.get("state"),
                    "name": attributes.get("friendly_name"),
                    "last_triggered": attributes.get("last_triggered"),
                    "mode": attributes.get("mode"),
                })
        return tool_result({"count": len(automations), "automations": automations})

    if name == "ha_list_services":
        services = ha_request("/services")
        domain = arguments.get("domain")
        if domain:
            services = [item for item in services if item.get("domain") == domain]
        return tool_result(services)

    if name == "ha_entity_history":
        entity_id = arguments["entity_id"]
        start = arguments.get("start") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now() - 86400))
        encoded_start = urllib.parse.quote(start, safe=":TZ-.")
        encoded_entity = urllib.parse.quote(entity_id, safe="._-")
        history = ha_request(f"/history/period/{encoded_start}?filter_entity_id={encoded_entity}&minimal_response")
        return tool_result({"entity_id": entity_id, "start": start, "history": history})

    if name == "ha_prepare_service_call":
        services = ha_request("/services")
        exists = any(item.get("domain") == arguments["domain"] and arguments["service"] in item.get("services", {}) for item in services)
        if not exists:
            return tool_result({"error": "Unknown Home Assistant service; no change was staged."}, True)
        change_id = "chg_" + secrets.token_urlsafe(12)
        payload = dict(arguments.get("service_data") or {})
        if "entity_id" in arguments:
            payload["entity_id"] = arguments["entity_id"]
        with STATE.lock:
            STATE.data["prepared"][change_id] = {
                "change_id": change_id,
                "domain": arguments["domain"],
                "service": arguments["service"],
                "payload": payload,
                "reason": arguments["reason"],
                "created_at": now(),
                "expires_at": now() + PREPARED_TTL,
                "approved": False,
                "executed": False,
            }
            STATE.save()
        return tool_result({
            "change_id": change_id,
            "status": "prepared_not_approved",
            "expires_in_minutes": PREPARED_TTL // 60,
            "next_step": "The owner must review and approve this exact change in the HA Copilot Bridge add-on page inside Home Assistant. The MCP client cannot approve it.",
            "change": {"domain": arguments["domain"], "service": arguments["service"], "payload": payload, "reason": arguments["reason"]},
        })

    if name == "ha_apply_approved_service_call":
        change_id = arguments["change_id"]
        with STATE.lock:
            change = STATE.data["prepared"].get(change_id)
            if not change:
                return tool_result({"error": "Unknown or expired change ID."}, True)
            if change.get("executed"):
                return tool_result({"error": "This change has already been executed."}, True)
            if not options().get("enable_service_execution", False):
                return tool_result({"error": "Service execution is disabled in the add-on configuration."}, True)
            if not change.get("approved"):
                return tool_result({"error": "The owner has not approved this change in Home Assistant."}, True)
            change["executed"] = True
            STATE.save()
        try:
            response = ha_request(f"/services/{change['domain']}/{change['service']}", "POST", change["payload"])
            return tool_result({"change_id": change_id, "status": "executed", "result": response})
        except Exception as exc:
            with STATE.lock:
                change["executed"] = False
                STATE.save()
            return tool_result({"change_id": change_id, "error": str(exc)}, True)

    return tool_result({"error": f"Unknown tool: {name}"}, True)


def render_authorize_form(query: dict[str, list[str]], error: str = "") -> bytes:
    values = {key: value[0] for key, value in query.items()}
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in values.items()
    )
    error_html = f"<p class=error>{html.escape(error)}</p>" if error else ""
    page = f"""<!doctype html><html><head><meta charset=utf-8><title>HA Copilot Bridge</title>
    <style>body{{font-family:system-ui;max-width:38rem;margin:4rem auto;padding:1rem}}input{{width:100%;padding:.7rem;margin:.5rem 0}}button{{padding:.7rem 1rem}}.error{{color:#b00020}}</style>
    </head><body><h1>HA Copilot Bridge</h1><p>Authorize this ChatGPT connection to use the private Home Assistant bridge.</p>{error_html}
    <form method=post action=/auth/authorize>{hidden}<label>Bridge owner password<input type=password name=password autocomplete=current-password required autofocus></label><button type=submit>Authorize</button></form>
    </body></html>"""
    return page.encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "HACopilotBridge/0.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        # Requests can contain authorization codes. Do not write request URLs to logs.
        return

    def send_json(self, value: Any, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        payload = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        for key, item in (extra_headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(payload)

    def read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        return urllib.parse.parse_qs(raw, keep_blank_values=True)

    def query(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def require_token(self) -> bool:
        challenge = {
            "WWW-Authenticate": (
                'Bearer resource_metadata="'
                + protected_resource_metadata_url(self)
                + '", scope="mcp:read"'
            )
        }
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self.send_json({"error": "unauthorized"}, 401, challenge)
            return False
        token = header[7:]
        with STATE.lock:
            valid = token in STATE.data["tokens"] and STATE.data["tokens"][token].get("expires_at", 0) > now()
        if not valid:
            self.send_json({"error": "invalid_token"}, 401, challenge)
            return False
        return True

    def do_GET(self) -> None:
        path, query = self.query()
        base = base_url(self)
        if path in ("/health", "/"):
            self.send_json({"status": "ok", "service": "ha-copilot-bridge"})
        elif path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server/mcp"):
            self.send_json({
                "issuer": base,
                "authorization_endpoint": base + "/auth/authorize",
                "token_endpoint": base + "/auth/token",
                "registration_endpoint": base + "/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["mcp:read", "mcp:prepare", "mcp:apply"],
                "authorization_response_iss_parameter_supported": True,
            })
        elif path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            self.send_json({
                "resource": base + "/mcp",
                "authorization_servers": [base],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["mcp:read", "mcp:prepare", "mcp:apply"],
            })
        elif path == "/mcp":
            # ChatGPT probes the configured MCP endpoint with GET before it
            # starts the OAuth flow. A 401 OAuth challenge (not a 404) is
            # therefore required for protected-resource discovery.
            if not self.require_token():
                return
            self.send_json({"error": "method_not_allowed"}, 405)
        elif path == "/auth/authorize":
            content = render_authorize_form(query)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif path == "/admin":
            if not getattr(self.server, "allow_admin", False):
                self.send_json({"error": "not_found"}, 404)
                return
            if not self.headers.get("X-Remote-User-Id"):
                self.send_json({"error": "The approval page is available only through Home Assistant ingress."}, 403)
                return
            with STATE.lock:
                changes = [item for item in STATE.data["prepared"].values() if not item.get("executed")]
            rows = "".join(
                "<li><pre>" + html.escape(json.dumps(item, ensure_ascii=False, indent=2)) + "</pre>"
                + (f'<form method=post action="/admin/approve/{html.escape(item["change_id"])}"><button>Approve this exact change</button></form>' if not item.get("approved") else "<strong>Approved</strong>")
                + "</li>" for item in changes
            ) or "<p>No pending changes.</p>"
            content = f"<!doctype html><html><head><meta charset=utf-8><title>HA Copilot Bridge approvals</title></head><body><h1>Pending changes</h1>{rows}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_json({"error": "not_found"}, 404)

    def do_POST(self) -> None:
        path, query = self.query()
        if path == "/oauth/register":
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                redirects = payload.get("redirect_uris", [])
                def supported_redirect(uri: Any) -> bool:
                    if not isinstance(uri, str):
                        return False
                    parsed = urllib.parse.urlparse(uri)
                    return (
                        (parsed.scheme == "https" and parsed.hostname == "chatgpt.com") or
                        (parsed.scheme == "http" and parsed.hostname == "127.0.0.1")
                    )

                if not isinstance(redirects, list) or not redirects or not all(supported_redirect(item) for item in redirects):
                    raise ValueError("redirect_uris is required")
                client_id = "client_" + secrets.token_urlsafe(18)
                with STATE.lock:
                    STATE.data["clients"][client_id] = {"redirect_uris": redirects, "created_at": now()}
                    STATE.save()
                self.send_json({
                    "client_id": client_id,
                    "client_id_issued_at": now(),
                    "token_endpoint_auth_method": "none",
                    "redirect_uris": redirects,
                }, 201)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                self.send_json({"error": "invalid_client_metadata"}, 400)
            return

        if path == "/auth/authorize":
            form = self.read_form()
            values = {key: value[0] for key, value in form.items()}
            client_id = values.get("client_id", "")
            redirect_uri = values.get("redirect_uri", "")
            with STATE.lock:
                client = STATE.data["clients"].get(client_id)
            invalid = (
                not client or redirect_uri not in client.get("redirect_uris", []) or
                values.get("response_type") != "code" or values.get("code_challenge_method") != "S256" or
                not values.get("code_challenge")
            )
            if invalid or not owner_password_is_valid(values.get("password", "")):
                content = render_authorize_form({key: value for key, value in form.items() if key != "password"}, "Invalid authorization request or owner password.")
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            code = "code_" + secrets.token_urlsafe(24)
            with STATE.lock:
                STATE.data["codes"][code] = {
                    "client_id": client_id, "redirect_uri": redirect_uri,
                    "code_challenge": values["code_challenge"], "scope": values.get("scope", "mcp:read"),
                    "expires_at": now() + AUTH_CODE_TTL,
                }
                STATE.save()
            destination = urllib.parse.urlparse(redirect_uri)
            params = urllib.parse.parse_qsl(destination.query, keep_blank_values=True)
            params.extend([("code", code), ("iss", base_url(self))])
            if values.get("state"):
                params.append(("state", values["state"]))
            location = urllib.parse.urlunparse(destination._replace(query=urllib.parse.urlencode(params)))
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        if path == "/auth/token":
            form = self.read_form()
            values = {key: value[0] for key, value in form.items()}
            code = values.get("code", "")
            with STATE.lock:
                record = STATE.data["codes"].pop(code, None)
                STATE.save()
            verifier = values.get("code_verifier", "")
            challenge = b64url(hashlib.sha256(verifier.encode()).digest())
            valid = (
                values.get("grant_type") == "authorization_code" and record and
                record.get("expires_at", 0) > now() and record.get("client_id") == values.get("client_id") and
                record.get("redirect_uri") == values.get("redirect_uri") and
                secrets.compare_digest(record.get("code_challenge", ""), challenge)
            )
            if not valid:
                self.send_json({"error": "invalid_grant"}, 400)
                return
            token = "atk_" + secrets.token_urlsafe(32)
            refresh = "rtk_" + secrets.token_urlsafe(32)
            with STATE.lock:
                STATE.data["tokens"][token] = {"client_id": record["client_id"], "scope": record["scope"], "expires_at": now() + SESSION_TTL, "refresh_token": refresh}
                STATE.save()
            self.send_json({"access_token": token, "token_type": "Bearer", "expires_in": SESSION_TTL, "refresh_token": refresh, "scope": record["scope"]})
            return

        if path.startswith("/admin/approve/"):
            if not getattr(self.server, "allow_admin", False):
                self.send_json({"error": "not_found"}, 404)
                return
            if not self.headers.get("X-Remote-User-Id"):
                self.send_json({"error": "Home Assistant ingress is required."}, 403)
                return
            change_id = path.rsplit("/", 1)[-1]
            with STATE.lock:
                change = STATE.data["prepared"].get(change_id)
                if not change:
                    self.send_json({"error": "Unknown or expired change."}, 404)
                    return
                change["approved"] = True
                change["approved_at"] = now()
                change["approved_by_ha_user"] = self.headers.get("X-Remote-User-Id")
                STATE.save()
            self.send_response(303)
            self.send_header("Location", "/admin")
            self.end_headers()
            return

        if path == "/mcp":
            if not self.require_token():
                return
            try:
                request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                method = request.get("method")
                request_id = request.get("id")
                if method == "initialize":
                    protocol = request.get("params", {}).get("protocolVersion", "2025-03-26")
                    session_id = "mcp_" + secrets.token_urlsafe(18)
                    with STATE.lock:
                        STATE.data["sessions"][session_id] = {"expires_at": now() + SESSION_TTL}
                        STATE.save()
                    self.send_json({"jsonrpc": "2.0", "id": request_id, "result": {
                        "protocolVersion": protocol,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "ha-copilot-bridge", "version": "0.1.0"},
                        "instructions": "Use read-only tools for diagnosis. Stage a service call first. The owner must approve the exact staged change in Home Assistant before it can be executed.",
                    }}, extra_headers={"Mcp-Session-Id": session_id, "MCP-Protocol-Version": protocol})
                elif method == "notifications/initialized":
                    self.send_response(202)
                    self.end_headers()
                elif method == "ping":
                    self.send_json({"jsonrpc": "2.0", "id": request_id, "result": {}})
                elif method == "tools/list":
                    self.send_json({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tool_definitions()}})
                elif method == "tools/call":
                    params = request.get("params", {})
                    result = run_tool(params.get("name", ""), params.get("arguments") or {})
                    self.send_json({"jsonrpc": "2.0", "id": request_id, "result": result})
                else:
                    self.send_json({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}})
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.send_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}, 400)
            except Exception as exc:
                self.send_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}, 500)
            return

        self.send_json({"error": "not_found"}, 404)


def main() -> None:
    public_server = ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    public_server.allow_admin = False
    admin_server = ThreadingHTTPServer(("0.0.0.0", 8091), Handler)
    admin_server.allow_admin = True
    threading.Thread(target=admin_server.serve_forever, daemon=True).start()
    public_server.serve_forever()


if __name__ == "__main__":
    main()
