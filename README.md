# HA Copilot Bridge

Private Home Assistant add-on that exposes a narrowly scoped MCP endpoint for the
`HA Copilot` ChatGPT Workspace Agent.

The add-on is intentionally built in phases:

- read-only Home Assistant inventory, states, services, automations, and history;
- preparation of a Home Assistant service call;
- execution only after a separate approval in the add-on's Home Assistant ingress
  page.

It does not expose the Home Assistant configuration directory and it does not
modify YAML, automations, or scripts in version 0.1.0.

The source code is public so that Home Assistant can install the repository
without storing GitHub credentials. Credentials and instance-specific settings
are entered only in the add-on configuration and are never committed here.

## Security model

The public MCP endpoint is protected by an OAuth 2.1 authorization-code flow
with PKCE S256 and dynamic client registration. The only bridge-owner password
is entered in the add-on configuration. It is needed once during the ChatGPT
connection approval and is not returned by any MCP tool.

Service calls are staged first. A staged operation cannot be executed until the
owner approves it in the add-on page opened from Home Assistant. The MCP client
cannot grant that approval.

## Status

This repository is an experimental, single-owner integration. Do not use it for
safety-critical actions. Heat, locks, gates, watering, and other physical
equipment remain disabled by default because service execution is off until the
owner enables it deliberately in the add-on configuration.
