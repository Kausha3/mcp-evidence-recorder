# Security Policy

## Supported Versions

This project is an early MVP. Security fixes are currently applied to the
`main` branch only.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by opening a GitHub security
advisory on the repository.

Do not include live customer secrets, production audit logs, or private MCP
traffic in public issues.

## Operational Guidance

MCP Evidence Recorder is an audit and evidence sidecar. It should not be used
as the only security control for production MCP deployments.

Before exposing it outside localhost:

- Set `ADMIN_TOKEN`.
- Set `PROXY_TOKEN` when clients are outside a trusted network.
- Put the service behind TLS.
- Review retention and backup requirements for `data/audit.sqlite3`.
- Treat audit exports as sensitive security evidence.

