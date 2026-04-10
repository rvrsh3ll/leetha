# Authentication & API Security

Leetha includes token-based authentication for securing the web dashboard and REST API when exposed beyond localhost.

## When Auth Is Enabled

Authentication is **automatically enabled** when the web server binds to a non-localhost address (e.g., `0.0.0.0`). It is **disabled** when bound to `127.0.0.1` or `::1`.

You can override this with:
- `--auth` -- force authentication on
- `--no-auth` -- force authentication off

## Admin Token

On first startup, Leetha generates an admin token and saves it to `~/.leetha/admin-token`. View it with:

```bash
leetha auth show-token
```

## Token Management

```bash
# List all tokens
leetha auth list-tokens

# Create a new token with a specific role
leetha auth create-token --role analyst --label "readonly-user"

# Revoke a token
leetha auth revoke-token <token-id>
```

## Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access: settings, capture control, token management, delete alerts |
| `analyst` | Read access: devices, alerts, stats. Can acknowledge alerts. |

## API Authentication

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer ltk_..." http://host:8080/api/devices
```

## WebSocket Authentication

WebSocket connections pass the token as a subprotocol:

```javascript
new WebSocket("ws://host:8080/ws", ["auth.ltk_..."]);
```

## Exempt Paths

These paths do not require authentication:
- `/login` -- login page
- `/api/health` -- health check
- Static assets (`/assets/*`)
