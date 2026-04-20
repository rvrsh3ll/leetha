# Notifications

Leetha can send alert notifications when security findings are detected. Notifications are powered by [Apprise](https://github.com/caronc/apprise), supporting 80+ notification services including Slack, Discord, email, webhooks, Telegram, and more.

## Configuration

Set notification URLs in the web UI settings page or via the config file at `~/.leetha/config.json`:

```json
{
  "notification_urls": [
    "slack://tokenA/tokenB/tokenC",
    "discord://webhook_id/webhook_token",
    "mailto://user:pass@gmail.com"
  ],
  "notification_min_severity": "warning"
}
```

## Severity Levels

| Level | Description | Example Findings |
|-------|-------------|-----------------|
| `info` | Informational | New device discovered |
| `low` | Low priority | Low certainty identification |
| `warning` | Attention needed | Platform drift, stale fingerprint source |
| `high` | Action required | MAC spoofing detected, identity shift |
| `critical` | Immediate action | Address conflict, infrastructure offline |

Set `notification_min_severity` to control the minimum severity that triggers a notification. Default is `warning`.

## Rate Limiting

Notifications are rate-limited to prevent flooding:
- One notification per rule+MAC combination per 5-minute window
- Duplicate findings within the cooldown are suppressed

## Supported Services

Any [Apprise-supported URL](https://github.com/caronc/apprise/wiki) works. Common examples:

| Service | URL Format |
|---------|------------|
| Slack | `slack://tokenA/tokenB/tokenC` |
| Discord | `discord://webhook_id/webhook_token` |
| Email | `mailto://user:pass@gmail.com` |
| Telegram | `tgram://bot_token/chat_id` |
| Webhook | `json://hostname/path` |
| Gotify | `gotify://hostname/token` |
| Ntfy | `ntfy://topic` |
| PushOver | `pover://user_key/token` |
