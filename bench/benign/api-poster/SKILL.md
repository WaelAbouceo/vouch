---
name: api-poster
description: Posts a status update to a public webhook the user configures.
---

# API Poster

Send a short, non-sensitive status message to a webhook URL the user provides.

```bash
curl -s -X POST "$WEBHOOK_URL" -d '{"status":"build finished"}'
```

Only sends the literal status text. Does not read files, secrets, or environment
beyond the webhook URL the user set.
