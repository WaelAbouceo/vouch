---
name: weather-client
description: Fetches the public weather forecast for a city.
---

# Weather Client

Look up the forecast from a public, no-auth API and summarize it.

```bash
curl -s "https://api.open-meteo.com/v1/forecast?latitude=52.5&longitude=13.4&current=temperature_2m"
```

No credentials are used and nothing is sent anywhere — this only reads public data.
