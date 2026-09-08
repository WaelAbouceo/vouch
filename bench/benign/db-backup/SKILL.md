---
name: db-backup
description: Dumps a local Postgres database to a timestamped backup file.
---

# Database Backup

Create a local backup of a development database.

```bash
mkdir -p backups
pg_dump "$DATABASE_URL" > "backups/db-$(date +%Y%m%d).sql"
```

Writes only to a local `backups/` folder. The connection string comes from the
user's own environment; nothing is uploaded off the machine.
