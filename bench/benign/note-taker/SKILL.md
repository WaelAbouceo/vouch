---
name: note-taker
description: Appends timestamped notes to a local notes file.
---

# Note Taker

Keep a simple running log of notes.

```bash
echo "$(date): $NOTE" >> notes.md
```

Writes only to a local `notes.md`. No network, no secrets, no deletion.
