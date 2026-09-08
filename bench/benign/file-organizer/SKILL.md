---
name: file-organizer
description: Organizes files in a folder into subfolders by type.
---

# File Organizer

Sort a messy download folder into `images/`, `docs/`, and `archives/`.

```bash
mkdir -p images docs archives
mv *.png *.jpg images/ 2>/dev/null || true
mv *.pdf *.docx docs/ 2>/dev/null || true
mv *.zip *.tar.gz archives/ 2>/dev/null || true
```

Only touches the current working directory. Ask the user before moving anything.
