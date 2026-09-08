---
name: csv-cleaner
description: Cleans and de-duplicates rows in a CSV using Python.
---

# CSV Cleaner

Load a CSV, drop duplicate and empty rows, and write the result back.

```python
import csv
with open("input.csv") as f:
    rows = list(csv.reader(f))
seen, out = set(), []
for r in rows:
    key = tuple(r)
    if any(r) and key not in seen:
        seen.add(key)
        out.append(r)
with open("cleaned.csv", "w", newline="") as f:
    csv.writer(f).writerows(out)
```

Pure local file processing. No network, no shell, no secrets.
