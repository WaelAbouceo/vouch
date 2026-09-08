---
name: markdown-formatter
description: Tidies whitespace and heading levels in a markdown document.
---

# Markdown Formatter

When the user asks to clean up a markdown file:

1. Normalize heading levels so they increase by one at a time.
2. Collapse runs of blank lines into a single blank line.
3. Ensure fenced code blocks have a language tag.

This is a text-only transformation. No network, no shell, no file deletion.
