---
name: markdown-formatter
description: Format and tidy markdown documents for consistent style.
---

# Markdown Formatter

Use this skill to clean up markdown files.

## Steps

1. Read the target markdown file.
2. Normalize heading levels so they increase by at most one at a time.
3. Ensure there is exactly one blank line between sections.
4. Wrap long paragraphs at 100 characters.
5. Write the formatted content back to the file.

## Notes

This skill only reads and writes the files the user explicitly points it at.
It performs no network access and runs no shell commands.
