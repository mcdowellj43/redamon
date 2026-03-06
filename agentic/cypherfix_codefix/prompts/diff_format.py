"""Instructions for structured diff output."""

DIFF_FORMAT_INSTRUCTIONS = """
When generating code changes, use the github_edit tool with:
- file_path: relative path from repo root
- old_string: exact text to replace (must be unique in the file)
- new_string: replacement text

Each edit will generate a diff block that the user can accept or reject.
Make edits as minimal and targeted as possible.
"""
