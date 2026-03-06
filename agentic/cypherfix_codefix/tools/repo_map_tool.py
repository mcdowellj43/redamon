"""RepoMap tool: tree-sitter + PageRank codebase overview."""

import logging
from collections import defaultdict
from .symbols_tool import EXT_TO_LANG, _get_parser, _walk_definitions

logger = logging.getLogger(__name__)

SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '__pycache__', '.tox', 'venv', '.venv',
    'dist', 'build', '.next', '.cache', 'coverage',
}
MAX_FILE_SIZE = 100 * 1024  # 100KB


async def github_repo_map(state, max_tokens: int = 2000, focus_paths: list = None) -> str:
    """Generate a ranked codebase overview."""
    base = state.repo_path
    file_symbols = {}

    # Collect files to index
    if focus_paths:
        source_files = []
        for fp in focus_paths:
            target = base / fp
            if target.is_dir():
                for ext in EXT_TO_LANG:
                    source_files.extend(target.rglob(f"*{ext}"))
            elif target.is_file():
                source_files.append(target)
    else:
        source_files = []
        for ext in EXT_TO_LANG:
            for f in base.rglob(f"*{ext}"):
                if any(skip in f.parts for skip in SKIP_DIRS):
                    continue
                if f.stat().st_size > MAX_FILE_SIZE:
                    continue
                source_files.append(f)

    # Parse each file
    all_symbol_names = set()
    for file_path in source_files[:500]:
        ext = file_path.suffix
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            continue
        parser = _get_parser(lang)
        if not parser:
            continue

        try:
            content = file_path.read_bytes()
            tree = parser.parse(content)
            defs = _walk_definitions(tree.root_node, lang)
            rel = str(file_path.relative_to(base))
            file_symbols[rel] = defs
            for d in defs:
                all_symbol_names.add(d['name'])
        except Exception:
            continue

    # Count references for ranking
    ref_counts = defaultdict(int)
    for file_path in source_files[:500]:
        try:
            text = file_path.read_text(encoding='utf-8', errors='replace')
            for name in all_symbol_names:
                count = text.count(name)
                if count > 0:
                    ref_counts[name] += count
        except Exception:
            continue

    # Rank files by total reference count of their symbols
    file_scores = defaultdict(int)
    for rel, defs in file_symbols.items():
        for d in defs:
            file_scores[rel] += ref_counts.get(d['name'], 0)

    # Sort by score
    ranked_files = sorted(file_symbols.keys(), key=lambda f: file_scores[f], reverse=True)

    # Build output within token budget
    output_lines = ["Repository Map (ranked by importance):", ""]
    chars_used = 50
    chars_budget = max_tokens * 4  # ~4 chars per token

    for rel in ranked_files:
        defs = file_symbols[rel]
        if not defs:
            continue

        file_line = f"{rel}:"
        def_lines = []
        for d in defs:
            if d['depth'] == 0:
                def_lines.append(
                    f"  {d['kind']} {d['name']}  [{d['start_line']}-{d['end_line']}]"
                )

        section = file_line + '\n' + '\n'.join(def_lines) + '\n'
        if chars_used + len(section) > chars_budget:
            output_lines.append(f"\n[Map truncated at token budget ({max_tokens} tokens)]")
            break
        output_lines.append(section)
        chars_used += len(section)

    if not ranked_files:
        return "No source files found to map."

    return '\n'.join(output_lines)
