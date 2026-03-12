#!/usr/bin/env python3
"""Check internal links and anchors in the built MkDocs site.

Validates:
  - All internal href links resolve to existing files
  - All anchor (#fragment) links resolve to existing id attributes
  - All images reference existing files

Run via: uv run scripts/check-docs-links.py [site_dir]
Exit code 0 if all links valid, 1 if broken links found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

SITE_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("site")

# Regex to extract href/src attributes from HTML
LINK_RE = re.compile(r'(?:href|src)="([^"]*)"')

# Regex to extract id attributes from HTML
ID_RE = re.compile(r'id="([^"]*)"')


def _collect_ids(html: str) -> set[str]:
    """Extract all id attributes from an HTML file."""
    return set(ID_RE.findall(html))


def _check_file(path: Path, all_files: set[Path]) -> list[str]:
    """Check all links in a single HTML file."""
    errors: list[str] = []
    html = path.read_text(errors="replace")
    ids = _collect_ids(html)
    rel_path = path.relative_to(SITE_DIR)

    for match in LINK_RE.finditer(html):
        href = match.group(1)

        # Skip external links, mailto, javascript, data URIs, empty
        if not href or href.startswith(("http://", "https://", "mailto:", "javascript:", "data:", "#__", "//")):
            continue

        parsed = urlparse(href)

        # Pure fragment link — check anchor in same file
        if href.startswith("#"):
            fragment = unquote(parsed.fragment)
            if fragment and fragment not in ids:
                errors.append(f"  {rel_path}: broken anchor #{fragment}")
            continue

        # Resolve the target file
        target_path = parsed.path
        if not target_path:
            continue

        # Make absolute relative to site dir
        if target_path.startswith("/"):
            resolved = SITE_DIR / target_path.lstrip("/")
        else:
            resolved = (path.parent / target_path).resolve()

        # If it's a directory, check for index.html
        if resolved.is_dir():
            resolved = resolved / "index.html"

        # Normalize
        try:
            resolved = resolved.resolve()
        except OSError:
            errors.append(f"  {rel_path}: unresolvable path {href}")
            continue

        if resolved not in all_files and not resolved.is_file():
            errors.append(f"  {rel_path}: broken link {href}")
            continue

        # Check fragment if present
        if parsed.fragment and resolved.is_file() and resolved.suffix == ".html":
            target_html = resolved.read_text(errors="replace")
            target_ids = _collect_ids(target_html)
            fragment = unquote(parsed.fragment)
            if fragment not in target_ids:
                errors.append(f"  {rel_path}: broken anchor {href}")

    return errors


def main() -> int:
    if not SITE_DIR.is_dir():
        print(f"Site directory not found: {SITE_DIR}")
        print("Run 'mkdocs build' first.")
        return 1

    html_files = [f for f in SITE_DIR.rglob("*.html") if f.name != "404.html"]
    all_files = {f.resolve() for f in SITE_DIR.rglob("*") if f.is_file()}

    print(f"Checking {len(html_files)} HTML files in {SITE_DIR}/")

    all_errors: list[str] = []
    for html_file in sorted(html_files):
        errors = _check_file(html_file, all_files)
        all_errors.extend(errors)

    if all_errors:
        print(f"\nFound {len(all_errors)} broken link(s):")
        for error in all_errors:
            print(error)
        return 1

    print("All links OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
