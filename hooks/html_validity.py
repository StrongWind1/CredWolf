# SPDX-License-Identifier: Apache-2.0
"""Make every rendered page pass the Nu HTML Checker (vnu).

Python-Markdown emits XHTML-style void elements and the Material theme ships a few
attributes that the HTML Standard does not allow. None of it is visible to a reader,
but it fails ``vnu``, which CI runs over the whole built site. Template overrides
would have to be re-synced on every theme release, so the output is corrected here
instead, on each page after the theme has rendered it:

* ``<hr />``, ``<br />``, ``<input ... />`` and the other void elements lose the
    trailing slash. SVG and MathML elements are left alone; there it is meaningful.
* ``tabindex=""`` on navigation labels is dropped (an empty string is not an integer).
* ``autocomplete`` is dropped from the theme's checkbox toggles, where it is not an
    allowed attribute.
* ``for="__toc"`` is dropped from the table-of-contents label on pages that render no
    table of contents, where the control it points at does not exist.
* On a page with no headings Material renders the table-of-contents toggle
    (``id="__toc"``) but no label for it, leaving a form control with no name
    (pa11y H91, F68). It is named with ``aria-label``; nothing else changes.
* A fenced code block written straight after a line of text (typically a list item
    ending in a colon) renders inside that paragraph, and a ``<div>`` may not sit in a
    ``<p>``. The paragraph is closed before the block and any text after the block is
    left outside a paragraph, which is exactly how browsers already repair it, so
    nothing on the page moves.

Two more corrections are for pa11y at WCAG 2 AAA (technique H32, "forms have a submit
button"), which CI also runs over every page:

* The colour-scheme switch is a ``<form>`` that is never submitted: its radio inputs
    act the moment they change. It becomes a ``<div>``; the theme's script finds the
    inputs through ``data-md-component="palette"``, not through the form.
* The search box filters as you type and has no submit step either, but it must stay a
    ``<form>`` because its "Clear" control is a reset button. It gains a ``hidden``
    submit button, which changes nothing for any user: the theme already handles Enter
    itself.

Every rule is a no-op on markup that is already valid, so this is safe to keep after
the theme fixes any of them upstream.
"""

from __future__ import annotations

import re

_VOID = "area|base|br|col|embed|hr|img|input|link|meta|source|track|wbr"
_VOID_SLASH = re.compile(rf"<({_VOID})\b([^<>]*?)\s*/>", re.IGNORECASE)
_EMPTY_TABINDEX = re.compile(r'(<label\b[^<>]*?)\s+tabindex=""', re.IGNORECASE)
_CHECKBOX = re.compile(r'<input\b[^<>]*\btype="checkbox"[^<>]*>', re.IGNORECASE)
_AUTOCOMPLETE = re.compile(r'\s+autocomplete="[^"]*"', re.IGNORECASE)
_TOC_LABEL_FOR = re.compile(r'(<label\b[^<>]*?)\s+for="__toc"', re.IGNORECASE)
_PALETTE_FORM = re.compile(
    r'<form\b(?P<attrs>[^<>]*\bdata-md-component="palette"[^<>]*)>(?P<body>.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)
_SEARCH_FORM = re.compile(r'(<form\b[^<>]*\bclass="md-search__form"[^<>]*>)', re.IGNORECASE)
_TOC_INPUT = re.compile(r'<input\b[^<>]*\bid="__toc"[^<>]*>', re.IGNORECASE)
_SEARCH_SUBMIT = '<button type="submit" hidden>Search</button>'
_CODE_BLOCK = r'<div class="[^"]*\bhighlight\b[^"]*">.*?</pre></div>'
_P_WITH_CODE_BLOCK = re.compile(rf"<p>((?:(?!</?p\b).)*?{_CODE_BLOCK}(?:(?!</?p\b).)*?)</p>", re.DOTALL)
_CODE_BLOCK_SPLIT = re.compile(f"({_CODE_BLOCK})", re.DOTALL)


def _name_toc_input(match: re.Match[str]) -> str:
    tag = match[0]
    return tag if "aria-label=" in tag else tag[:-1] + ' aria-label="Table of contents">'


def _strip_autocomplete(match: re.Match[str]) -> str:
    return _AUTOCOMPLETE.sub("", match[0])


def _unwrap_code_blocks(match: re.Match[str]) -> str:
    before, *rest = _CODE_BLOCK_SPLIT.split(match[1])
    lead = [f"<p>{before.rstrip()}</p>"] if before.strip() else []
    return "\n".join(lead + [part.strip() for part in rest if part.strip()])


def _clean(output: str) -> str:
    output = _VOID_SLASH.sub(r"<\1\2>", output)
    output = _EMPTY_TABINDEX.sub(r"\1", output)
    output = _CHECKBOX.sub(_strip_autocomplete, output)
    output = _P_WITH_CODE_BLOCK.sub(_unwrap_code_blocks, output)
    if 'id="__toc"' not in output:
        output = _TOC_LABEL_FOR.sub(r"\1", output)
    elif 'for="__toc"' not in output:
        output = _TOC_INPUT.sub(_name_toc_input, output, count=1)
    output = _PALETTE_FORM.sub(r"<div\g<attrs>>\g<body></div>", output)
    if _SEARCH_SUBMIT not in output:
        output = _SEARCH_FORM.sub(rf"\1{_SEARCH_SUBMIT}", output)
    return output


def on_post_page(output: str, **_kwargs: object) -> str:
    """Return a rendered page with the invalid-but-harmless markup corrected."""
    return _clean(output)


def on_post_template(output_content: str, template_name: str, **_kwargs: object) -> str:
    """Do the same for static templates such as ``404.html``; leave XML alone."""
    return _clean(output_content) if template_name.endswith(".html") else output_content
