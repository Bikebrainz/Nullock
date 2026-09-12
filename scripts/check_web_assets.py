#!/usr/bin/env python3
"""Verify served integrity, website assets, and repository documentation offline."""
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import posixpath
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def markdown_links(source):
    """Read inline destinations and reference definitions outside fenced examples.

    Check destination paths, not heading fragments: GitHub renders the Markdown
    anchors, while Page below checks the actual IDs in committed HTML.
    """
    fence = None
    for line in source.splitlines():
        marker = re.match(r'^ {0,3}(`{3,}|~{3,})', line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        # Remove inline code examples, retaining real links whose labels use code.
        line = re.sub(r'(`+).*?\1', '', line)
        pattern = (r'\]\(\s*(?:<([^>]+)>|([^\s)]+))'
                   r'|^ {0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))')
        for match in re.finditer(pattern, line):
            yield next(value for value in match.groups() if value is not None)


def check_markdown(root):
    # Only inspect versioned documentation, not dependency READMEs or build output.
    tracked = subprocess.check_output(
        ['git', 'ls-files', '-z'], cwd=root).decode('utf-8').split('\0')
    paths = set(filter(None, tracked))
    directories = {parent.as_posix() for name in paths for parent in Path(name).parents}
    errors, count = [], 0
    for name in sorted(paths):
        if not name.endswith('.md'):
            continue
        for href in markdown_links((root / name).read_text(encoding='utf-8')):
            url = urlsplit(href)
            if url.scheme or url.netloc or not url.path:
                continue
            count += 1
            relative = posixpath.join(posixpath.dirname(name), unquote(url.path))
            if url.path.startswith('/'):
                relative = unquote(url.path).lstrip('/')
            # Compare Git's spelling, so Windows also catches case-only mistakes
            # and links to files that exist locally but were never committed.
            relative = posixpath.normpath(relative)
            if ((relative not in paths and relative not in directories)
                    or not (root / relative).exists()):
                errors.append(f'{name}: missing tracked Markdown target {href}')
    return count, errors

class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.refs, self.ids, self.integrity = [], set(), []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        for attr in ('href', 'src', 'poster'):
            if attrs.get(attr): self.refs.append((tag, attr, attrs[attr]))
        if tag == 'script' and attrs.get('integrity'):
            self.integrity.append((attrs.get('src', ''), attrs['integrity']))

def main():
    markdown_count, errors = check_markdown(ROOT)
    ui = ROOT / 'ui-v2'
    parsed_ui = Page((ui / 'Nullock.html').read_text(encoding='utf-8'))
    for name, expected in parsed_ui.integrity:
        path = ui / name
        algorithm, digest = expected.split('-', 1)
        actual = base64.b64encode(hashlib.new(algorithm, path.read_bytes()).digest()).decode()
        if actual != digest: errors.append(f'UI integrity mismatch: {name}')
    docs = ROOT / 'docs'
    pages = {p.resolve(): Page(p.read_text(encoding='utf-8')) for p in docs.rglob('*.html')}
    for path, page in pages.items():
        for tag, attr, href in page.refs:
            url = urlsplit(href)
            if url.scheme or url.netloc or not href or href == '#': continue
            relative = unquote(url.path)
            if relative.startswith('/Nullock/'): target = docs / relative[len('/Nullock/'):]
            elif relative.startswith('/'): target = docs / relative.lstrip('/')
            else: target = path.parent / relative if relative else path
            if target.is_dir(): target /= 'index.html'
            target = target.resolve()
            if not target.is_file():
                errors.append(f'{path.relative_to(ROOT)}: missing {href}')
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                errors.append(f'{path.relative_to(ROOT)}: missing fragment {href}')
    for error in errors: print(error)
    print(f'{markdown_count} Markdown targets, {len(parsed_ui.integrity)} integrity hashes, '
          f'{len(pages)} site pages, {len(errors)} errors')
    return bool(errors)

if __name__ == '__main__': raise SystemExit(main())
