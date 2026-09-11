#!/usr/bin/env python3
"""Verify served integrity bytes and local website navigation/assets without network."""
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]

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
    errors = []
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
    print(f'{len(parsed_ui.integrity)} integrity hashes, {len(pages)} site pages, {len(errors)} errors')
    return bool(errors)

if __name__ == '__main__': raise SystemExit(main())
