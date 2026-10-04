#!/usr/bin/env python3
"""Fetch the ICANN + PRIVATE PSL and its vectors, convert DNS labels to ASCII, repin."""
import hashlib
from pathlib import Path
import re
import urllib.request

root = Path(__file__).resolve().parents[1]
base = 'https://raw.githubusercontent.com/publicsuffix/list/master/'
resource = root / 'crates/cerebellum/resources/public_suffix_list.dat'
raw = urllib.request.urlopen(base + 'public_suffix_list.dat').read().decode()
lines = []
for line in raw.splitlines():
    if line and not line.startswith('//'):
        prefix = '!' if line.startswith('!') else ''
        line = prefix + '.'.join(label.encode('idna').decode('ascii') for label in line.lstrip('!').split('.'))
    lines.append(line)
resource.write_text('\n'.join(lines) + '\n')
vectors = urllib.request.urlopen(base + 'tests/test_psl.txt').read().decode()
# Keep the official vectors, including Unicode inputs, alongside the snapshot.
resource.with_name('test_psl.txt').write_text(vectors)
ascii_vectors = []
for match in re.finditer(r"^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\)", vectors, re.MULTILINE):
    def ascii_value(value):
        if value == 'null':
            return 'null'
        return '.'.join(label.encode('idna').decode('ascii') if label else '' for label in value[1:-1].split('.'))
    ascii_vectors.append('\t'.join(ascii_value(value) for value in match.groups()))
resource.with_name('test_psl_ascii.txt').write_text('\n'.join(ascii_vectors) + '\n')
source = root / 'crates/cerebellum/src/public_suffix.rs'
text = source.read_text()
text = re.sub(r'pub const PSL_SHA256: &str = "[^"]*";', 'pub const PSL_SHA256: &str = "' + hashlib.sha256(resource.read_bytes()).hexdigest() + '";', text)
source.write_text(text)
print('PSL SHA256:', hashlib.sha256(resource.read_bytes()).hexdigest())
