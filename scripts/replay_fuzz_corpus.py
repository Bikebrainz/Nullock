#!/usr/bin/env python3
"""Replay every committed seed and fail if a corpus or executable is missing."""
import argparse
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument('build',type=Path)
parser.add_argument('--config',default='')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
count=0
for folder,target in [('http1','fuzz_http1_parser'),('har','fuzz_har_import'),('ws','fuzz_ws_parser')]:
    binary=args.build/'Tests/fuzz'/args.config/(target+('.exe' if sys.platform=='win32' else ''))
    seeds=sorted((root/'Tests/fuzz/seeds'/folder).glob('*'))
    if not binary.is_file() or not seeds: raise SystemExit(f'Missing executable or corpus: {target}')
    subprocess.run([str(binary.resolve()),*[str(p.resolve()) for p in seeds]],check=True,timeout=90)
    count+=len(seeds)
    print(f'{target}: replayed {len(seeds)} seeds')
print(f'PASS: {count} parser seed replays')
