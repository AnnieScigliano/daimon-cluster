"""Add homes to a qualified worker without advancing its body dependencies.

Both revisions are explicit full Git commits. The bounded overlay contains the
worker hook, its home provider and mount observation; all other qualified worker
files (including SDK/Telegram pins) remain byte-for-byte from the base. This is
an operator-built release, never a runtime import override or body upgrade.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


MODULES = {
    'clusterctl/onboarding_worker.py',
    'clusterctl/onboarding_host.py',
    'clusterctl/onboarding_homes.py',
    'tools/install_onboarding_worker.py',
}


def git(repository, *args):
    return subprocess.run(['git', '-C', str(repository), *args], check=True,
                          capture_output=True).stdout


def tree(repository, commit):
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('exact_worker_commit_required')
    if git(repository, 'rev-parse', commit + '^{commit}').decode().strip() != commit:
        raise ValueError('exact_worker_commit_required')
    rows = {}
    for record in git(repository, 'ls-tree', '-rz', commit).split(b'\0'):
        if not record:
            continue
        description, name = record.split(b'\t', 1)
        mode, kind, oid = description.decode().split()
        path = name.decode()
        if kind != 'blob' or mode not in {'100644', '100755'}:
            raise ValueError('regular_worker_source_required')
        rows[path] = (mode, oid)
    return rows


def build(repository, base_commit, source_commit, output):
    base, source = tree(repository, base_commit), tree(repository, source_commit)
    overlay = MODULES | {p for p in source if p.startswith('clusterctl/homes/')}
    if not MODULES <= source.keys() or 'clusterctl/homes/provision.py' not in overlay:
        raise ValueError('complete_home_worker_source_required')
    selected = {**base, **{p: source[p] for p in overlay}}
    # Refuse unsafe source paths and destinations before writing any bytes.
    for name in selected:
        p = Path(name)
        if p.is_absolute() or '..' in p.parts or name == 'worker-successor.json':
            raise ValueError('regular_worker_source_required')
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        raise ValueError('worker_destination_preserved')
    output.mkdir(mode=0o755)
    files = []
    for name, (mode, oid) in sorted(selected.items()):
        raw = git(repository, 'cat-file', 'blob', oid)
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o755 if mode == '100755' else 0o644)
        files.append(dict(path=name, sha256=hashlib.sha256(raw).hexdigest(), mode=mode))
    value = dict(schema='cluster-home-worker-successor/v1', base_commit=base_commit,
                 source_commit=source_commit, overlay=sorted(overlay), files=files)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    (output / 'worker-successor.json').write_bytes(raw)
    (output / 'worker-successor.json').chmod(0o644)
    return dict(manifest_sha256=hashlib.sha256(raw).hexdigest(), file_count=len(files))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.repository, args.base_commit, args.source_commit, args.output)))


if __name__ == '__main__':
    main()
