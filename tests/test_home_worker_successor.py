"""Real Git composition preserves qualified dependencies and refuses overwrite."""
import json
import subprocess

import pytest

from tools.build_home_worker_successor import MODULES, build


def test_home_overlay_preserves_qualified_worker_and_dependency_pins(tmp_path):
    repository = tmp_path / 'repository'
    repository.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repository), *args]).decode().strip()
    git('init', '-q')
    git('config', 'user.name', 'Fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    files = MODULES | {'clusterctl/onboarding_sdk.py', 'clusterctl/onboarding_telegram.py',
                       'clusterctl/matrix_host.py'}
    for name in files:
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('qualified original ' + name)
    git('add', '.')
    git('commit', '-qm', 'Qualified worker')
    base = git('rev-parse', 'HEAD')
    for name in files | {'clusterctl/homes/provision.py', 'clusterctl/homes/assets/home.css'}:
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('advanced source ' + name)
    git('add', '.')
    git('commit', '-qm', 'Independent dependency advance and homes')
    source = git('rev-parse', 'HEAD')
    output = tmp_path / 'successor'
    receipt = build(repository, base, source, output)
    for name in files - MODULES:
        assert (output / name).read_text() == 'qualified original ' + name
    for name in MODULES | {'clusterctl/homes/provision.py', 'clusterctl/homes/assets/home.css'}:
        assert (output / name).read_text() == 'advanced source ' + name
    manifest = json.loads((output / 'worker-successor.json').read_text())
    assert manifest['base_commit'] == base and manifest['source_commit'] == source
    assert receipt['file_count'] == len(manifest['files'])
    with pytest.raises(ValueError, match='worker_destination_preserved'):
        build(repository, base, source, output)
    with pytest.raises(ValueError, match='exact_worker_commit_required'):
        build(repository, 'HEAD', source, tmp_path / 'other')
