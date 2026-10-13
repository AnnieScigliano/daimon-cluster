"""Actual offline pip installation, crash replay and immutable completed code."""
import hashlib
import json
import os
import zipfile

import pytest

from clusterctl import onboarding_release, onboarding_sdk
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_guest import artifact
from tools.build_onboarding_sdk import seal


def fixture(tmp_path, *, requirements=(), wheel_tag='py3-none-any'):
    code = tmp_path / "code"
    artifact(code)
    (code / "release.json").unlink()
    root = code / "sdk"
    wheels = root / "wheels"
    wheels.mkdir(parents=True)
    package = "daimon_matrix-0.1.0rc1.dist-info"
    with zipfile.ZipFile(wheels / "daimon_matrix-0.1.0rc1-py3-none-any.whl", "w") as archive:
        archive.writestr("daimon_matrix/__init__.py", "# Synthetic dependency-installation fixture only.\n")
        archive.writestr(package + "/METADATA", "Metadata-Version: 2.1\nName: daimon-matrix\nVersion: 0.1.0rc1\n"
                         + ''.join('Requires-Dist: ' + row + '\n' for row in requirements))
        archive.writestr(package + "/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: " + wheel_tag + '\n')
        archive.writestr(package + "/RECORD", "")
    seal(root)
    selected = dict(schema=onboarding_release.PROFILE, model="gpt-6.1-sol", reasoning="xhigh",
                    approval="never", sandbox="danger-full-access", skills=["listening"], primary_store=None)
    fingerprint = onboarding_release.seal(code, selected)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return code, fingerprint, home


def test_actual_offline_install_retry_and_changed_completed_code_are_observed(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    receipt = json.loads((venv.parent / "installation.json").read_bytes())
    assert receipt["matrix_commit"] == onboarding_sdk.MATRIX_COMMIT and receipt["wheel_count"] == 1
    assert onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid()) == venv
    target = next(venv.glob("lib/python*/site-packages/daimon_matrix/__init__.py"))
    target.write_bytes(b"# Own changed installation must not be overwritten.\n")
    preserved = target.read_bytes()
    with pytest.raises(OnboardingError, match="installed_onboarding_sdk_changed"):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert target.read_bytes() == preserved
    assert not (home / ".codex").exists() and not list(home.rglob("custody.json"))


def test_missing_install_acknowledgement_replays_only_offline_dependencies(tmp_path, monkeypatch):
    code, fingerprint, home = fixture(tmp_path)
    original = onboarding_sdk._run
    failed = []
    def interrupted(argv):
        result = original(argv)
        if "--require-hashes" in argv and not failed:
            failed.append(True)
            raise RuntimeError("process disappeared after pip finished")
        return result
    monkeypatch.setattr(onboarding_sdk, "_run", interrupted)
    with pytest.raises(RuntimeError):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob("installation.json"))
    before = next(home.glob(".local/share/daimon-matrix/sdk/*/venv/lib/python*/site-packages/daimon_matrix/__init__.py"))
    checksum = hashlib.sha256(before.read_bytes()).hexdigest()
    marker = tmp_path / 'unexpected-startup'
    hook = 'import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("executed")\n'
    (before.parent.parent / 'unexpected.pth').write_text(hook)
    (before.parent.parent / 'sitecustomize.py').write_text(hook)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert hashlib.sha256(before.read_bytes()).hexdigest() == checksum
    assert (venv.parent / "installation.json").exists()
    assert not marker.exists()


def test_completed_sdk_probe_never_executes_site_hooks_or_installed_pip(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    site = next(venv.glob('lib/python*/site-packages'))
    marker = tmp_path / 'unexpected-startup'
    hook = 'import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("executed")\n'
    files = [site / 'unexpected.pth', site / 'sitecustomize.py', site / 'pip/__init__.py']
    for path in files:
        path.write_text(hook + 'raise RuntimeError("unverified installed code executed")\n')
    before = {path: path.read_bytes() for path in files}
    receipt = (venv.parent / 'installation.json').read_bytes()
    assert onboarding_sdk.observe(home, code, code_uid=os.geteuid()) == venv
    assert onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid()) == venv
    assert not marker.exists()
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert (venv.parent / 'installation.json').read_bytes() == receipt


def test_hook_free_dependency_check_still_rejects_missing_dependencies(tmp_path):
    code, fingerprint, home = fixture(tmp_path, requirements=('missing-synthetic-package>=1',))
    with pytest.raises(OnboardingError, match='native_onboarding_sdk_refused'):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob('installation.json'))


def test_hook_free_dependency_check_honors_environment_markers(tmp_path):
    code, fingerprint, home = fixture(tmp_path,
        requirements=('missing-synthetic-package>=1; python_version < "0"',))
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert onboarding_sdk.observe(home, code, code_uid=os.geteuid()) == venv


def test_hook_free_check_still_rejects_unsupported_installed_wheel_tags(tmp_path):
    code, fingerprint, home = fixture(tmp_path, wheel_tag='cp99-cp99-unavailable_platform')
    with pytest.raises(OnboardingError, match='native_onboarding_sdk_refused'):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob('installation.json'))


def test_changed_wheel_or_requirement_refused_before_home_creation(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    (code / "sdk/requirements.txt").write_bytes(b"daimon-matrix\n")
    with pytest.raises(OnboardingError, match="receiving_release_digest_mismatch"):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.iterdir())
    value = json.loads((code / "sdk/sdk.json").read_bytes())
    assert len(digest(value)) == 64
    with pytest.raises(OnboardingError, match="onboarding_sdk_digest_mismatch"):
        onboarding_sdk.verify(code, uid=os.geteuid())


def test_wheel_paths_cannot_escape_site_packages(tmp_path):
    path = tmp_path / "bad-1-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape", "bad")
    path.chmod(0o644)
    with pytest.raises(OnboardingError, match="invalid_onboarding_sdk_wheel"):
        onboarding_sdk.wheel(path, uid=os.geteuid())
