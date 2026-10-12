"""Gateway ownership, route withdrawal, and preserved guest service upgrades."""

from copy import deepcopy
import json

import pytest

from clusterctl.homes.host import ensure_proxy, guest_unit, register
from clusterctl.homes.provision import install_service, sha
from clusterctl.homes.policy import Actor


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)
    return str(path)


def configuration(tmp_path):
    home = {
        "name": "Existing",
        "owner_being_ref": "being-one",
        "owner_revision": "a" * 64,
        "public_url": "https://one.example",
        "vpn_url": "https://private-one.example",
        "backend": "http://127.0.0.1:8801",
        "ring": [],
        "owner_token_file": write(tmp_path / "owner.key", b"fixture-owner"),
        "gateway_token_file": write(tmp_path / "reader.key", b"fixture-reader"),
    }
    return {
        "schema": "dm.resource-access.host/v1",
        "state": str(tmp_path / "state"),
        "binding_source": str(tmp_path / "identities.json"),
        "relationship_store": str(tmp_path / "relationships.db"),
        "authority_source": str(tmp_path / "public-proofs.json"),
        "viewer_port": 8820,
        "owner_port": 8821,
        "content_public_url": "https://artifacts.example",
        "content_vpn_url": "https://private-artifacts.example",
        "homes": {"one": home},
    }


def test_shared_registration_requires_current_owner_and_preserves_other_homes(
    tmp_path, monkeypatch
):
    config = configuration(tmp_path)
    file = tmp_path / "config.json"
    raw = json.dumps(config).encode()
    write(file, raw)

    class Authority:
        def __init__(self, *a, **k):
            pass

        def actor(self, ref):
            return (
                Actor(ref, "being", "a" * 64, "Existing")
                if ref in {"being-one", "another-being"}
                else None
            )

    monkeypatch.setattr("clusterctl.homes.authority.NativeAuthority", Authority)
    new = deepcopy(config["homes"]["one"])
    new.update(public_url="https://two.example", vpn_url="https://private-two.example")
    assert (
        register(file, "two", new, previous_digest=sha(raw))["status"] == "registered"
    )
    assert json.loads(file.read_bytes())["homes"]["one"] == config["homes"]["one"]
    assert register(file, "two", new, previous_digest="old")["status"] == "unchanged"
    changed = deepcopy(new)
    changed["owner_being_ref"] = "another-being"
    with pytest.raises(ValueError, match="owner_conflict"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    changed = deepcopy(new)
    changed["owner_revision"] = "b" * 64
    with pytest.raises(ValueError, match="current_home_identity"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    before = file.read_bytes()
    assert (
        register(file, "two", new, previous_digest=sha(before), withdraw=True)["status"]
        == "withdrawn"
    )
    assert "two" not in json.loads(file.read_bytes())["homes"]
    changed = deepcopy(new)
    changed["owner_being_ref"] = "another-being"
    with pytest.raises(ValueError, match="owner_conflict"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    assert (
        register(file, "two", new, previous_digest=sha(file.read_bytes()))["status"]
        == "registered"
    )
    assert list((tmp_path / "previous").iterdir())


def test_guest_service_upgrade_is_idempotent_and_keeps_actual_rollback(tmp_path):
    binding = {"store": "/home/agent/.local/share/daimon-home"}
    unit = guest_unit(binding)
    assert b"User=agent\n" in unit and b"NoNewPrivileges=true" in unit
    system = tmp_path / "system"
    system.mkdir(mode=0o700)
    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    write(candidate, unit)
    assert install_service(candidate, None, system_dir=system, state_dir=state)
    assert not install_service(candidate, None, system_dir=system, state_dir=state)
    successor = unit.replace(b"MemoryMax=128M", b"MemoryMax=160M")
    write(candidate, successor)
    with pytest.raises(ValueError, match="preserved"):
        install_service(candidate, "wrong", system_dir=system, state_dir=state)
    assert install_service(candidate, sha(unit), system_dir=system, state_dir=state)
    assert any(path.read_bytes() == unit for path in state.iterdir())
    with pytest.raises(ValueError):
        guest_unit({"store": "/etc"})


def test_existing_proxy_conflict_is_never_replaced():
    devices = {}
    calls = []

    def run(args):
        if args[0] == "query":
            return json.dumps({"devices": devices})
        calls.append(args)
        devices[args[4]] = {
            key: value for key, value in (v.split("=", 1) for v in args[6:])
        }
        devices[args[4]]["type"] = args[5]
        return ""

    desired = {
        "type": "proxy",
        "listen": "tcp:127.0.0.1:8802",
        "connect": "tcp:127.0.0.1:8801",
    }
    assert ensure_proxy(run, "dm-existing", "daimon-home-public", desired)
    assert not ensure_proxy(run, "dm-existing", "daimon-home-public", desired)
    with pytest.raises(ValueError, match="preserved"):
        ensure_proxy(
            run,
            "dm-existing",
            "daimon-home-public",
            {**desired, "connect": "tcp:127.0.0.1:other"},
        )
    assert len(calls) == 1
