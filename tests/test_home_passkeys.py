"""Real WebAuthn signatures, fresh approval provenance and shared revocation."""

from contextlib import closing
from dataclasses import replace
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import pytest

from clusterctl.homes.passkeys import encode
from clusterctl.homes.policy import Actor
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions
from tests.test_home_gateway import serving
import urllib.request
import urllib.error


@pytest.fixture
def system(tmp_path):
    class Authority:
        people = {
            "owner": Actor("owner", "being", "v1", "Owner"),
            "human": Actor("human", "human", "v1", "Human"),
            "other": Actor("other", "human", "v1", "Other"),
        }

        def actor(self, ref):
            return self.people.get(ref)

        def paired_human(self, home):
            return "human" if home == "one" else "other"

        def tribe_member(self, *args):
            return False

    class Empty:
        def state(self):
            return {"schema": 1, "entries": []}

    homes = {
        name: {
            "public_url": "https://" + name + ".example.test",
            "vpn_url": "https://private-" + name + ".example.test",
            "name": name,
            "owner_being_ref": "owner",
            "owner_revision": "v1",
        }
        for name in ["one", "two"]
    }
    clock = [1000]
    sessions = Sessions(tmp_path / "state", clock=lambda: clock[0])
    app = Application(
        {"homes": homes},
        Authority(),
        sessions,
        backends={name: Empty() for name in homes},
        passkey_rp_id="example.test",
    )
    return app, clock


def approved(app, home="one", actor="human"):
    origin = app.homes[home]["public_url"]
    request, proof = app.sessions.request(home=home, origin=origin)
    app.sessions.approve(
        home=home, code=request["code"], subject=app.authority.actor(actor)
    )
    _, token = app.sessions.claim(
        home=home,
        origin=origin,
        code=request["code"],
        proof=proof,
        current_actor=app.policy.current,
    )
    return token, proof


def registration(options, *, origin="https://one.example.test", uv=True, cross=False):
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    identifier = os.urandom(32)
    cose = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    auth = (
        hashlib.sha256(options["rp"]["id"].encode()).digest()
        + bytes([0x41 | (4 if uv else 0)])
        + bytes(4)
        + bytes(16)
        + len(identifier).to_bytes(2, "big")
        + identifier
        + cose
    )
    client = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": origin,
            "crossOrigin": cross,
        }
    ).encode()
    credential = {
        "id": encode(identifier),
        "rawId": encode(identifier),
        "type": "public-key",
        "response": {
            "clientDataJSON": encode(client),
            "attestationObject": encode(
                cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
            ),
        },
        "clientExtensionResults": {},
    }
    return private, credential


def assertion(
    options,
    key,
    identifier,
    handle,
    *,
    origin="https://one.example.test",
    counter=1,
    uv=True,
    cross=False,
    rp="example.test",
    challenge=None,
):
    client = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge or options["challenge"],
            "origin": origin,
            "crossOrigin": cross,
        }
    ).encode()
    auth = (
        hashlib.sha256(rp.encode()).digest()
        + bytes([1 | (4 if uv else 0)])
        + counter.to_bytes(4, "big")
    )
    signature = key.sign(
        auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
    )
    return {
        "id": identifier,
        "rawId": identifier,
        "type": "public-key",
        "response": {
            "clientDataJSON": encode(client),
            "authenticatorData": encode(auth),
            "signature": encode(signature),
            "userHandle": handle,
        },
        "clientExtensionResults": {},
    }


def enrolled(app):
    token, browser = approved(app)
    start, proof = app.passkeys.begin(
        home="one",
        origin=app.homes["one"]["public_url"],
        mode="register",
        token=token,
        browser_proof=browser,
    )
    key, credential = registration(start["options"])
    result, _ = app.passkeys.finish(
        home="one",
        origin=app.homes["one"]["public_url"],
        mode="register",
        nonce=start["nonce"],
        proof=proof,
        credential=credential,
        token=token,
        browser_proof=browser,
    )
    assert result["status"] == "registered"
    return key, credential["id"], start["options"]["user"]["id"]


def login(app, key, identifier, handle, home="one", **changes):
    origin = app.homes[home]["public_url"]
    start, proof = app.passkeys.begin(home=home, origin=origin, mode="login")
    credential = assertion(
        start["options"], key, identifier, handle, **({"origin": origin} | changes)
    )
    return app.passkeys.finish(
        home=home,
        origin=origin,
        mode="login",
        nonce=start["nonce"],
        proof=proof,
        credential=credential,
    )


def test_fresh_browser_enrollment_is_not_a_read_token_power(system):
    app, clock = system
    token = app.sessions.issue(
        home="one",
        origin=app.homes["one"]["public_url"],
        subject=app.authority.actor("human"),
    )
    with pytest.raises(ValueError, match="fresh_browser"):
        app.passkeys.begin(
            home="one",
            origin=app.homes["one"]["public_url"],
            mode="register",
            token=token,
        )
    token, proof = approved(app)
    with pytest.raises(ValueError, match="fresh_browser"):
        app.passkeys.begin(
            home="one",
            origin=app.homes["one"]["public_url"],
            mode="register",
            token=token,
            browser_proof="wrong",
        )
    clock[0] += 901
    with pytest.raises(ValueError, match="fresh_browser"):
        app.passkeys.begin(
            home="one",
            origin=app.homes["one"]["public_url"],
            mode="register",
            token=token,
            browser_proof=proof,
        )


def test_shared_credential_login_and_atomic_global_revocation(system):
    app, _ = system
    key, identifier, handle = enrolled(app)
    _, first = login(app, key, identifier, handle, counter=1)
    _, second = login(app, key, identifier, handle, home="two", counter=2)
    assert app.identity(first, "one", app.homes["one"]["public_url"]).ref == "human"
    assert app.identity(second, "two", app.homes["two"]["public_url"]).ref == "human"
    # Identity in another home does not imply that home's paired-human audience.
    assert not app.policy.allows(
        {"visibility": "human"}, home="two", subject=app.authority.actor("human")
    )
    app.passkeys.revoke(
        home="one",
        origin=app.homes["one"]["public_url"],
        token=first,
        browser_proof="",
        identifier=identifier,
    )
    assert app.identity(first, "one", app.homes["one"]["public_url"]) is None
    assert app.identity(second, "two", app.homes["two"]["public_url"]) is None
    with pytest.raises(ValueError, match="unknown_passkey"):
        login(app, key, identifier, handle, counter=3)


@pytest.mark.parametrize(
    "changes",
    [
        {"uv": False},
        {"cross": True},
        {"rp": "attacker.example"},
        {"challenge": encode(bytes(32))},
        {"handle": encode(bytes(32))},
        {"origin": "https://artifacts.example.test"},
    ],
)
def test_signed_assertions_still_require_uv_context_and_user_handle(system, changes):
    app, _ = system
    key, identifier, handle = enrolled(app)
    supplied_handle = changes.pop("handle", handle)
    with pytest.raises(ValueError):
        login(app, key, identifier, supplied_handle, **changes)


@pytest.mark.parametrize(
    "changes",
    [{"uv": False}, {"cross": True}, {"origin": "https://artifacts.example.test"}],
)
def test_registration_checks_actual_attestation_uv_and_origin(system, changes):
    app, _ = system
    token, browser = approved(app)
    start, proof = app.passkeys.begin(
        home="one",
        origin=app.homes["one"]["public_url"],
        mode="register",
        token=token,
        browser_proof=browser,
    )
    _, credential = registration(start["options"], **changes)
    with pytest.raises(ValueError):
        app.passkeys.finish(
            home="one",
            origin=app.homes["one"]["public_url"],
            mode="register",
            nonce=start["nonce"],
            proof=proof,
            credential=credential,
            token=token,
            browser_proof=browser,
        )


def test_browser_challenge_is_one_shot_scoped_and_expires(system):
    app, clock = system
    key, identifier, handle = enrolled(app)
    start, proof = app.passkeys.begin(
        home="one", origin=app.homes["one"]["public_url"], mode="login"
    )
    credential = assertion(start["options"], key, identifier, handle)
    kwargs = dict(
        home="one",
        origin=app.homes["one"]["public_url"],
        mode="login",
        nonce=start["nonce"],
        proof=proof,
        credential=credential,
    )
    for override in [
        {"proof": "wrong"},
        {"home": "two", "origin": app.homes["two"]["public_url"]},
        {"mode": "register"},
    ]:
        with pytest.raises(ValueError):
            app.passkeys.finish(**(kwargs | override))
    app.passkeys.finish(**kwargs)
    with pytest.raises(ValueError, match="challenge_unavailable"):
        app.passkeys.finish(**kwargs)
    start, proof = app.passkeys.begin(
        home="one", origin=app.homes["one"]["public_url"], mode="login"
    )
    clock[0] += 301
    with pytest.raises(ValueError, match="challenge_unavailable"):
        app.passkeys.finish(**(kwargs | {"nonce": start["nonce"], "proof": proof}))


def test_identity_counter_and_revoked_session_enrollment_fences(system):
    app, _ = system
    key, identifier, handle = enrolled(app)
    login(app, key, identifier, handle, counter=2)
    with pytest.raises(ValueError):
        login(app, key, identifier, handle, counter=1)
    app.authority.people["human"] = replace(
        app.authority.people["human"], revision="v2"
    )
    with pytest.raises(ValueError, match="identity_changed"):
        login(app, key, identifier, handle, counter=3)


def test_synced_zero_counter_credentials_are_supported(system):
    app, _ = system
    key, identifier, handle = enrolled(app)
    assert login(app, key, identifier, handle, counter=0)[1]
    assert login(app, key, identifier, handle, counter=0)[1]


def test_http_bearer_and_wrong_origin_cannot_enroll_keys(system):
    app, _ = system
    token, proof = approved(app)
    with serving(handler(app)) as root:
        for headers in [
            {"Authorization": "Bearer " + token, "Origin": "https://one.example.test"},
            {"Origin": "null"},
            {"Origin": "https://artifacts.example.test"},
        ]:
            request = urllib.request.Request(
                root + "/access/passkeys/register-options",
                data=b"{}",
                headers={
                    "Host": "one.example.test",
                    "Cookie": "__Host-home=" + token + "; __Host-home-proof=" + proof,
                    **headers,
                },
            )
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(request)
            assert err.value.code == 403
            err.value.close()
    with closing(app.sessions.connect()) as db:
        assert db.execute("SELECT count(*) FROM passkeys").fetchone()[0] == 0
