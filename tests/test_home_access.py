"""Home grants do not inherit network, pairing or unrelated session scopes."""

import pytest

from clusterctl.homes.policy import Actor, Policy, validate_audience
from clusterctl.homes.sessions import Sessions


def test_independent_audiences_and_live_revocation():
    human = Actor("human:known", "human", "binding-1", "Paired person")
    other = Actor("human:other", "human", "binding-1", "Another person")
    being = Actor("dm:being:known", "being", "binding-1", "Being")
    actors = {a.ref: a for a in (human, other, being)}
    pair = {"home": human.ref}
    members = {being.ref}
    policy = Policy(
        actor=actors.get,
        paired_human=pair.get,
        tribe_member=lambda home, tribe, actor: tribe == "tribe"
        and actor.ref in members,
    )

    def allows(visibility, subject=None, vpn=False, **extra):
        return policy.allows(
            {"visibility": visibility, **extra},
            home="home",
            subject=subject,
            dedicated_vpn=vpn,
        )

    assert allows("public") and allows("vpn", vpn=True)
    assert not allows("vpn", human)
    assert allows("human", human) and not allows("human", being, vpn=True)
    assert not allows("tribe", human, vpn=True, tribes=["tribe"])
    assert allows("tribe", being, tribes=["tribe"])
    assert allows("individual", other, recipients=[other.ref])
    members.clear()
    assert not allows("tribe", being, tribes=["tribe"])
    pair["home"] = other.ref
    assert not allows("human", human)
    actors[other.ref] = Actor(other.ref, "human", "binding-2", other.name)
    assert not allows("individual", other, recipients=[other.ref])


def test_audience_targets_are_closed_and_resolved():
    person = Actor("human:known", "human", "v1", "Person")

    def validate(entry):
        return validate_audience(
            entry,
            known_actor=lambda r: person if r == person.ref else None,
            known_tribe=lambda t: t == "tribe",
        )

    validate({"visibility": "individual", "recipients": [person.ref]})
    validate({"visibility": "tribe", "tribes": ["tribe"]})
    for entry in [
        {"visibility": "tribe"},
        {"visibility": "individual", "recipients": ["unverified"]},
        {"visibility": "human", "recipients": [person.ref]},
        {"visibility": "vpn", "tribes": ["tribe"]},
        {"visibility": "public", "recipients": [person.ref]},
        {"visibility": "invented"},
    ]:
        with pytest.raises(ValueError):
            validate(entry)


def test_browser_proof_exact_home_actor_and_expiry(tmp_path):
    now = [1000]
    store = Sessions(tmp_path, clock=lambda: now[0])
    actor = Actor("human:known", "human", "v1", "Person")
    request, proof = store.request(home="one", origin="https://one.example")
    store.approve(home="one", code=request["code"], subject=actor)

    def current(ref, revision):
        return actor if (ref, revision) == (actor.ref, actor.revision) else None

    for wrong in (
        {"home": "two"},
        {"origin": "https://two.example"},
        {"proof": "other-browser"},
    ):
        args = dict(
            home="one",
            origin="https://one.example",
            code=request["code"],
            proof=proof,
            current_actor=current,
        )
        args.update(wrong)
        with pytest.raises(ValueError):
            store.claim(**args)
    status, token = store.claim(
        home="one",
        origin="https://one.example",
        code=request["code"],
        proof=proof,
        current_actor=current,
    )
    assert status["status"] == "approved"
    assert (
        store.resolve(token, home="one", origin="https://one.example")["actor"]
        == actor.ref
    )
    assert store.resolve(token, home="two", origin="https://one.example") is None
    repeated, same_token = store.claim(
        home="one",
        origin="https://one.example",
        code=request["code"],
        proof=proof,
        current_actor=current,
    )
    assert repeated == status and same_token == token
    store.revoke(home="one", token=token)
    assert store.resolve(token, home="one", origin="https://one.example") is None
    with pytest.raises(ValueError):
        store.claim(
            home="one",
            origin="https://one.example",
            code=request["code"],
            proof=proof,
            current_actor=current,
        )
    assert (
        token.encode() not in store.path.read_bytes()
        and proof.encode() not in store.path.read_bytes()
    )


def test_binding_change_and_clock_rollback_cannot_revive_pairing(tmp_path):
    now = [1000]
    store = Sessions(tmp_path, clock=lambda: now[0])
    actor = Actor("human:known", "human", "v1", "Person")
    request, proof = store.request(home="one", origin="https://one.example")
    store.approve(home="one", code=request["code"], subject=actor)
    with pytest.raises(ValueError):
        store.claim(
            home="one",
            origin="https://one.example",
            code=request["code"],
            proof=proof,
            current_actor=lambda *_: None,
        )
    token = store.issue(home="one", origin="https://one.example", subject=actor, ttl=30)
    now[0] = 1100
    assert store.resolve(token, home="one", origin="https://one.example") is None

    now[0] = 1001
    assert store.resolve(token, home="one", origin="https://one.example") is None


def test_owner_credentials_are_not_rebound_by_configuration_changes(tmp_path):
    store = Sessions(tmp_path)
    actor = Actor("being-one", "being", "first", "Being")
    store.register_owner(
        home="home", actor=actor.ref, revision=actor.revision, token="fixture-owner"
    )
    assert store.owner("fixture-owner", home="home", subject=actor)
    next_actor = Actor(actor.ref, "being", "successor", actor.name)
    assert not store.owner("fixture-owner", home="home", subject=next_actor)
    with pytest.raises(ValueError, match="immutable"):
        store.register_owner(
            home="home",
            actor=actor.ref,
            revision=next_actor.revision,
            token="fixture-owner",
        )
    assert (
        store.resolve("fixture-owner", home="home", origin="https://home.example")
        is None
    )
