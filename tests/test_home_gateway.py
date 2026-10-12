"""Shared authority, publication crash boundaries and actual HTTP audience reads."""

from contextlib import closing, contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import urllib.error
import urllib.request

import pytest

from clusterctl.homes.policy import Actor
from clusterctl.homes.registry import Registry, version_digest
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions


@contextmanager
def serving(cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def selected(ref, visibility, **fields):
    result = {
        "id": ref[0:8],
        "artifact_ref": ref,
        "visibility": visibility,
        "recipients": [],
        "tribes": [],
        "title": "Restricted title " + ref,
        "summary": "Description",
        "kind": "artifact",
        "revision": "1" * 64,
        "version_ref": ref + "1" * 32,
        "object": "object",
        "entrypoint": "index.html",
        "files": ["index.html", "data.txt"],
        "versions": [],
        **fields,
    }
    result["version_ref"] = version_digest(result)
    return result


def key(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value)
    path.chmod(0o600)
    return str(path)


class Authority:
    def __init__(self):
        self.people = {
            ref: Actor(ref, kind, "v1", ref)
            for ref, kind in [
                ("owner-one", "being"),
                ("owner-two", "being"),
                ("human-one", "human"),
                ("human-two", "human"),
            ]
        }
        self.members = {"owner-one", "human-one"}

    def actors(self):
        return self.people

    def actor(self, ref):
        return self.people.get(ref)

    def paired_human(self, home):
        return {"one": "human-one", "two": "human-two"}.get(home)

    def tribes(self):
        return {"tribe": {"founder_principal_id": "owner-one"}}

    def tribe_member(self, home, tribe, actor):
        return tribe == "tribe" and actor.ref in self.members


def test_shared_registry_cas_ownership_and_failed_projection(tmp_path):
    sessions = Sessions(tmp_path / "authority")
    registry = Registry(sessions)
    state = {"schema": 1, "entries": [selected("a" * 32, "public")]}

    def register(home, revision, value):
        return registry.register(
            home=home,
            owner=home,
            state=value,
            expected_revision=revision,
            known_actor=lambda _: True,
            known_tribe=lambda _: True,
        )

    receipt = register("one", 0, state)
    assert receipt["revision"] == 1 and registry.current("one", observed_state=state)
    assert register("one", 0, state)["status"] == "unchanged"
    changed = deepcopy(state)
    changed["entries"][0]["visibility"] = "human"
    changed["entries"][0]["version_ref"] = version_digest(changed["entries"][0])
    assert registry.current("one", observed_state=changed) is None
    with pytest.raises(ValueError, match="revision_conflict"):
        register("one", 0, changed)
    assert register("one", 1, changed)["revision"] == 2
    assert registry.current("one", observed_state=state) is None
    with pytest.raises(ValueError, match="owner_conflict"):
        register("two", 0, state)
    assert registry.revision("two") == 0
    register("one", 2, {"schema": 1, "entries": []})
    # Removal never relinquishes identity to another owner; history stays.
    with pytest.raises(ValueError, match="owner_conflict"):
        register("two", 0, state)
    with closing(sessions.connect()) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM publication_history WHERE home=?", ("one",)
            ).fetchone()[0]
            == 3
        )


def test_current_and_historical_audiences_both_required(tmp_path):
    authority = Authority()
    entry = selected("a" * 32, "public")
    old = selected("a" * 32, "human")
    old["revision"] = "0" * 64
    old["version_ref"] = version_digest(old)
    entry["versions"] = [old]
    state = {"schema": 1, "entries": [entry]}

    class Bytes:
        def state(self):
            return state

    app = Application(
        {"homes": {"one": {"owner_being_ref": "owner-one"}}},
        authority,
        Sessions(tmp_path),
        backends={"one": Bytes()},
    )
    app.registry.register(
        home="one",
        owner="owner-one",
        state=state,
        expected_revision=0,
        known_actor=authority.actor,
        known_tribe=lambda _: True,
    )
    assert app.selected("one", "a" * 32, "current", None)
    assert not app.selected("one", "a" * 32, old["version_ref"], None)
    assert app.selected(
        "one", "a" * 32, old["version_ref"], authority.actor("human-one")
    )
    # Even a matching retained manifest cannot transfer to another paired human.
    app.homes["one"]["owner_being_ref"] = "owner-two"
    assert not app.publication("one")["entries"]
    with pytest.raises(ValueError, match="owner_conflict"):
        Application(app.config, authority, app.sessions, backends=app.backends)
    app.homes["one"]["owner_being_ref"] = "owner-one"
    state["entries"][0]["visibility"] = "human"
    # Local changes alone cannot open or retain the old serving projection.
    assert not app.selected("one", "a" * 32, "current", authority.actor("human-one"))


def test_historical_grant_cannot_be_rewritten_by_local_publisher(tmp_path):
    authority = Authority()
    registry = Registry(Sessions(tmp_path))
    original = selected("a" * 32, "human")
    current = selected("a" * 32, "public")
    current["versions"] = [original]
    state = {"schema": 1, "entries": [current]}
    registry.register(
        home="one",
        owner="owner-one",
        state=state,
        expected_revision=0,
        known_actor=authority.actor,
        known_tribe=lambda _: True,
    )
    altered = deepcopy(state)
    altered["entries"][0]["versions"][0]["visibility"] = "public"
    with pytest.raises(ValueError, match="immutable_version"):
        registry.register(
            home="one",
            owner="owner-one",
            state=altered,
            expected_revision=1,
            known_actor=authority.actor,
            known_tribe=lambda _: True,
        )
    retained = registry.version(
        home="one", resource="a" * 32, version=original["version_ref"]
    )
    assert retained["visibility"] == "human"
    assert registry.revision("one") == 1


def test_artifact_child_read_follows_parent_revocation_and_clock(tmp_path):
    now = [1000]
    sessions = Sessions(tmp_path, clock=lambda: now[0])
    person = Actor("human-one", "human", "v1", "Person")
    origin = "https://one.example"
    content = "https://artifacts.example"
    parent = sessions.issue(home="one", origin=origin, subject=person, ttl=60)
    child = sessions.content_read(
        home="one",
        origin=origin,
        content_origin=content,
        resource="a" * 32,
        version="b" * 64,
        subject=person,
        parent_token=parent,
    )
    assert (
        sessions.resolve_content(child, content_origin=content)["actor"] == person.ref
    )
    assert sessions.resolve_content(child, content_origin=origin) is None
    with pytest.raises(ValueError):
        sessions.content_read(
            home="one",
            origin=origin,
            content_origin=content,
            resource="a" * 32,
            version="b" * 64,
            subject=person,
            parent_token="invalid",
        )
    sessions.revoke(home="one", token=parent)
    assert sessions.resolve_content(child, content_origin=content) is None
    public = sessions.content_read(
        home="one",
        origin=origin,
        content_origin=content,
        resource="a" * 32,
        version="b" * 64,
        subject=None,
        parent_token=None,
        ttl=30,
    )
    now[0] = 1100
    assert sessions.resolve_content(public, content_origin=content) is None
    now[0] = 1001
    assert sessions.resolve_content(public, content_origin=content) is None


def test_http_catalog_files_ranges_and_revocation_use_same_authority(tmp_path):
    authority = Authority()
    entries = [
        selected(chr(ord("a") + i) * 32, audience, **extra)
        for i, (audience, extra) in enumerate(
            [
                ("public", {}),
                ("vpn", {}),
                ("human", {}),
                ("individual", {"recipients": ["human-two"]}),
                ("tribe", {"tribes": ["tribe"]}),
            ]
        )
    ]
    state = {"schema": 1, "entries": entries}

    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            assert self.headers.get("Authorization") == "Bearer content-reader"
            body = (
                json.dumps(state).encode()
                if self.path == "/_home/state"
                else b"<p>Selected bytes</p>"
            )
            code = 200
            if self.headers.get("Range"):
                body = body[:4]
                code = 206
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            if self.path != "/_home/state":
                self.send_header("X-Home-Version", self.path.split("/")[4])
            self.send_header(
                "Content-Type",
                "application/json" if self.path == "/_home/state" else "text/html",
            )
            if code == 206:
                self.send_header("Content-Range", "bytes 0-3/21")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    with serving(Origin) as backend:
        home = {
            "backend": backend,
            "gateway_token_file": key(tmp_path, "reader", "content-reader"),
            "owner_token_file": key(tmp_path, "owner", "home-owner"),
            "owner_being_ref": "owner-one",
            "owner_revision": "v1",
            "public_url": "https://one.example",
            "vpn_url": "https://private-one.example",
            "name": "Home",
        }
        app = Application(
            {"homes": {"one": home}}, authority, Sessions(tmp_path / "state")
        )
        app.owner("one", "home-owner", "sync", {})
        token = app.sessions.issue(
            home="one", origin=home["public_url"], subject=authority.actor("human-one")
        )
        other = app.sessions.issue(
            home="one", origin=home["public_url"], subject=authority.actor("human-two")
        )
        with serving(handler(app)) as gateway:

            def get(path, token="", vpn=False, method="GET", extra=None):
                headers = {
                    "Host": "private-one.example" if vpn else "one.example",
                    "X-Daimon-Home": "one",
                    "X-Daimon-Vpn": "1" if vpn else "0",
                }
                if token:
                    headers["Authorization"] = "Bearer " + token
                headers.update(extra or {})
                try:
                    with urllib.request.urlopen(
                        urllib.request.Request(
                            gateway + path, headers=headers, method=method
                        )
                    ) as response:
                        return response.status, response.read(), response.headers
                except urllib.error.HTTPError as error:
                    return error.code, error.read(), error.headers

            def visible(credential="", vpn=False):
                return json.loads(get("/catalog.json", credential, vpn)[1])["entries"]

            assert len(visible()) == 1
            assert len(visible(vpn=True)) == 2
            assert {e["visibility"] for e in visible(token)} == {
                "public",
                "human",
                "tribe",
            }
            assert {e["visibility"] for e in visible(other)} == {"public", "individual"}
            assert b"Restricted title c" not in get("/")[1]
            path = "/works/" + "c" * 32 + "/current/index.html"
            assert get(path)[0] == 404 and get(path, method="HEAD")[0] == 404
            assert get(path, extra={"Range": "bytes=0-3"})[0] == 404
            code, body, headers = get(path, token, extra={"Range": "bytes=0-3"})
            assert code == 206 and body == b"<p>S"
            assert "sandbox" in headers["Content-Security-Policy"]
            assert headers["Content-Disposition"] == "attachment"
            assert "default-src 'none'" in headers["Content-Security-Policy"]
            assert get(path, token, extra={"Origin": "null"})[0] == 404
            assert get("/_home/state", token)[0] == 404
            assert get(path, token, extra={"Host": "other.example"})[0] == 404
            authority.members.clear()
            assert {e["visibility"] for e in visible(token)} == {"public", "human"}
            app.sessions.revoke(home="one", token=token)
            assert get(path, token)[0] == 404
            # A local publisher changing a public object without registering it
            # cannot retain access through either direct or legacy URLs.
            state["entries"][0]["visibility"] = "human"
            assert visible() == []
            assert get("/artifacts/aaaaaaaa/index.html")[0] == 404


def test_owner_identity_approval_and_shared_roster_are_not_reader_powers(tmp_path):
    authority = Authority()

    class Empty:
        def state(self):
            return {"schema": 1, "entries": []}

    homes = {
        name: {
            "owner_being_ref": "owner-" + name,
            "owner_revision": "v1",
            "owner_token_file": key(tmp_path, name, "credential-" + name),
        }
        for name in ("one", "two")
    }
    app = Application(
        {"homes": homes},
        authority,
        Sessions(tmp_path / "state"),
        backends={name: Empty() for name in homes},
    )
    request, proof = app.sessions.request(home="one", origin="https://one.example")
    app.owner(
        "two",
        "credential-two",
        "approve-browser",
        {"home": "one", "code": request["code"]},
    )
    _, token = app.sessions.claim(
        home="one",
        origin="https://one.example",
        code=request["code"],
        proof=proof,
        current_actor=app.policy.current,
    )
    assert app.identity(token, "one", "https://one.example").ref == "human-two"
    with pytest.raises(ValueError):
        app.owner("one", token, "sync", {})
    with pytest.raises(ValueError):
        app.owner("one", "credential-two", "sync", {})
    payload = {
        "tribe": "tribe",
        "expected_revision": 0,
        "readers": ["human-two"],
        "revoked": False,
        "expires_at_ms": None,
    }
    with pytest.raises(ValueError, match="founder_required"):
        app.owner("two", "credential-two", "tribe-readers", payload)
    app.owner("one", "credential-one", "tribe-readers", payload)
    assert app.registry.rosters()["tribe"]["readers"] == ["human-two"]
    payload.update(expected_revision=1, readers=[], revoked=True)
    app.owner("one", "credential-one", "tribe-readers", payload)
    assert app.registry.rosters()["tribe"]["revoked"] is True
