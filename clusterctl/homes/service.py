"""Shared read gateway and separate owner-local publication adapter.

Only the trusted front proxy selects the home/network fence. The owner adapter
is never routed publicly. Artifact metadata becomes authoritative when committed
to the shared Registry, and every delivery checks its serving manifest digest.
"""

from __future__ import annotations

import argparse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import html
import json
import mimetypes
import os
from pathlib import Path
import re
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .authority import NativeAuthority
from .policy import Policy, validate_audience
from .registry import Registry
from .sessions import Sessions

MAX_MANIFEST = 8 * 1024 * 1024


def validate_config(config, *, credential_uid=None):
    required = {
        "schema",
        "state",
        "binding_source",
        "relationship_store",
        "authority_source",
        "homes",
        "viewer_port",
        "owner_port",
        "content_public_url",
        "content_vpn_url",
    }
    if (
        not isinstance(config, dict)
        or set(config) != required
        or config["schema"] != "dm.resource-access.host/v1"
        or not isinstance(config["homes"], dict)
        or not 0 <= len(config["homes"]) <= 256
    ):
        raise ValueError("invalid_resource_access_configuration")

    def origin(url):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("home_requires_exact_https_origin")
        return parsed.netloc

    origins = {origin(config[key]) for key in ("content_public_url", "content_vpn_url")}
    if len(origins) != 2:
        raise ValueError("isolated_content_origins_required")
    for field in ("state", "binding_source", "relationship_store", "authority_source"):
        if not isinstance(config[field], str) or not Path(config[field]).is_absolute():
            raise ValueError("invalid_home_receiving_path")
    ports = [config[k] for k in ("viewer_port", "owner_port")]
    if (
        any(type(p) is not int or not 1024 <= p <= 65535 for p in ports)
        or len(set(ports)) != 2
    ):
        raise ValueError("separate_home_listener_ports_required")
    for reference, home in config["homes"].items():
        if (
            not isinstance(reference, str)
            or not re.fullmatch("[A-Za-z0-9:_-]{1,128}", reference)
            or not isinstance(home, dict)
            or set(home)
            != {
                "name",
                "owner_being_ref",
                "owner_revision",
                "public_url",
                "vpn_url",
                "backend",
                "owner_token_file",
                "gateway_token_file",
                "ring",
            }
            or not isinstance(home["name"], str)
            or not 1 <= len(home["name"]) <= 128
            or not isinstance(home["owner_being_ref"], str)
            or not home["owner_being_ref"]
            or not isinstance(home["owner_revision"], str)
            or not re.fullmatch("[a-f0-9]{64}", home["owner_revision"])
        ):
            raise ValueError("invalid_home_receiving_binding")
        for field in ("public_url", "vpn_url"):
            hostname = origin(home[field])
            if hostname in origins:
                raise ValueError("unique_home_content_origins_required")
            origins.add(hostname)
        for field in ("owner_token_file", "gateway_token_file"):
            if not isinstance(home[field], str) or not Path(home[field]).is_absolute():
                raise ValueError("invalid_home_receiving_path")
            if credential_uid is None:
                private_text(home[field])
            else:
                private_credential(home[field], uid=credential_uid)
        if not isinstance(home["ring"], list) or len(home["ring"]) > 256:
            raise ValueError("invalid_home_ring")
        for peer in home["ring"]:
            if (
                not isinstance(peer, dict)
                or set(peer) != {"name", "url"}
                or not isinstance(peer["name"], str)
            ):
                raise ValueError("invalid_home_ring")
            origin(peer["url"])
        Backend(home)
    return config


def private_credential(path, *, uid):
    """Check an operator-selected gateway owner's file without reading its key."""
    import stat
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1024):
            raise ValueError("private_home_credential_required")
    finally:
        os.close(descriptor)


def private_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        import stat

        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 1024
        ):
            raise ValueError("private_home_credential_required")
        return stream.read().strip()


class Backend:
    def __init__(self, home):
        self.home = home
        url = urlsplit(home["backend"])
        if (
            url.scheme != "http"
            or url.hostname != "127.0.0.1"
            or url.path not in ("", "/")
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("home_backend_must_be_loopback")

    def open(self, path, *, method="GET", byte_range=None):
        headers = {
            "Authorization": "Bearer " + private_text(self.home["gateway_token_file"])
        }
        if byte_range:
            headers["Range"] = byte_range

        # No redirects: an untrusted backend response must not disclose its key.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_):
                return None

        request = urllib.request.Request(
            self.home["backend"].rstrip("/") + path, method=method, headers=headers
        )
        return urllib.request.build_opener(NoRedirect).open(request, timeout=15)

    def state(self):
        with self.open("/_home/state") as response:
            data = response.read(MAX_MANIFEST + 1)
            if len(data) > MAX_MANIFEST:
                raise ValueError("home_manifest_too_large")
            return json.loads(data)


class Application:
    def __init__(self, config, authority, sessions, *, backends=None):
        self.config, self.homes, self.authority, self.sessions = (
            config,
            config["homes"],
            authority,
            sessions,
        )
        self.registry = Registry(sessions)
        self.policy = Policy(
            actor=authority.actor,
            paired_human=authority.paired_human,
            tribe_member=authority.tribe_member,
        )
        self.backends = backends or {
            ref: Backend(home) for ref, home in self.homes.items()
        }
        for reference, home in self.homes.items():
            self.registry.bind_home(reference, home["owner_being_ref"])
            if "owner_token_file" in home:
                self.sessions.register_owner(
                    home=reference,
                    actor=home["owner_being_ref"],
                    revision=home["owner_revision"],
                    token=private_text(home["owner_token_file"]),
                )
        self.locks = {ref: threading.RLock() for ref in self.homes}

    def identity(self, token, home, origin):
        row = self.sessions.resolve(token, home=home, origin=origin)
        return self.policy.current(row["actor"], row["revision"]) if row else None

    def publication(self, home):
        observed = self.backends[home].state()
        committed = self.registry.current(home, observed_state=observed)
        return (
            committed["state"]
            if committed and committed["owner"] == self.homes[home]["owner_being_ref"]
            else {"schema": 1, "entries": []}
        )

    def entries(self, home, subject, vpn=False):
        return [
            e
            for e in self.publication(home)["entries"]
            if self.policy.allows(e, home=home, subject=subject, dedicated_vpn=vpn)
        ]

    def selected(self, home, reference, version, subject, vpn=False):
        for current in self.entries(home, subject, vpn):
            if current["artifact_ref"] != reference:
                continue
            if version == "current":
                return current
            selected = self.registry.version(
                home=home, resource=reference, version=version
            )
            if selected and self.policy.allows(
                selected, home=home, subject=subject, dedicated_vpn=vpn
            ):
                return selected
        return None

    def owner(self, home, token, operation, payload):
        if home not in self.homes or not token:
            raise ValueError("home_owner_denied")
        receiving = self.homes[home]
        if not hmac.compare_digest(token, private_text(receiving["owner_token_file"])):
            raise ValueError("home_owner_denied")
        owner = self.authority.actor(receiving["owner_being_ref"])
        if (
            not owner
            or owner.kind != "being"
            or not owner.enabled
            or receiving.get("owner_revision") != owner.revision
            or not self.sessions.owner(token, home=home, subject=owner)
        ):
            raise ValueError("home_owner_binding_unavailable")
        if operation == "validate-audience":
            validate_audience(
                payload,
                known_actor=self.authority.actor,
                known_tribe=lambda ref: ref in self.authority.tribes(),
            )
            return {"status": "valid"}
        if operation == "sync":
            if payload:
                raise ValueError("home_sync_takes_no_manifest_from_client")
            with self.locks[home]:
                revision = self.registry.revision(home)
                state = self.backends[home].state()
                return self.registry.register(
                    home=home,
                    owner=owner.ref,
                    state=state,
                    expected_revision=revision,
                    known_actor=self.authority.actor,
                    known_tribe=lambda ref: ref in self.authority.tribes(),
                )
        if operation == "targets":
            if payload:
                raise ValueError("invalid_home_owner_request")
            return {
                "actors": [
                    {"ref": a.ref, "kind": a.kind, "name": a.name}
                    for a in self.authority.actors().values()
                ],
                "tribes": list(self.authority.tribes()),
                "homes": [
                    {"ref": ref, "name": h["name"], "public_url": h["public_url"]}
                    for ref, h in self.homes.items()
                ],
            }
        if operation == "reader-session":
            if set(payload) != {"origin"}:
                raise ValueError("invalid_home_reader_request")
            targets = [
                ref
                for ref, h in self.homes.items()
                if payload["origin"] in (h["public_url"], h["vpn_url"])
            ]
            if len(targets) != 1:
                raise ValueError("unknown_home_reader_target")
            return {
                "credential": self.sessions.issue(
                    home=targets[0], origin=payload["origin"], subject=owner
                )
            }
        if operation == "approve-browser":
            if set(payload) != {"home", "code"} or payload["home"] not in self.homes:
                raise ValueError("invalid_home_browser_approval")
            pair = self.authority.actor(self.authority.paired_human(home))
            if not pair or pair.kind != "human":
                raise ValueError("home_pairing_unavailable")
            # The credential of a pair can prove only its own human identity,
            # even when that browser is visiting a different owner's home.
            self.sessions.approve(
                home=payload["home"], code=payload["code"], subject=pair
            )
            return {"status": "approved"}
        if operation == "tribe-readers":
            if set(payload) != {
                "tribe",
                "expected_revision",
                "readers",
                "revoked",
                "expires_at_ms",
            }:
                raise ValueError("invalid_home_reader_roster")
            tribe = self.authority.tribes().get(payload["tribe"])
            if not tribe or tribe["founder_principal_id"] != owner.ref:
                raise ValueError("home_roster_founder_required")

            def known_human(ref):
                actor = self.authority.actor(ref)
                return actor and actor.enabled and actor.kind == "human"

            return self.registry.roster(
                tribe=payload["tribe"],
                founder=owner.ref,
                expected_revision=payload["expected_revision"],
                known_human=known_human,
                document={
                    k: payload[k] for k in ("readers", "revoked", "expires_at_ms")
                },
            )
        raise ValueError("unknown_home_owner_operation")


def audience_view(entry, home):
    """Already-authorized visitor projection: no recipients, local paths or history."""
    reference = entry["artifact_ref"]
    url = (
        entry["url"]
        if entry["kind"] == "link"
        else "/works/" + reference + "/current/" + quote(entry["entrypoint"])
    )
    return {
        **{
            k: entry[k]
            for k in (
                "id",
                "title",
                "summary",
                "kind",
                "revision",
                "version_ref",
                "updated_at",
                "visibility",
            )
            if k in entry
        },
        "resource_ref": "dm:resource:v1:" + reference,
        "url": url,
        "preview_url": "/view/" + reference if entry["kind"] == "artifact" else None,
    }


def render(home, works, subject, vpn):
    esc = html.escape
    cards = "".join(
        "<article><small>"
        + esc(e.get("visibility", ""))
        + "</small><h2>"
        + esc(e["title"])
        + "</h2><p>"
        + esc(e["summary"])
        + '</p><a href="'
        + esc(e["preview_url"] or e["url"], quote=True)
        + '">Explore ↗</a></article>'
        for e in reversed(works)
    )
    rings = "".join(
        '<a href="' + esc(r["url"], quote=True) + '">' + esc(r["name"]) + "</a>"
        for r in home.get("ring", [])
    )
    scope = (
        ("Signed in as " + subject.name)
        if subject
        else ("Dedicated VPN" if vpn else "Public view")
    )
    auth = (
        '<form method="post" action="/access/logout"><button>Sign out</button></form>'
        if subject
        else '<a href="/access">Sign in</a>'
    )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(home["name"])} · Home</title><link rel="stylesheet" href="/home.css"></head><body><main><nav><span>DAIMON MATRIX</span>{auth}</nav><header><svg viewBox="0 0 88 48" aria-hidden="true"><ellipse cx="44" cy="24" rx="41" ry="17"/><ellipse cx="44" cy="24" rx="22" ry="22"/><circle cx="44" cy="24" r="4"/></svg><small>{esc(scope)}</small><h1>{esc(home["name"])}</h1><p>A shared starting place for ideas, experiments and things we make.</p><a href="{esc(home["vpn_url"], quote=True)}">Dedicated VPN space ↗</a></header><section class="works">{cards or "<p>Room for what comes next. Selected work will appear here as it is shared.</p>"}</section><nav class="ring" aria-label="Tribe web-ring">{rings}</nav><footer>Only work selected for your current access is shown. This page does not indicate current daimon activity.</footer></main></body></html>'''.encode()


def preview(app, home, reference, version, subject, vpn, *, origin, parent_token):
    selected = app.selected(home, reference, version, subject, vpn)
    if not selected or selected["kind"] != "artifact":
        raise ValueError("preview_denied")
    current = next(
        e for e in app.entries(home, subject, vpn) if e["artifact_ref"] == reference
    )
    esc = html.escape
    content_origin = app.config[
        "content_vpn_url" if vpn else "content_public_url"
    ].rstrip("/")
    child = app.sessions.content_read(
        home=home,
        origin=origin,
        content_origin=content_origin,
        resource=reference,
        version=selected["version_ref"],
        subject=subject,
        parent_token=parent_token,
    )
    prefix = content_origin + "/r/" + child + "/"
    source = prefix + quote(selected["entrypoint"])
    mime = mimetypes.guess_type(selected["entrypoint"])[0] or "application/octet-stream"
    if mime.startswith("image/") and mime != "image/svg+xml":
        display = (
            '<img class="media" src="'
            + esc(source, quote=True)
            + '" alt="'
            + esc(selected["title"], quote=True)
            + '">'
        )
    elif mime.startswith("audio/") or mime.startswith("video/"):
        tag = mime.split("/")[0]
        display = (
            "<"
            + tag
            + ' class="media" controls preload="metadata" src="'
            + esc(source, quote=True)
            + '"></'
            + tag
            + ">"
        )
    else:
        display = (
            '<iframe class="preview" sandbox="allow-scripts" src="'
            + esc(source, quote=True)
            + '" title="'
            + esc(selected["title"], quote=True)
            + '"></iframe>'
        )
    versions = ['<li><a href="/view/' + reference + '">Current version</a></li>']
    for previous in reversed(current.get("versions", [])):
        if app.policy.allows(previous, home=home, subject=subject, dedicated_vpn=vpn):
            versions.append(
                '<li><a href="/view/'
                + reference
                + "?version="
                + previous["version_ref"]
                + '">'
                + esc(previous.get("updated_at", "Earlier version"))
                + "</a></li>"
            )
    files = "".join(
        '<li><a download href="'
        + prefix
        + quote(filename)
        + '">'
        + esc(filename)
        + "</a></li>"
        for filename in selected["files"]
    )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(selected["title"])} · {esc(app.homes[home]["name"])}</title><link rel="stylesheet" href="/home.css"></head><body><main><a href="/">← Home</a><header><small>{esc(selected["visibility"])} · {"Current version" if version == "current" else "Earlier version"}</small><h1>{esc(selected["title"])}</h1><p>{esc(selected["summary"])}</p><a href="{esc(source, quote=True)}">Open selected work ↗</a></header>{display}<details><summary>Selected files</summary><ul>{files}</ul></details><details><summary>Versions available to you</summary><ul>{"".join(versions)}</ul></details></main></body></html>'''.encode()


def handler(app, *, owner=False):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def log_message(self, *_):
            pass

        def end_headers(self):
            self._headers_sent = True
            super().end_headers()

        def respond(self, status, body, kind="application/json", cookies=()):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # Browser form POSTs under no-referrer serialize their Origin as
            # null. Keep same-origin proofs while disclosing no cross-site URL.
            self.send_header("Referrer-Policy", "same-origin")
            frames = " ".join(
                app.config.get(k, "") for k in ("content_public_url", "content_vpn_url")
            )
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; frame-src "
                + frames
                + "; img-src 'self' "
                + frames
                + "; media-src "
                + frames
                + "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def context(self):
            home = self.headers.get("X-Daimon-Home", "")
            network = self.headers.get("X-Daimon-Vpn", "")
            if not home:
                field = "vpn_url" if network == "1" else "public_url"
                matches = [
                    ref
                    for ref, row in app.homes.items()
                    if urlsplit(row[field]).netloc == self.headers.get("Host", "")
                ]
                home = matches[0] if len(matches) == 1 else ""
            if home not in app.homes:
                raise ValueError("unknown_home")
            origin = app.homes[home][
                "vpn_url" if network == "1" else "public_url"
            ].rstrip("/")
            supplied = self.headers.get("Origin")
            if supplied is not None and supplied != origin:
                raise ValueError("cross_origin_home_request")
            host = self.headers.get("Host", "")
            if host != urlsplit(origin).netloc:
                raise ValueError("home_origin_mismatch")
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies.get("__Host-home")
            # Bearer credentials use the same read-only, exact-origin sessions.
            authorization = self.headers.get("Authorization", "")
            token = (
                authorization[7:]
                if authorization.startswith("Bearer ")
                else (token.value if token else "")
            )
            subject = app.identity(token, home, origin)
            return home, origin, subject, network == "1", cookies, token

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if owner:
                self.respond(404, {})
                return
            try:
                content_origins = {
                    urlsplit(app.config[k]).netloc: app.config[k].rstrip("/")
                    for k in ("content_public_url", "content_vpn_url")
                    if app.config.get(k)
                }
                if self.headers.get("Host", "") in content_origins:
                    return self.content(content_origins[self.headers["Host"]])
                home, origin, subject, vpn, cookies, parent_token = self.context()
                path = urlsplit(self.path).path
                if path == "/":
                    self.respond(
                        200,
                        render(
                            app.homes[home],
                            [
                                audience_view(e, home)
                                for e in app.entries(home, subject, vpn)
                            ],
                            subject,
                            vpn,
                        ),
                        "text/html; charset=utf-8",
                    )
                elif path == "/catalog.json":
                    self.respond(
                        200,
                        {
                            "home_ref": home,
                            "access_contract": "dm.resource-access/v1",
                            "entries": [
                                audience_view(e, home)
                                for e in app.entries(home, subject, vpn)
                            ],
                        },
                    )
                elif path.startswith("/view/"):
                    reference = path.removeprefix("/view/")
                    if not re.fullmatch("[a-f0-9]{32}", reference):
                        raise ValueError("invalid_resource_reference")
                    query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                    if (
                        set(query) - {"version"}
                        or len(query.get("version", ["current"])) != 1
                    ):
                        raise ValueError("invalid_version_query")
                    version = query.get("version", ["current"])[0]
                    self.respond(
                        200,
                        preview(
                            app,
                            home,
                            reference,
                            version,
                            subject,
                            vpn,
                            origin=origin,
                            parent_token=parent_token,
                        ),
                        "text/html; charset=utf-8",
                    )
                elif path == "/home.css":
                    self.respond(
                        200,
                        (Path(__file__).parent / "assets" / "home.css").read_bytes(),
                        "text/css",
                    )
                elif path.startswith("/fonts/"):
                    filename = path.removeprefix("/fonts/")
                    if filename not in ("space-grotesk-latin.woff2",):
                        raise ValueError("unknown_asset")
                    self.respond(
                        200,
                        (
                            Path(__file__).resolve().parents[2]
                            / "clusterd"
                            / "assets"
                            / "fonts"
                            / filename
                        ).read_bytes(),
                        "font/woff2",
                    )
                elif path == "/access":
                    request, proof = app.sessions.request(home=home, origin=origin)
                    code = request["code"]
                    home_name = html.escape(app.homes[home]["name"])
                    body = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><title>Sign in · {home_name}</title><main><a href="/">← Home</a><h1>Open your shared space</h1><p>Send this code to your own daimon in your existing conversation:</p><p><strong>{code}</strong></p><p>Ask them to approve your browser for {home_name}. The code expires in 15 minutes. Approval proves who you are; each resource keeps its selected audience.</p><form method="post" action="/access/claim"><input name="code" type="hidden" value="{code}"><button>Continue after approval</button></form></main></html>'''.encode()
                    self.respond(
                        200,
                        body,
                        "text/html; charset=utf-8",
                        cookies=(
                            f"__Host-home-proof={proof}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=900",
                        ),
                    )
                elif path.startswith("/works/") or path.startswith("/artifacts/"):
                    parts = [unquote(p) for p in path.split("/")]
                    if path.startswith("/artifacts/"):
                        if len(parts) < 4:
                            raise ValueError("invalid_artifact_path")
                        selected = next(
                            (
                                e
                                for e in app.entries(home, subject, vpn)
                                if e["id"] == parts[2] and e["kind"] == "artifact"
                            ),
                            None,
                        )
                        reference, version, files = (
                            (selected["artifact_ref"] if selected else ""),
                            "current",
                            parts[3:],
                        )
                    else:
                        if len(parts) < 5:
                            raise ValueError("invalid_artifact_path")
                        reference, version, files = parts[2], parts[3], parts[4:]
                        selected = app.selected(home, reference, version, subject, vpn)
                    if (
                        not selected
                        or selected["kind"] != "artifact"
                        or "/".join(files) not in selected["files"]
                        or any(
                            p in ("", ".", "..") or "/" in p or "\\" in p or "\0" in p
                            for p in files
                        )
                    ):
                        raise ValueError("artifact_denied")
                    # Never follow a mutable current pointer after authorization.
                    backend_path = (
                        "/_home/artifact/"
                        + reference
                        + "/"
                        + selected["version_ref"]
                        + "/"
                        + "/".join(quote(p, safe="") for p in files)
                    )
                    with app.backends[home].open(
                        backend_path,
                        method=self.command,
                        byte_range=self.headers.get("Range"),
                    ) as response:
                        if (
                            response.headers.get("X-Home-Version")
                            != selected["version_ref"]
                        ):
                            raise ValueError("home_delivery_version_mismatch")
                        self.send_response(response.status)
                        for name in (
                            "Content-Type",
                            "Content-Length",
                            "Content-Range",
                            "Accept-Ranges",
                        ):
                            if response.headers.get(name):
                                self.send_header(name, response.headers[name])
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("Referrer-Policy", "no-referrer")
                        content_type = response.headers.get("Content-Type", "").split(
                            ";"
                        )[0]
                        if content_type in ("text/html", "image/svg+xml"):
                            # Active content executes only on the cookie-free
                            # isolated viewer, never on the authenticated home.
                            self.send_header("Content-Disposition", "attachment")
                            self.send_header(
                                "Content-Security-Policy", "default-src 'none'; sandbox"
                            )
                        else:
                            self.send_header(
                                "Content-Security-Policy", "default-src 'none'; sandbox"
                            )
                        self.end_headers()
                        if self.command != "HEAD":
                            while block := response.read(256 * 1024):
                                self.wfile.write(block)
                else:
                    self.respond(404, {})
            except (ValueError, KeyError, OSError, urllib.error.URLError):
                if not getattr(self, "_headers_sent", False):
                    self.respond(404, {})
                else:
                    self.close_connection = True

        def content(self, origin):
            """One artifact child context, without home cookies or login APIs."""
            supplied = self.headers.get("Origin")
            if supplied not in (None, "null", origin):
                raise ValueError("content_origin_denied")
            parts = urlsplit(self.path).path.split("/")
            if len(parts) < 4 or parts[1] != "r":
                raise ValueError("invalid_content_route")
            ticket = parts[2]
            row = app.sessions.resolve_content(ticket, content_origin=origin)
            if not row:
                raise ValueError("content_read_denied")
            subject = (
                app.policy.current(row["actor"], row["revision"])
                if row["actor"]
                else None
            )
            if row["actor"] and not subject:
                raise ValueError("content_actor_changed")
            vpn = self.headers.get("X-Daimon-Vpn") == "1"
            selected = app.selected(
                row["home"], row["resource"], row["version"], subject, vpn
            )
            files = [unquote(p) for p in parts[3:]]
            if (
                not selected
                or selected["kind"] != "artifact"
                or "/".join(files) not in selected["files"]
                or any(
                    p in ("", ".", "..") or "/" in p or "\\" in p or "\0" in p
                    for p in files
                )
            ):
                raise ValueError("content_file_denied")
            path = (
                "/_home/artifact/"
                + row["resource"]
                + "/"
                + selected["version_ref"]
                + "/"
                + "/".join(quote(p, safe="") for p in files)
            )
            with app.backends[row["home"]].open(
                path, method=self.command, byte_range=self.headers.get("Range")
            ) as response:
                if response.headers.get("X-Home-Version") != selected["version_ref"]:
                    raise ValueError("content_delivery_version_mismatch")
                self.send_response(response.status)
                for name in (
                    "Content-Type",
                    "Content-Length",
                    "Content-Range",
                    "Accept-Ranges",
                ):
                    if response.headers.get(name):
                        self.send_header(name, response.headers[name])
                prefix = origin + "/r/" + ticket + "/"
                # Opaque-origin modules, fonts and own JSON use only this
                # artifact-scoped context. Null never authenticates a home.
                self.send_header(
                    "Access-Control-Allow-Origin",
                    "null" if supplied == "null" else origin,
                )
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' "
                    + prefix
                    + "; style-src 'unsafe-inline' "
                    + prefix
                    + "; font-src "
                    + prefix
                    + "; img-src data: blob: "
                    + prefix
                    + "; media-src data: blob: "
                    + prefix
                    + "; connect-src "
                    + prefix
                    + "; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors "
                    + app.homes[row["home"]]["public_url"]
                    + " "
                    + app.homes[row["home"]]["vpn_url"],
                )
                self.end_headers()
                if self.command != "HEAD":
                    while block := response.read(256 * 1024):
                        self.wfile.write(block)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 65536:
                    raise ValueError("invalid_request_size")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("incomplete_home_request")
                if owner:
                    parts = urlsplit(self.path).path.split("/")
                    if len(parts) != 4 or parts[1] != "owner":
                        raise ValueError("unknown_owner_route")
                    token = self.headers.get("Authorization", "")
                    if not token.startswith("Bearer "):
                        raise ValueError("home_owner_denied")
                    payload = json.loads(data)
                    if not isinstance(payload, dict):
                        raise ValueError("invalid_owner_payload")
                    self.respond(
                        200, app.owner(unquote(parts[2]), token[7:], parts[3], payload)
                    )
                    return
                home, origin, subject, vpn, cookies, token = self.context()
                if self.headers.get("Origin") != origin:
                    raise ValueError("home_post_requires_exact_origin")
                path = urlsplit(self.path).path
                if path == "/access/logout":
                    app.sessions.revoke(home=home, token=token)
                    self.respond(
                        200,
                        {"status": "signed-out"},
                        cookies=(
                            "__Host-home=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
                        ),
                    )
                elif path == "/access/claim":
                    from urllib.parse import parse_qs

                    payload = parse_qs(data.decode(), strict_parsing=True)
                    if (
                        set(payload) != {"code"}
                        or len(payload["code"]) != 1
                        or not cookies.get("__Host-home-proof")
                    ):
                        raise ValueError("invalid_browser_claim")
                    status, credential = app.sessions.claim(
                        home=home,
                        origin=origin,
                        code=payload["code"][0],
                        proof=cookies["__Host-home-proof"].value,
                        current_actor=app.policy.current,
                    )
                    if credential:
                        self.respond(
                            200,
                            b'<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><main><h1>Signed in</h1><a href="/">Open home</a></main></html>',
                            "text/html",
                            cookies=(
                                f"__Host-home={credential}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800",
                            ),
                        )
                    else:
                        self.respond(200, status)
                else:
                    self.respond(404, {})
            except (ValueError, KeyError, OSError, urllib.error.URLError):
                self.respond(403, {"status": "denied"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    from daimon_matrix.messaging_config import protected_read

    config = validate_config(json.loads(protected_read(Path(args.config))))
    sessions = Sessions(Path(config["state"]))
    registry = Registry(sessions)
    authority = NativeAuthority(
        Path(config["binding_source"]),
        Path(config["relationship_store"]),
        config["homes"],
        authority_source=Path(config["authority_source"]),
        human_rosters=registry.rosters,
    )
    app = Application(config, authority, sessions)
    servers = [
        ThreadingHTTPServer(("127.0.0.1", config[key]), handler(app, owner=owner))
        for key, owner in (("viewer_port", False), ("owner_port", True))
    ]
    for server in servers:
        server.daemon_threads = True
    threading.Thread(target=servers[1].serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    finally:
        for server in servers:
            server.server_close()


if __name__ == "__main__":
    main()
