"""One human credential registry, exact home origins, existing read sessions.

Credentials identify a current human; they never create resource grants. A
read-only token cannot enroll keys. Enrollment/management requires a recent
approved browser-code ceremony or recent verified passkey browser login.
"""

from contextlib import closing
import base64
import hashlib
import hmac
import json
import sqlite3
import re
from urllib.parse import urlsplit

from clusterd.auth import hash_token
from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttachment,
)


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(value):
    if not isinstance(value, str) or len(value) > 32768:
        raise ValueError("invalid_passkey_encoding")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid_passkey_encoding") from exc
    if encode(raw) != value:
        raise ValueError("noncanonical_passkey_encoding")
    return raw


class Passkeys:
    def __init__(self, app, rp_id):
        self.app, self.sessions, self.rp_id = app, app.sessions, rp_id
        if not isinstance(rp_id, str) or not re.fullmatch(
            r"[a-z0-9]+(?:[.-][a-z0-9]+)+", rp_id
        ):
            raise ValueError("invalid_passkey_rp_id")
        # Fixed receiving config, never derived from Host or a suffix wildcard.
        for home in app.homes.values():
            hostname = urlsplit(home["public_url"]).hostname
            if not (hostname == rp_id or hostname.endswith("." + rp_id)):
                raise ValueError("passkey_home_outside_rp")
        with closing(self.sessions.connect()) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS passkeys(
              id TEXT PRIMARY KEY, actor TEXT NOT NULL, revision TEXT NOT NULL,
              handle TEXT NOT NULL, public_key BLOB NOT NULL, counter INTEGER NOT NULL,
              label TEXT NOT NULL, created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS passkey_challenges(
              id TEXT PRIMARY KEY, home TEXT NOT NULL, origin TEXT NOT NULL,
              mode TEXT NOT NULL, proof TEXT NOT NULL, challenge BLOB NOT NULL,
              parent TEXT, actor TEXT, revision TEXT, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS passkey_sessions(
              digest TEXT PRIMARY KEY, credential TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS passkey_users(
              actor TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE);
            """)

    def trusted(self, home, origin):
        if getattr(self.app, 'sso', None) and home == self.app.sso.context:
            if origin != self.app.sso.origin:
                raise ValueError('passkeys_require_login_origin')
            return
        if origin != self.app.homes[home]["public_url"]:
            raise ValueError("passkeys_require_public_home_origin")

    def elevated(self, db, home, origin, token, browser_proof):
        now = self.sessions.now(db)
        row = db.execute(
            "SELECT * FROM sessions WHERE digest=?", (hash_token(token),)
        ).fetchone()
        subject = (
            self.app.policy.current(row["actor"], row["revision"]) if row else None
        )
        if (
            not subject
            or subject.kind != "human"
            or not row
            or row["home"] != home
            or row["origin"] != origin
            or not self.sessions.active(db, row, now, max_age=900)
            or now - row["created"] > 900
        ):
            raise ValueError("fresh_browser_sign_in_required")
        key = db.execute(
            """SELECT p.* FROM passkey_sessions s JOIN passkeys p
                         ON p.id=s.credential WHERE s.digest=? AND p.revoked=0""",
            (hash_token(token),),
        ).fetchone()
        if key and (key["actor"], key["revision"]) == (subject.ref, subject.revision):
            return subject
        request = db.execute(
            """SELECT * FROM requests WHERE proof=? AND home=? AND
            origin=? AND claimed=1 AND expires>? AND actor=? AND revision=?""",
            (
                hash_token(browser_proof),
                home,
                origin,
                now,
                subject.ref,
                subject.revision,
            ),
        ).fetchone()
        if request:
            material = (
                b"dm.home-browser-session/v1\0"
                + home.encode()
                + b"\0"
                + origin.encode()
                + b"\0"
                + request["code"].encode()
                + b"\0"
                + browser_proof.encode()
            )
            if hmac.compare_digest(encode(hashlib.sha256(material).digest()), token):
                return subject
        raise ValueError("fresh_browser_sign_in_required")

    def begin(self, *, home, origin, mode, token="", browser_proof=""):
        self.trusted(home, origin)
        if mode not in ("register", "login"):
            raise ValueError("unknown_passkey_ceremony")
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                now = self.sessions.now(db)
                db.execute("DELETE FROM passkey_challenges WHERE expires<=?", (now,))
                if (
                    db.execute(
                        "SELECT count(*) FROM passkey_challenges WHERE home=?", (home,)
                    ).fetchone()[0]
                    >= 100
                ):
                    raise ValueError("passkey_requests_busy")
                subject = (
                    self.elevated(db, home, origin, token, browser_proof)
                    if mode == "register"
                    else None
                )
                if (
                    subject
                    and db.execute(
                        "SELECT count(*) FROM passkeys WHERE actor=? AND revoked=0",
                        (subject.ref,),
                    ).fetchone()[0]
                    >= 20
                ):
                    raise ValueError("passkey_limit_reached")
                challenge = decode(self.sessions.secret())
                nonce, proof = self.sessions.secret(), self.sessions.secret()
                db.execute(
                    "INSERT INTO passkey_challenges VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        nonce,
                        home,
                        origin,
                        mode,
                        hash_token(proof),
                        challenge,
                        hash_token(token) if subject else None,
                        subject.ref if subject else None,
                        subject.revision if subject else None,
                        now + 300,
                    ),
                )
                if subject:
                    db.execute(
                        "INSERT OR IGNORE INTO passkey_users VALUES(?,?)",
                        (subject.ref, self.sessions.secret()),
                    )
                    handle = decode(
                        db.execute(
                            "SELECT handle FROM passkey_users WHERE actor=?",
                            (subject.ref,),
                        ).fetchone()["handle"]
                    )
                    excluded = [
                        PublicKeyCredentialDescriptor(id=decode(r["id"]))
                        for r in db.execute(
                            "SELECT id FROM passkeys WHERE actor=? AND revoked=0",
                            (subject.ref,),
                        )
                    ]
                    options = generate_registration_options(
                        rp_id=self.rp_id,
                        rp_name="Daimon Matrix",
                        user_id=handle,
                        user_name=subject.name,
                        user_display_name=subject.name,
                        challenge=challenge,
                        timeout=120000,
                        exclude_credentials=excluded,
                        authenticator_selection=AuthenticatorSelectionCriteria(
                            resident_key=ResidentKeyRequirement.REQUIRED,
                            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                            user_verification=UserVerificationRequirement.REQUIRED,
                        ),
                    )
                else:
                    options = generate_authentication_options(
                        rp_id=self.rp_id,
                        challenge=challenge,
                        timeout=120000,
                        user_verification=UserVerificationRequirement.REQUIRED,
                    )
                db.commit()
                return {
                    "nonce": nonce,
                    "options": json.loads(options_to_json(options)),
                }, proof
            except BaseException:
                db.rollback()
                raise

    def finish(
        self,
        *,
        home,
        origin,
        mode,
        nonce,
        proof,
        credential,
        token="",
        browser_proof="",
        label="My phone",
    ):
        self.trusted(home, origin)
        if not isinstance(credential, dict):
            raise ValueError("invalid_passkey_credential")
        if not isinstance(nonce, str) or len(nonce) != 43 or not isinstance(proof, str):
            raise ValueError("invalid_passkey_proof")
        try:
            client = json.loads(decode(credential["response"]["clientDataJSON"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("invalid_passkey_client_data") from exc
        if (
            not isinstance(client, dict)
            or client.get("crossOrigin", False) is not False
            or client.get("topOrigin") is not None
        ):
            raise ValueError("cross_origin_passkey_denied")
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM passkey_challenges WHERE id=?", (nonce,)
                ).fetchone()
                if (
                    not row
                    or row["home"] != home
                    or row["origin"] != origin
                    or row["mode"] != mode
                    or row["expires"] <= self.sessions.now(db)
                    or not hmac.compare_digest(row["proof"], hash_token(proof))
                ):
                    raise ValueError("passkey_challenge_unavailable")
                # Verified challenge consumption, counter update and session
                # issuance share one transaction; no credential/session race.
                db.execute("DELETE FROM passkey_challenges WHERE id=?", (nonce,))
                if mode == "register":
                    subject = self.elevated(db, home, origin, token, browser_proof)
                    if (
                        db.execute(
                            "SELECT count(*) FROM passkeys WHERE actor=? AND revoked=0",
                            (subject.ref,),
                        ).fetchone()[0]
                        >= 20
                    ):
                        raise ValueError("passkey_limit_reached")
                    if row["parent"] != hash_token(token) or (
                        row["actor"],
                        row["revision"],
                    ) != (subject.ref, subject.revision):
                        raise ValueError("passkey_enrollment_changed")
                    verified = verify_registration_response(
                        credential=credential,
                        expected_challenge=row["challenge"],
                        expected_rp_id=self.rp_id,
                        expected_origin=origin,
                        require_user_verification=True,
                    )
                    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80:
                        raise ValueError("invalid_passkey_label")
                    db.execute(
                        "INSERT INTO passkeys VALUES(?,?,?,?,?,?,?,?,0)",
                        (
                            encode(verified.credential_id),
                            subject.ref,
                            subject.revision,
                            db.execute(
                                "SELECT handle FROM passkey_users WHERE actor=?",
                                (subject.ref,),
                            ).fetchone()["handle"],
                            verified.credential_public_key,
                            verified.sign_count,
                            label.strip(),
                            self.sessions.now(db),
                        ),
                    )
                    db.commit()
                    return {"status": "registered"}, None
                if mode != "login":
                    raise ValueError("unknown_passkey_ceremony")
                identifier = encode(decode(credential["id"]))
                key = db.execute(
                    "SELECT * FROM passkeys WHERE id=? AND revoked=0", (identifier,)
                ).fetchone()
                if not key:
                    raise ValueError("unknown_passkey")
                subject = self.app.policy.current(key["actor"], key["revision"])
                if not subject or subject.kind != "human":
                    raise ValueError("passkey_identity_changed")
                if credential["response"].get("userHandle") != key["handle"]:
                    raise ValueError("passkey_user_handle_mismatch")
                verified = verify_authentication_response(
                    credential=credential,
                    expected_challenge=row["challenge"],
                    expected_rp_id=self.rp_id,
                    expected_origin=origin,
                    credential_public_key=key["public_key"],
                    credential_current_sign_count=key["counter"],
                    require_user_verification=True,
                )
                db.execute(
                    "UPDATE passkeys SET counter=? WHERE id=?",
                    (verified.new_sign_count, identifier),
                )
                session = self.sessions._issue(db, home, origin, subject, 7 * 86400)
                db.execute(
                    "INSERT INTO passkey_sessions VALUES(?,?)",
                    (hash_token(session), identifier),
                )
                db.commit()
                return {"status": "signed-in"}, session
            except (WebAuthnException, sqlite3.IntegrityError) as exc:
                db.rollback()
                raise ValueError("passkey_verification_failed") from exc
            except BaseException:
                db.rollback()
                raise

    def list(self, subject):
        if not subject or subject.kind != "human":
            raise ValueError("human_browser_required")
        with closing(self.sessions.connect()) as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT id,label,created FROM passkeys "
                    "WHERE actor=? AND revision=? AND revoked=0 ORDER BY created",
                    (subject.ref, subject.revision),
                )
            ]

    def revoke(self, *, home, origin, token, browser_proof, identifier):
        self.trusted(home, origin)
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                subject = self.elevated(db, home, origin, token, browser_proof)
                count = db.execute(
                    "UPDATE passkeys SET revoked=1 WHERE id=? AND actor=? AND revision=?",
                    (identifier, subject.ref, subject.revision),
                ).rowcount
                if count != 1:
                    raise ValueError("passkey_not_owned")
                db.execute(
                    "UPDATE sessions SET revoked=1 WHERE digest IN "
                    "(SELECT digest FROM passkey_sessions WHERE credential=?)",
                    (identifier,),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise
