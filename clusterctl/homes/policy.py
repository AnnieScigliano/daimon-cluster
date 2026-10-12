"""Independent artifact audiences evaluated against current authority.

Identity providers and tribe evidence stay outside this policy. A browser
session establishes its subject, never a frozen membership or artifact grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping


AUDIENCES = frozenset({"public", "vpn", "tribe", "individual", "human"})


@dataclass(frozen=True)
class Actor:
    ref: str
    kind: str
    revision: str
    name: str
    enabled: bool = True

    def __post_init__(self):
        if (
            self.kind not in {"human", "being"}
            or not self.ref
            or not self.revision
            or not self.name
            or type(self.enabled) is not bool
        ):
            raise ValueError("invalid_home_actor")


def validate_audience(
    entry: Mapping,
    *,
    known_actor: Callable[[str], Actor | None],
    known_tribe: Callable[[str], bool],
) -> None:
    audience = entry.get("visibility")
    if audience not in AUDIENCES:
        raise ValueError("invalid_home_audience")
    recipients, tribes = entry.get("recipients", []), entry.get("tribes", [])
    for values in (recipients, tribes):
        if (
            not isinstance(values, list)
            or len(values) > 64
            or any(not isinstance(v, str) or not v or len(v) > 256 for v in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("invalid_home_audience_set")
    if audience == "individual":
        if not recipients or tribes or any(not known_actor(r) for r in recipients):
            raise ValueError("unresolved_home_recipient")
    elif audience == "tribe":
        if not tribes or recipients or any(not known_tribe(t) for t in tribes):
            raise ValueError("unresolved_home_tribe")
    elif recipients or tribes:
        raise ValueError("unexpected_home_audience_set")


class Policy:
    def __init__(
        self,
        *,
        actor: Callable[[str], Actor | None],
        paired_human: Callable[[str], str | None],
        tribe_member: Callable[[str, str, Actor], bool],
    ):
        self.actor = actor
        self.paired_human = paired_human
        self.tribe_member = tribe_member

    def current(self, ref: str, revision: str) -> Actor | None:
        subject = self.actor(ref)
        if not subject or not subject.enabled or subject.revision != revision:
            return None
        return subject

    def allows(
        self,
        entry: Mapping,
        *,
        home: str,
        subject: Actor | None,
        dedicated_vpn: bool = False,
    ) -> bool:
        audience = entry.get("visibility")
        if audience == "public":
            return True
        if audience == "vpn":
            return dedicated_vpn
        if not subject or not subject.enabled:
            return False
        current = self.current(subject.ref, subject.revision)
        if not current:
            return False
        if audience == "human":
            return current.kind == "human" and current.ref == self.paired_human(home)
        if audience == "individual":
            return current.ref in entry.get("recipients", [])
        if audience == "tribe":
            return any(
                self.tribe_member(home, tribe, current)
                for tribe in entry.get("tribes", [])
            )
        return False
