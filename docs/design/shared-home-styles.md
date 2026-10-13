# Shared style consumption — authority boundary

Roadmap: Cluster214/222; cross-system design proposal:
https://github.com/AlterMundi/daimon-matrix/issues/328.

## Actual source and candidate state

Homemaker's owning repository is AnnieScigliano/homemaker, inspected read-only
at checkpoint671c846. The published version0.5.1 remains separate from the
contribution candidate. The current CompAII GitHub account cannot access that
private repository; source was inspected through its existing local body.
No owner credentials or private sessions were copied. Oliva's original checkout
and production publication are unchanged.

The contribution candidate extracts an appearance projection **in Homemaker**,
using its existing `readRecipe`, catalogs and font roles. Its existing renderer
uses those same roles. The projection advertises palette, font roles, spacing
and corners, not a complete layout transformation. Richer templates, imagery,
widgets and composition remain owned by the actual creator and site authors.
Recipe keywords, personal preview contents and arbitrary CSS are excluded from
this projection. Earlier recipe compatibility is retained by the creator itself.

## One authority, independent consumers

Canonical recipes/design identities, versions, provenance, defaults and explicit
surface choices belong to the Homemaker component. Cluster's `StyleConsumer`
delegates resolution and performs no design writes, no recipe imports and no
local authoritative selection persistence. A provider must be explicitly wired
and qualified before deployment; the standalone prototype is not a live provider.

Receiving authentication/policy resolves current Matrix being references and
existing human pairing, not hostnames or presentation labels. The consumer
chooses a stable author-being scope. A human's personal context is supplied only
when this surface explicitly supports it; another pair's visitor preference
cannot silently repaint authored public sites. An explicit surface selection
wins over either kind of default. Followed design revisions and pinned revisions
are different choices, independent of software package versions.

The proposed backend receives action-scoped authorization from the actual
identity/access adapter; it creates no accounts, sessions, signing custody or
listeners. A read cookie by itself is not permission to publish designs. Keep
private recipes/keywords/default histories out of public lists and unauthorized
projections. Publishing a new recipe does not publish private earlier revisions;
restricting the current design also protects its earlier public revision URLs.
Write with CAS and stable operation IDs, rechecking authorization before replay.

## Foreground presentation and isolated work

A registered trusted home consumer requests only its resolved appearance for the
exact authorized home/resource. It validates a bounded palette/font/density/
corner projection and applies semantic CSS hooks while retaining the authored
layout. The frame receives appearance only from its actual trusted parent, never
credentials, actor references or an editable preference store. Unsafe CSS,
network URLs, sibling messages and null-origin senders cannot change styles.
Explicitly authored work may opt out through its own style declaration.

The current consumer candidate refreshes on opening/resuming and at most once
per15seconds while visible; same-origin invalidation can refresh immediately.
Requests have a10second fetch/body deadline. Hidden/closed pages cancel their timer, abort in-flight requests and discard late responses. This is browser presentation traffic,
not Matrix inbox polling or a model wakeup. Retain the last valid presentation
on unavailable/malformed responses and the local accessible fallback when no
shared selection applies. No offline style cache adds artifact access rights.

Consumers need source-owned font assets/license integration when using the
creator's named font families; normal CSS fallbacks keep text readable until
that explicit asset route is qualified. Do not claim font/layout fidelity merely
because palette variables changed. Images and rich layout adapters must declare
and test their own supported subset.

## Remaining coordination before live adoption

Oliva/Ani and CompAII reconcile the actual creator's current plan and canonical
resolver/editor contract under Matrix328. The source contribution and gateway
consumer candidate remain separate from deployment. No new preference authority
may be introduced at the gateway. Link the owning source/version, qualify the
existing fingerprint/pairing/Matrix authorization adapter, wire only that provider,
and demonstrate one home and an existing Telecodex Mini App sharing a default,
explicit exceptions, followed edits and unavailable/revoked-source fallbacks.
Physical Telegram acceptance remains separate from browser qualification.

Preserve current artifacts/grants/recipe exports, body/native sessions, passkeys,
source history and compatible rollback. Automatic package updates and autonomous
attention stay outside this increment.
