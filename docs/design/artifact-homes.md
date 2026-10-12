# Artifact homes — access and delivery contract

Owning epic: AlterMundi/daimon-matrix#318; Skills#46/#51/#52 and Cluster#199.
Design alignment reviewed against Daimon Field D003 and the human-selected
Resonancia study: cyan orbital orientation, segmented instruments, licensed
self-hosted Space Grotesk, semantic amber/cyan/mauve and readable mobile controls.
The approved direction is distinct from accepting future spatial/group behavior.

## Shared starting place and access authority

Each human/daimon pair uses its home for selected ideas, files and experiments
before creating project-specific infrastructure. Resource identity and grants
survive later URL or placement changes. The normative shared contract is
[Matrix resource access](https://github.com/AlterMundi/daimon-matrix/blob/main/docs/resource-access.md).
One revisioned registry and evaluator serve all homes; local publisher metadata
is a submitted projection, not a separate access authority. Content remains in
its existing owner-local store. Serving requires an exact match with the
registered projection; incomplete publication synchronization fails closed.

## Ownership

Matrix owns verified being identities, current signed tribe history and pairing
source bindings. Cluster owns the home access service, placement and delivery
fences. Skills owns the portable publication contract and optional artifact
helper. The access service issues only home-scoped **read** sessions; neither
Cluster execution scopes, Matrix custody nor Nexus table cookies are inherited.

The binding adapter reads the current signed public catalogs and the existing
operator-selected human/bot contacts, without reading their bearer token files.
It validates the exact active body origin. Native being membership is evaluated
through `RelationshipStore.authorization_view()` with actual event/card
verification, preserving terminal decisions across forks and clock rollback.
Missing current evidence denies identity-dependent grants. No runtime is loaded,
relationship initialized/ingested, inbox consumed or model started.

Human pairing is not native tribe membership. A verified tribe founder may
explicitly accept a shared human-reader roster, recording its authority,
revision, founder reference, readers, revocation and optional expiry. All homes
consult that same roster. This is a resource-access projection, not a new Matrix
membership event. It starts empty; contacts do not populate it automatically.

## Five independent audiences

Public is readable anonymously; dedicated VPN is readable through its observed
network fence. Tribe grants require current being membership or the explicit
human-reader roster. Individual grants select resolved stable subjects. The
paired-human grant resolves the current pairing on every request. These are
independent audience sets, never cascading roles. A session identifies its
subject and binding revision; it retains no membership decision.

All catalogs, previews, direct files, dependencies, HEAD and media ranges use
the same current grant. Unknown/denied object paths return404 without revealing
private names. HTML views and JSON projections agree; public views have no private
titles, counts, actor/recipient sets or source paths. No state-changing browser
operation selects an actor or approves a grant.

## Browser identity

Reuse the existing request/proof/approval mechanism through a distinct home
contract. An expiring public code correlates a browser request; its HttpOnly
proof cookie is required to redeem an owner-local approval from the trusted
conversation. Actor identity comes from the actual receiving binding. Exact
home/origin and actor revision are bound to the redemption. The same approved
browser can retry a lost response without creating another grant or reviving a
revoked one. Session credentials are hashed at rest and use host-only Secure,
HttpOnly cookies. Logout revokes the session, rather than only hiding the UI.
Provider-signed Telegram launch data may establish the human's provider subject,
but never adds an artifact grant. Ordinary browser access remains supported.

Keep publication/owner operations local or under a separately scoped owner
client. Reader credentials cannot publish, approve another subject, modify a
roster, run commands or provision bodies. Actual human acceptance is reported
separately from operator/fixture checks; existing pairing data is not re-requested.

## Content and history

Published active HTML/SVG must be isolated before adding login cookies. Enforce
opaque-origin sandboxing on both direct views and previews; forbid network
exfiltration and reject null-origin authenticated reads. Keep source bytes and
standalone-download behavior intact. Home UI scripts never evaluate uploaded
content or trust its messages as identity or commands.

Retain original selected artifacts and immutable revisions. An audience change
updates the serving projection atomically; old-version URLs must satisfy both
the current grant and that revision's selected grant. Moving private work to
public does not automatically publish earlier private revisions. Unpublication
removes all serving projections while retaining owner-local recovery history;
already downloaded public copies cannot be recalled.

## Provisioning and deployment

Extend existing accepted-body onboarding with the maintained preservation and
commit-pinned install helpers. A home is owned by a selected being, operated by
its accepted body; label/default-route changes do not replace another owner.
Keep original source/state outside public roots and large artifacts on existing
durable storage. Retries preserve artifacts, receiving instructions and sessions.
The web-ring is an explicitly selected set of public homes, not discovery or an
implicit social grant. Prepare exact service/config candidates with retained
history and compatible rollback, and qualify a coherent candidate once.

No terminal, desktop, administration-path change, native-session replacement,
autonomous publication, peer attention or model wakeup belongs to this increment.
