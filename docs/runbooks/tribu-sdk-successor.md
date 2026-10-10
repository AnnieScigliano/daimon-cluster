# Readable Tribu SDK successor

Parent: [Matrix #287](https://github.com/AlterMundi/daimon-matrix/issues/287).
Rendering and signed presentation installation are owned by Matrix. Cluster
selects the exact executable SDK and maintained helper on the existing bodies.

## Preserve the receiving context

The original SDK `196ec7219f954cf4e514a1f61ae72eb3451d851e` remains
`PREVIOUS_MATRIX_COMMIT`: it is the immutable original receiving plan's
artifact, not the most recently running generation. Keep every prior selected
runtime and dependency environment for rollback. Changing that original pin to
the currently running SDK would invalidate legitimate receiving history.

Build the replacement wheelhouse with `tools.build_onboarding_sdk.py` from the
exact Matrix commit declared in `onboarding_sdk.MATRIX_COMMIT`. It is a closed,
hash-locked public artifact. `onboarding_code_successor.build` supports an
explicit SDK successor against the ORIGINAL base and verifies that all original
non-runtime context remains byte-identical. `onboarding_sdk.install` installs a
new content-addressed environment and validates every installed wheel byte;
never repair or overwrite a completed generation in place.

Retain the actual currently selected Telegram artifact. Where Telegram already
has its own qualified successor, keep that independent selection. If building a
combined V3 successor, pass its current qualified artifact explicitly: building
only from the original base must not select an older human-facing consumer.
No re-export, enrollment, identity rotation, bot replacement or reset of native
stores follows from this SDK upgrade.

Source keeps the exact installed VCS-commit guard; receiving bodies keep the
hash-locked wheelhouse and installation receipt. Both use the same declared
Matrix commit. The native peer helper and owner-client installer remain exact,
unchanged captures of their maintained upstream source, with separate hashes
and provenance. The installer's existing `--refresh-guidance-plan` changes
planned instruction bytes without replacing the connection's command, channels,
capability or request history.

## Qualification and live selection

The SDK CI profile runs on the actual Python 3.13.5. Its closed file boundary
covers this exact dependency pin, the native helper, installed-byte integrity,
SDK/runtime successors, actual local native services, custody/authority, owner
separation and shared host/API contracts. Unrelated dependency, authority,
provider or target runtime changes still select broader coverage. Historical
container recovery and offline-release sandbox trials are not this presentation
increment's deployment evidence.

Record prior and candidate SDK/runtime digests, current supervisor commands,
label and guidance transactions, signed visibility backups and shared reply
correlation mounts before stopping a native Matrix service. Validate the new
SDK and the existing signed application before selecting them. Select a body's
SDK/runtime and signed presentation as one coherent finite operation, restart
its existing supervisor, and inspect actual readiness. Keep private credentials
and proof keys outside shared correlation metadata. Do not restart the owner's
Telegram consumer merely to change Matrix presentation.

Rollback selects the preserved preceding executable environment and signed
installation together, preserving subsequent receiving writes and all native
journals. A checkout test, published package or installed wheel is not live
readiness. The owning Matrix epic records actual cohort acceptance, confirmed
Telegram replies and native receipts after the authorized bounded demonstration.

## Passive paired-human Tribu application (phase 4)

Parent: [Matrix #288](https://github.com/AlterMundi/daimon-matrix/issues/288),
roadmap [#289](https://github.com/AlterMundi/daimon-matrix/issues/289), deployment
[Cluster #188](https://github.com/nicoechaniz/daimon-cluster/issues/188).
The SDK's `docs/runbooks/tribu-human-mentions.md` owns the closed configuration
contracts, passive adapter and manual owner-client operations.

Use one supervised passive consumer for the existing shared visibility bot,
separate from every private Telecodex consumer. Qualify its identity, selected
chat and absent webhook without polling during staging; startup stops on a
conflicting consumer. Place its private journal, pinned TLS configuration and
per-being scoped credentials on the existing host/container route. Reuse each
body's current public authority, native socket, own public echo catalogs and
existing private-bot paired-human ID. A shared harness account, global human
allowlist, group membership or display name does not grant cross-being access.
Never collect resolved bot or human data again from participants.

Install a private owner-client configuration and discoverable manual guidance
for each body. An explicit `read` resolves only that human's pending parent IDs
against selected own public proof catalogs and exact authored events. Explicit
`reply` uses the running native daemon to sign the intent; each public part
requires confirmed Telegram parent evidence. It keeps conversation in the
requesting session and adds no callback or dependency to native delivery.
Unresolved targets remain pending; dispatched but uncertain parts are never
blindly retransmitted. Neither receiving nor querying chooses a native session,
opens model inference or imports memory. Dedicated topics, attention schedulers,
compaction renewal and cross-human permission grants remain later increments.

Before selection, retain guarded current unit/config bytes and actual SDK/runtime
digests in one protected cutover plan. Review that exact plan, qualify the adapter
with `serve --check`, and select the immutable SDK generations and owner clients.
Do not restart private Telegram consumers. Verify live queries under each owner,
correct rejection of another human, no automatic turns, and retry stability.
Genuine human acceptance is separate evidence and cannot be fabricated from
synthetic fixtures.

Rollback stops the passive consumer and selects the retained compatible SDKs.
Preserve the human journal, pending/revision history, cursor, reply/outbox states,
prepared owner requests, native ledgers/proofs and all private Telecodex histories.
Never replace a publication database with an older snapshot after an effect.
Forward restart resumes the same journal.

### Optional passive-service network route

Owner clients in Incus guests need an explicitly selected host-service route.
The current bridge input policy rejects every host port not listed before its
container drop. A working host-local query does not prove guest reachability.
Use a dedicated rule for the passive adapter's selected bridge gateway and TLS
port, not a proxy through the legacy broker or a management-rule modification:

```text
iifname "incusbr0" ip daddr <BRIDGE_GATEWAY> tcp dport 9491 accept comment "daimon-tribu-human"
```

Keep this optional until the adapter is selected. Qualify actual guest TCP and
pinned-CA queries for each owner. A reviewed operational candidate inserts this
one rule immediately before the existing bridge drop and persists the same line
with exact before/after file hashes. Compare the existing rule expressions,
handles and chain policies before/after, excluding only the new comment. Do not
reload the whole firewall, flush rules, restart nftables, rewrite the template
onto a divergent host or alter SSH, management, bridge isolation or forward
policy. Rollback deletes only the new rule and restores its retained config
bytes; retain every other service's rules and all Tribu journals.

For user-systemd deployments, `PrivateTmp=true` can put ancestor directories in
a namespace with unmapped root ownership. That conflicts with the existing
protected-file reader. Select this unit without `PrivateTmp`; keep owner-only
storage, `UMask=0077`, `NoNewPrivileges` and the package's original path guards.
The adapter does not use temporary storage. This is a service configuration
correction, not a reason to weaken file validation.

Manual owner command syntax is `reply --source ID --revision REVISION --id UUID
--text TEXT`, `retry UUID`, and `publication UUID`. Installed local guides must
match the selected package parser. Keep the operation UUID on retries.
