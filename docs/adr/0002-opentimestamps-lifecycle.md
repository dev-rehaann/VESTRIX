# ADR 0002: OpenTimestamps lifecycle

- Status: Proposed
- Date: 2026-08-22
- Decision owner: VESTRIX maintainer

This ADR defines the boundary between the immutable forensic chain, asynchronous
OpenTimestamps submission, proof upgrading, and independent Bitcoin
verification. It does not claim that the design is implemented. The current
Python production backend and full Rust anchor verdict remain intentionally
fail-closed until an implementation conforming to this ADR is reviewed.

## 1. Digest-boundary handling

### Context

The forensic chain already computes a 32-byte SHA-256 `record_hash` for its
selected tip. That digest is the value the current Rust proof inspector expects
inside the detached OpenTimestamps proof.

The `ots stamp FILE` command hashes `FILE`; it does not accept an already
computed digest for submission. Passing a temporary file containing the 32
digest bytes would therefore anchor `SHA256(record_hash_bytes)`, not
`record_hash`. Hiding that extra layer would make the Python submitter and Rust
verifier disagree about the evidentiary boundary.

### Decision

Use the lower-level `opentimestamps` Python library directly to construct a
`DetachedTimestampFile` whose SHA-256 file digest is exactly the existing chain
tip `record_hash`. Build the timestamp graph from that digest and retain the
client's normal privacy protection: append a fresh random nonce and hash the
result before submitting the calendar commitment.

Use the official `opentimestamps-client` implementation for calendar submission
and proof upgrading, behind a narrow VESTRIX adapter. Do not invoke `ots stamp`
on digest bytes and do not define a VESTRIX-specific extra-hash proof format.

### Consequences

- The detached proof remains directly bound to the existing `record_hash`.
- Python and Rust can share the published OpenTimestamps wire format without
  sharing implementation code.
- Calendar servers see a nonce-protected commitment rather than the raw chain
  tip digest.
- The adapter must isolate the package's CLI-oriented internals and translate
  exceptions or process-exit behavior into explicit worker failures.
- Tests must assert that the detached proof's embedded digest is byte-for-byte
  equal to the selected chain-tip `record_hash`.

### Rejected Alternatives

- **Write the digest bytes to a temporary file and run `ots stamp`.** Rejected
  because it silently adds a SHA-256 layer and changes what is being attested.
- **Document and teach the Rust verifier about the extra hash layer.** Rejected
  because it creates a VESTRIX-specific semantic exception with no security or
  interoperability benefit.
- **Build the raw calendar protocol in VESTRIX.** Rejected because the official
  libraries already implement submission, serialization, and upgrading; a new
  protocol client would add security-sensitive code unnecessarily.

## 2. Submission architecture

### Context

Calendar requests have network latency and can fail. Bitcoin confirmation and
proof upgrading can take hours. Collector ingestion must not wait for either.
The signed JSONL chain is immutable evidence and cannot also serve as a mutable
job-status store.

### Decision

Implement anchoring as a one-shot worker process separate from the collector.
An operating-system scheduler starts it once when the service deployment comes
up and every 15 minutes afterward. A systemd timer is the reference Linux
deployment; cron or an equivalent scheduler may invoke the same command.

Each scheduled run:

1. briefly acquires the existing chain lock and snapshots the current
   `(sequence, record_hash)` tip;
2. inserts that tip as `queued` if it is not already tracked;
3. processes due submission, upgrade, and verification work; and
4. exits.

If no records have been appended since the most recent tracked tip, the run is
a no-op. Calendar and Bitcoin operations occur after releasing the chain lock.

Persist lifecycle state in a separate SQLite database under the evidence
directory, with detached `.ots` proof files stored beside it. SQLite is chosen
because it is transactional and is provided by the Python standard library.
The state database records at least:

- chain sequence and tip hash;
- current proof state and proof path;
- attempt count, last attempt, next attempt, and last error;
- the state from which a failed operation should resume; and
- verified Bitcoin height, block hash, verification time, and confirmation
  count when available.

Enforce uniqueness on `(sequence, tip_hash)`. Write new or upgraded proofs to a
temporary file, flush and `fsync` them, and atomically replace the sidecar proof
before committing the corresponding state transition. Never append lifecycle
metadata to, or rewrite, the forensic JSONL chain.

### Consequences

- Collector acceptance and hash-chain append remain independent of calendar or
  Bitcoin availability.
- The maximum normal unanchored interval is approximately 15 minutes, plus
  scheduler and submission delay.
- A stopped worker does not corrupt the chain, but monitoring must alert that
  external timestamp coverage is stale.
- The SQLite database is operational metadata, not primary evidence. A lost
  database can be reconstructed by inspecting retained proofs and chain tips;
  an `independently_verified` claim must still be reproducible from the chain,
  proof, and Bitcoin data.
- Deployment gains one scheduled command and one evidence-sidecar directory,
  not another long-running service.

### Rejected Alternatives

- **Run submission in the collector event loop.** Rejected because calendar
  latency or failure would affect ingestion availability.
- **Run an in-process collector background task.** Rejected because it couples
  anchoring lifetime, failure handling, and upgrades to collector restarts.
- **Create a permanent anchoring daemon.** Rejected because a scheduled
  one-shot worker provides the required isolation and retry behavior with less
  operational state.
- **Store lifecycle transitions in the signed JSONL chain.** Rejected because
  pending and retry state is mutable operational data and would blur or require
  rewriting the evidentiary record.
- **Use one mutable JSON status file.** Rejected because crash-safe concurrent
  transitions and recovery are already provided by standard-library SQLite.

## 3. Proof state machine

### Context

Calendar acceptance is not Bitcoin confirmation, and a proof containing a
Bitcoin attestation has not yet been independently checked against Bitcoin's
active chain. A single `anchored` flag would overstate assurance and make retry
behavior ambiguous.

### Decision

Use these explicit states:

| State | Meaning | Transition trigger |
|---|---|---|
| `queued` | A unique chain tip has been durably recorded, but no calendar submission proof has been durably stored. | Created from a new scheduled tip snapshot. Moves to `submitted_pending` after a valid pending proof is atomically stored, or directly to `upgraded_unverified` if the stored response already contains a Bitcoin block-header attestation. |
| `submitted_pending` | Calendar submission succeeded and a durable proof exists, but it contains no Bitcoin block-header attestation yet. | Remains pending when the calendar reports "not ready". Moves to `upgraded_unverified` when an upgraded proof with a Bitcoin attestation is atomically stored. |
| `upgraded_unverified` | The proof reaches a Bitcoin block-header attestation, but no independent active-chain check has succeeded. | Moves to `independently_verified` only after the Rust verifier succeeds against the configured Bitcoin Core node and the confirmation policy is met. |
| `independently_verified` | The Rust verifier authenticated the selected chain tip, replayed the proof, matched its commitment to a block header on Bitcoin Core's active chain, and observed the required confirmations. | Terminal for normal processing of that proof. A later explicit revalidation may report a deep-reorganization or evidence-integrity failure. |
| `retry_failed` | The most recent submission, upgrade, storage, or independent-verification attempt failed. | Stores `retry_from`, failure class, error, attempt count, and next attempt. A due transient retry returns to `retry_from`; an integrity failure disables automatic retry and requires operator review. |

Calendar `not ready` is normal pending state, not a failure. Network timeouts,
calendar quorum failures, temporary Bitcoin RPC unavailability, and temporary
filesystem or lock failures are retryable. Malformed proofs, digest mismatches,
and a commitment that does not match the active-chain block header are integrity
failures: they enter `retry_failed`, produce an alert, and receive no automatic
retry until reviewed.

Use bounded exponential backoff with jitter for transient failures. A successful
later operation clears the prior error but retains attempt history. State labels
are operational summaries; only re-running verification over the retained
artifacts establishes the evidentiary result.

### Consequences

- Operators and documentation can distinguish calendar acceptance, Bitcoin
  attestation availability, and independent verification.
- `submitted_pending` may legitimately last hours without blocking ingestion or
  being reported as failure.
- Proof corruption and digest divergence fail closed and cannot be hidden by
  repeated automatic submission.
- The worker must make every transition idempotent and recover correctly when a
  process stops between proof persistence and database commit.

### Rejected Alternatives

- **A Boolean `anchored` field.** Rejected because it conflates at least three
  materially different assurance levels.
- **Treat calendar submission as independent verification.** Rejected because a
  pending calendar receipt is not a Bitcoin timestamp.
- **Treat all upgrade misses as failures.** Rejected because confirmation delay
  is expected protocol behavior.
- **Retry integrity failures indefinitely.** Rejected because repeated network
  work cannot repair a malformed or mismatched evidentiary artifact.

## 4. Rust verifier scope for v0.9

### Context

The current Rust verifier authenticates forensic chains and partially inspects
OpenTimestamps proofs. It intentionally returns `anchor verification
incomplete` after reaching a Bitcoin attestation because the proof contains a
height, not authoritative evidence that the corresponding header belongs to
Bitcoin's active best chain.

The project roadmap assigns the independent verifier and OpenTimestamps
anchoring to v0.8-v0.9, with the acceptance condition that a third party can
verify a log without running VESTRIX. Deferring the final Bitcoin check while
calling v0.9 complete would contradict that condition.

### Decision

v0.9 requires full independent anchor verification in `verifier-cli` using a
Bitcoin Core RPC dependency. A successful Rust anchor verdict must:

1. authenticate the complete forensic chain with the supplied Ed25519 public
   key and identify the selected tip;
2. verify that the detached proof begins at that exact tip digest;
3. independently parse and replay every proof operation needed by proofs
   emitted by the pinned Python client;
4. ask Bitcoin Core for the active-chain block hash at each candidate attested
   height and retrieve the corresponding header;
5. compare the proof-derived commitment with the header's Merkle root; and
6. require the configured confirmation threshold before returning success.

The default proposed confirmation threshold is six. Bitcoin RPC unavailability,
unsupported proof operations, insufficient confirmations, malformed proof data,
digest mismatch, Merkle-root mismatch, or a height not present on the active
chain all fail closed. There is no public block-explorer fallback.

The Rust verifier must not call the Python submitter or `ots verify`; its proof
logic remains a separate implementation. Bitcoin Core is the verifier's
operator-controlled consensus data source, independent of the collector,
forensic logger, Python OpenTimestamps adapter, and public calendars. A pruned
Bitcoin Core node is acceptable because verification needs headers and active
chain lookup rather than historical transaction bodies.

The current `anchor verification incomplete` behavior remains correct until all
of these conditions are implemented and tested. It must not be replaced with a
success result in stages.

### Consequences

- v0.9 can satisfy the repository's existing independent-verification
  milestone rather than carrying a known gap into the credibility-focused v1.0
  phase.
- Independent verification requires access to a synchronized Bitcoin Core node
  and introduces RPC configuration and an additional Rust dependency.
- A verifier can be distributed without Python or trust in VESTRIX's calendar
  submission path.
- CI can test the RPC boundary deterministically with regtest fixtures, but a
  release-evidence verification must use a synchronized independently operated
  Bitcoin mainnet node.
- The verifier only needs to accept valid operations emitted by the pinned
  supported client; unsupported valid OTS variants continue to fail closed
  until deliberately added.

### Rejected Alternatives

- **Keep anchor verification incomplete throughout v0.9 and defer Bitcoin
  headers to v1.0+.** Rejected because it conflicts with the stated v0.9
  acceptance condition and leaves the project's independent timestamp claim
  unverifiable.
- **Delegate verification to Python `ots verify`.** Rejected because Python
  submission and verification would share one implementation and trust
  boundary.
- **Use a public blockchain explorer.** Rejected because the explorer's answer
  would become an unaudited trusted assertion.
- **Accept an operator-supplied standalone block header.** Rejected because one
  header does not establish membership in Bitcoin's active best chain.
- **Add the existing Rust `opentimestamps` crate and assume verification is
  complete.** Rejected because parsing and replaying a proof does not supply
  authoritative best-chain data or confirmation policy.

## 5. Pinned dependency versions

### Context

OpenTimestamps proof construction and calendar communication are
security-sensitive and have previously remained stubbed because no reviewed
client version was pinned. Version claims in this ADR must be tied to a dated
package-index check.

PyPI was checked directly on 2026-08-22:

- [`opentimestamps-client`](https://pypi.org/project/opentimestamps-client/) has
  latest release `0.7.2`, published 2024-12-31.
- Its current PyPI metadata requires
  `opentimestamps>=0.4.0,<0.5.0`.
- [`opentimestamps`](https://pypi.org/project/opentimestamps/) has latest release
  `0.4.5`, published 2023-01-25.
- Both projects are classified Beta on PyPI and use the LGPLv3-or-later license.

### Decision

The implementation must declare:

```text
opentimestamps-client==0.7.2
opentimestamps>=0.4.0,<0.5.0
```

The reproducible environment or lock artifact used for release testing must
record the resolved core package exactly; with the package index state checked
above, that resolution is `opentimestamps==0.4.5`.

Before implementation is merged, review the selected distributions' hashes,
licenses, transitive dependencies, calendar defaults, timeout/quorum behavior,
and the exact internal functions wrapped by VESTRIX. Re-check PyPI at that time;
newer releases require a separate compatibility and security review rather than
an automatic upgrade.

### Consequences

- Submission and upgrade behavior is reproducible for the first implementation.
- VESTRIX accepts maintenance responsibility for a narrow adapter around a Beta,
  CLI-oriented package.
- Security updates are deliberate changes requiring proof-vector, pending-state,
  upgrade, and cross-language verification tests.
- This ADR records versions only; dependency files remain unchanged until the
  implementation task is approved.

### Rejected Alternatives

- **Install unversioned latest releases.** Rejected because behavior could
  change without review and invalidate cross-language proof assumptions.
- **Pin directly to a Git commit.** Rejected because released PyPI artifacts are
  easier to reproduce, hash, cache, and audit.
- **Depend only on `opentimestamps-client` and leave the core resolution
  unconstrained.** Rejected because VESTRIX imports lower-level proof objects
  directly and must make that compatibility range explicit.
- **Vendor the Python packages immediately.** Rejected because there is no
  demonstrated need to own a fork; reviewed upstream distributions are the
  smaller trust and maintenance surface.

## Open questions for maintainer sign-off

1. Is a 15-minute checkpoint interval an acceptable evidence-recovery window,
   or must deployments use a shorter interval?
2. Is six Bitcoin confirmations the required default for
   `independently_verified`, and should deployments be permitted to increase but
   not decrease it?
3. Which public calendars and submission quorum should be approved instead of
   inheriting client defaults implicitly?
4. What retention and backup policy applies to pending proofs, upgraded proofs,
   and the reconstructible SQLite lifecycle database?
5. Should `retry_failed` with `failure_class = integrity` remain the only
   operator-review state, or should implementation introduce a separate terminal
   `invalid` state?
6. Which Bitcoin Core RPC authentication mechanism and Rust RPC crate/version
   should the implementation standardize on? RPC credentials must not be passed
   on a process command line.
7. Has the maintainer accepted the LGPLv3-or-later and Beta-status implications
   of the proposed Python dependencies?
