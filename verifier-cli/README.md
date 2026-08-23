# Vestrix independent verifier

`vestrix-verify` is a small, read-only Rust verifier for the Vestrix forensic
JSONL chain format. It is a separate codebase from the collector and Python
forensics pipeline. Its contract is the published `CHAIN_FORMAT.md`, not any
Vestrix implementation.

## Build and test

Install a stable Rust toolchain, then run:

```console
cd verifier-cli
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

The binary is `target/release/vestrix-verify` (or `.exe` on Windows).

Dependencies are intentionally narrow: `serde`/`serde_json` parse untrusted
JSON, `sha2` computes record and OTS operation hashes, `ed25519-dalek` verifies
signatures, `corepc-client` performs Bitcoin Core RPC calls, and `clap` parses
the CLI. The `ryu` dependency supplies shortest-round-trip binary64 digits so
the small canonical serializer can reproduce CPython's required float spelling.

The [`corepc-client` maintainers](https://github.com/rust-bitcoin/corepc#readme)
explicitly say, "Please do not use corepc-client in production and raise bugs,
issues, or feature requests." VESTRIX nevertheless uses its narrow read-only
RPC surface; a dependency bug can invalidate a verifier verdict, but cannot
modify the forensic chain or perform wallet or transaction-broadcast
operations.

## Chain verification

```console
vestrix-verify chain evidence/chain.jsonl --pubkey keys/logger-public.hex
```

The public-key file may contain exactly 32 raw Ed25519 public-key bytes, or 64
lowercase hexadecimal characters with an optional final LF. The command checks
every physical line in order: strict UTF-8 and JSON, exact schema and value
constraints, canonical stored bytes, sequence and previous-hash linkage,
SHA-256 `record_hash`, and Ed25519 signature. It exits 0 only when every record
passes. An empty file is a valid empty chain but has no tip.

On failure it exits non-zero and writes one deterministic diagnostic such as:

```text
chain verification failed at seq 17: record_hash mismatch
```

## OpenTimestamps anchor verification

```console
vestrix-verify anchor evidence/chain.jsonl --ots-proof evidence/tip.ots \
  --rpc-url http://127.0.0.1:8332 --rpc-cookie /path/to/.cookie
```

No endpoint or credentials are hardcoded. `--rpc-url` is required. Pass a
Bitcoin Core cookie path with `--rpc-cookie`; if omitted, set both
`VESTRIX_BITCOIN_RPC_USER` and `VESTRIX_BITCOIN_RPC_PASSWORD`. The password is
not accepted as a CLI argument, so it is not exposed in the process list.

The command implements a deliberately limited Bitcoin proof subset.
It checks that the detached OTS envelope uses SHA-256, that its digest is the
current chain tip's raw 32-byte `record_hash`, and that append/prepend/SHA-256
proof paths reach a Bitcoin block-header attestation. It obtains the active
block hash at the attested height with `getblockhash`, fetches and decodes that
exact header with `getblockheader`, independently checks the header hash,
compares the proof result to the header Merkle root, and requires at least six
confirmations using `getblockcount`. Unsupported operations, pending-only
timestamps, malformed proofs, stale-chain evidence, RPC failures, commitment
mismatches, and insufficient confirmations all fail closed with a specific
diagnostic.

The anchor command reads only the canonical final record. Run `chain` with the
logger public key first to authenticate the complete chain; an anchor failure
is not by itself a chain-integrity verdict.

### Regtest integration test

GitHub Actions starts the digest-pinned `bitcoin/bitcoin:29.0` Docker image,
mines six regtest blocks, and runs the otherwise ignored
`verifies_against_real_bitcoin_core_regtest` test. The other verifier tests run
in the same CI job through `cargo test --all-targets --all-features`.

## What this tool does not do

- It does not connect to or control the Vestrix collector.
- It does not import, execute, or trust any other Vestrix component.
- It does not repair, rewrite, append, delete, or otherwise modify evidence.
- It does not decide whether signed event contents are factually correct.
- It does not contact calendars or public block-explorer APIs.

## License

Apache License 2.0, as declared in `Cargo.toml` and the repository's root
`LICENSE` file.
