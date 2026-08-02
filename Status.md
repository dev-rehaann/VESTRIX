# Vestrix — Project Status

_Forensics-grade, open-source WiFi CSI intrusion detection platform_ _Last updated: August 2, 2026_

> Note: project renamed from **Sentrix → Vestrix** after a trademark conflict was found with an active enterprise cybersecurity company (plus other naming collisions). Minor phonetic overlap with "Vectrix" (a cloud/SaaS security scanner) was reviewed and accepted as a low risk. Repository documentation now uses the Vestrix name.

---

## ✅ Completed

### 1. mTLS Collector Service

- asyncio-based TCP/TLS ingest service
- Certificate CN allow-list for node authentication
- Anti-replay counters implemented

### 2. Forensic Hash-Chain Logger

- Ed25519 signing of log entries
- `filelock`-based concurrency safety
- OpenTimestamps anchor stub in place
- Normative `CHAIN_FORMAT.md` spec written
- Binary64 canonicalization vectors cover `1.0`, `0.30000000000000004`, `1e-05`, signed zero, and exponent boundaries across the Python writer and Rust verifier

### 3. Rust Verifier CLI

- Independent reimplementation from the `CHAIN_FORMAT.md` spec (deliberately shares no code with the Python collector/logger — this is a forensic integrity requirement, not just a design preference)
- Passes `cargo test` and `clippy`

### 4. Wazuh Decoder/Rules + OCSF Mapper

- Tested against a live Wazuh manager container (v4.14.5)
- A real decoder naming-collision bug was caught during live testing — not by static review
- A BOM-encoding issue from PowerShell-generated test fixtures was also caught this way

### 5. Documentation & Promotion Groundwork

- Full promotional README section drafted: competitive gap table, text architecture diagram, component status table, quick-links placeholders
- `docs/threat-model.md` ATT&CK/CAPEC mappings audited against MITRE's live catalogs; ICS-only mappings are explicitly conditional and the incorrect T1200 mapping was removed
- `ml/benchmarks/BENCHMARKS.md` expanded into the append-only benchmark template for dataset provenance, leakage checks, per-class metrics, confusion matrices, cross-room/device evaluation, and unflattering results; no real benchmark run exists yet
- Duplicate non-goals and initialization documents consolidated under `docs/`

---

## ⏳ Not Started / Blocked

|Item|Status|Blocker|
|---|---|---|
|ESP32 firmware (CSI capture)|Not started|Hardware not yet arrived (one unit on order/en route)|
|Leave-one-room-out / leave-one-device-out validation suite|Not started|Depends on firmware + real CSI data|
|Multi-node zone fusion / localization|Not started (moonshot tier)|Depends on firmware + multiple nodes|
|Labeled intrusion CSI dataset (Zenodo DOI)|Not started|Depends on firmware + collected data|
|DPIA / Responsible Deployment doc|Not started|—|
|Awesome-list PRs|Not started|Highest-return near-term promotion action once repo is demo-ready|
|Wazuh upstream community submission|Not started|Ruleset is tested and likely ready to submit|
|arXiv preprint (hash-chain + SHAP evidentiary design)|Not started|Depends on v1.0-track milestones|
|Black Hat Arsenal / DFRWS submission|Not started|Needs mTLS + forensic logging + SOC integration end-to-end demo (largely done — worth revisiting readiness)|

---

## Immediate Next Steps (priority order)

1. Submit Wazuh decoder/rules upstream + PR into relevant awesome-lists (low-effort, high-return — doesn't require firmware)
2. Once ESP32 hardware arrives: begin firmware development (CSI capture via ESP-IDF)
3. Tag v0.1 once the roadmap exit criterion is met: a reliable CSI stream from at least one node reaches the collector

---

## Reference

Full research context and detailed rationale live in:

- [`docs/RESEARCH.md`](docs/RESEARCH.md) (prior-art analysis, standards alignment, rigor playbook)
- [`docs/INITIALIZATION.md`](docs/INITIALIZATION.md) (full architecture/build reference, v0.1 → v1.0 roadmap)
