# Vestrix — Project Status

_Forensics-grade, open-source WiFi CSI intrusion detection platform_ _Last updated: July 24, 2026_

> Note: project renamed from **Sentrix → Vestrix** after a trademark conflict was found with an active enterprise cybersecurity company (plus other naming collisions). Minor phonetic overlap with "Vectrix" (a cloud/SaaS security scanner) was reviewed and accepted as a low risk. Any references to "Sentrix" in older docs (roadmap, initialization guide) are historical and should be read as Vestrix going forward.

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
- ⚠️ Known gap: spec lacks edge-case test vectors for float canonicalization (e.g. `1.0`, `0.30000000000000004`, `1e-05`) — needs explicit handling before it's considered airtight

### 3. Rust Verifier CLI

- Independent reimplementation from the `CHAIN_FORMAT.md` spec (deliberately shares no code with the Python collector/logger — this is a forensic integrity requirement, not just a design preference)
- Passes `cargo test` and `clippy`

### 4. Wazuh Decoder/Rules + OCSF Mapper

- Tested against a live Wazuh manager container (v4.14.5)
- A real decoder naming-collision bug was caught during live testing — not by static review
- A BOM-encoding issue from PowerShell-generated test fixtures was also caught this way

### 5. Documentation & Promotion Groundwork

- Full promotional README section drafted: competitive gap table, text architecture diagram, component status table, quick-links placeholders
- `docs/threat-model.md` generated (via Codex prompt) — currently mid-audit (see below)

---

## 🚧 In Progress

- **Threat model ATT&CK/CAPEC mapping audit** — `docs/threat-model.md` needs its technique/pattern IDs verified before it can be trusted as accurate. Specific IDs flagged for verification:
    - `T1685`
    - ICS `T0878`
    - This audit is a **blocking dependency** for the v0.1 public tag

---

## ⏳ Not Started / Blocked

|Item|Status|Blocker|
|---|---|---|
|ESP32 firmware (CSI capture)|Not started|Hardware not yet arrived (one unit on order/en route)|
|Float canonicalization test vectors in `CHAIN_FORMAT.md`|Not started|—|
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

1. **Finish the ATT&CK/CAPEC ID audit** on `docs/threat-model.md` — this is the explicit blocker for tagging v0.1
2. Add float-canonicalization edge-case test vectors to `CHAIN_FORMAT.md`
3. Once ESP32 hardware arrives: begin firmware development (CSI capture via ESP-IDF)
4. Submit Wazuh decoder/rules upstream + PR into relevant awesome-lists (low-effort, high-return — doesn't require firmware)
5. Tag v0.1 once threat model audit is complete

---

## Reference

Full research context and detailed rationale live in:

- `SENTRIX_Research_Roadmap.md` (prior-art analysis, standards alignment, rigor playbook)
- `SENTRIX_PROJECT_INITIALIZATION.md` (full architecture/build reference, v0.1 → v1.0 roadmap)

_(Titles retain the old "Sentrix" name from when they were written; content still applies to Vestrix.)_