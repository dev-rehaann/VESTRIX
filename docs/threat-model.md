# Vestrix Threat Model

This document defines the attacker capabilities, controls, and residual risks for
Vestrix, an open-source WiFi Channel State Information (CSI) intrusion-detection
system. Its scope is the sensor-to-collector data path, forensic evidence records,
and the alert path. It does not assert that a control is effective beyond the
implementation and testing described here.

`IMPLEMENTED` means that the relevant code or configuration is present in the
repository. It does not mean that the control has been validated on ESP32 hardware,
independently assessed, or deployed in an operational environment. `PLANNED` means
that the control is not implemented end to end.

## Assumptions

This threat model is built on four assumptions:

1. An attacker can physically tamper with a sensor node, including disabling,
   removing, moving, opening, or replacing it.
2. An attacker on the same network segment can attempt network-level spoofing,
   replay, or injection of fabricated CSI observations.
3. An attacker who obtains access to stored evidence can attempt post-hoc
   alteration, deletion, reordering, or replacement of forensic records.
4. An attacker can attempt to suppress, delay, or interfere with delivery of sensor
   data and alerts.

## Mapping scope

The ATT&CK and CAPEC IDs and titles below were verified against MITRE's live
catalogs on 2026-08-02 (CAPEC version 3.9). Enterprise ATT&CK mappings describe
matching adversary behavior; they do not imply that Vestrix is an enterprise
endpoint product. ATT&CK for ICS mappings apply directly only when Vestrix is
deployed in an ICS/OT environment and are cross-domain analogues otherwise.

## Summary

| Category | Status | Primary Control | ATT&CK/CAPEC Mapping |
|---|---|---|---|
| Physical tamper | `IMPLEMENTED` downstream handling; `PLANNED` sensor-side detection | Collector certificate allow-list; planned enclosure tamper event and liveness monitoring | ATT&CK [T1685](https://attack.mitre.org/techniques/T1685/); CAPEC [401](https://capec.mitre.org/data/definitions/401.html), [507](https://capec.mitre.org/data/definitions/507.html), [547](https://capec.mitre.org/data/definitions/547.html) |
| Stream injection | `IMPLEMENTED` collector side; `PLANNED` firmware client | mTLS, certificate-CN allow-list, payload identity binding, per-node sequence check | ATT&CK [T1692.002](https://attack.mitre.org/techniques/T1692/002/), [T1565.002](https://attack.mitre.org/techniques/T1565/002/); CAPEC [594](https://capec.mitre.org/data/definitions/594.html) |
| Log tampering | `IMPLEMENTED` chain and verifier; `PLANNED` complete external anchoring | Ed25519-signed SHA-256 hash chain and independent Rust verifier | ATT&CK [T1565.001](https://attack.mitre.org/techniques/T1565/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/); CAPEC [93](https://capec.mitre.org/data/definitions/93.html), [268](https://capec.mitre.org/data/definitions/268.html) |
| Alert suppression | `IMPLEMENTED` event mapping and Wazuh rules; `PLANNED` liveness controls | Wazuh/OCSF integration; planned heartbeat and missed-liveness detection | ATT&CK [T0878](https://attack.mitre.org/techniques/T0878/), [T1691.002](https://attack.mitre.org/techniques/T1691/002/), [T1498](https://attack.mitre.org/techniques/T1498/); CAPEC [125](https://capec.mitre.org/data/definitions/125.html), [595](https://capec.mitre.org/data/definitions/595.html), [601](https://capec.mitre.org/data/definitions/601.html) |

## 1. Physical tamper — attacker physically disables, removes, or replaces a sensor node

### Attack description

Fielded IoT sensors may be installed where unauthorized people can reach them.
Physical access can be used to remove power, change antenna or node placement,
damage the device, access local interfaces or credentials, or substitute a device
under the attacker's control. NIST identifies inadequate built-in protection from
physical tampering and inadequate operational/security event logging as recurring
IoT risk considerations ([NISTIR 8228](#references)).

Placement is also part of the sensing configuration. CSI-based recognition is
sensitive to environmental and deployment changes; published cross-environment
research treats transfer from a fixed, controlled environment as a distinct and
unresolved engineering problem ([Zhang et al.](#references)). Moving or replacing a
node can therefore change the observed channel and invalidate a previously measured
baseline without requiring a software exploit.

### Controls

| Status | Control | Security effect |
|---|---|---|
| `IMPLEMENTED` | The collector requires a CA-validated client certificate, exactly one certificate common name (CN), membership of that CN in the node allow-list, and equality between the certificate CN and payload `node_id`. | A replacement device without the enrolled private key and certificate cannot use the original node identity at the collector. This is a collector-side control only until firmware implements the client. |
| `IMPLEMENTED` | The OCSF mapper accepts the canonical `sensor_tamper` event class, and the Wazuh ruleset maps it to a level-12 alert. | A tamper event that reaches the SOC path has defined, tested downstream handling. This control does not detect tampering by itself. |
| `PLANNED` | ESP32 enclosure tamper input and generation of a `sensor_tamper` event through the authenticated ingest and forensic logging paths. | Intended to record enclosure opening or equivalent physical activation as evidence. The ESP32 CSI firmware and this input are not built. |
| `PLANNED` | Sensor heartbeat/liveness monitoring and a missing-heartbeat alert. | Intended to detect removal, loss of power, or loss of communications when a final tamper event cannot be transmitted. |

### Standards mapping

- **MITRE ATT&CK Enterprise [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/):** explicitly includes disabling, degrading, or tampering with intrusion-detection systems and sensors.
- **CAPEC [401 — Physically Hacking Hardware](https://capec.mitre.org/data/definitions/401.html):** applies to unauthorized modification or covert replacement of installed hardware.
- **CAPEC [507 — Physical Theft](https://capec.mitre.org/data/definitions/507.html):** applies when the node is removed and taken.
- **CAPEC [547 — Physical Destruction of Device or Component](https://capec.mitre.org/data/definitions/547.html):** applies when the node or a required component is physically disabled or destroyed.

ATT&CK does not define a single Enterprise technique that exactly represents every
form of physical removal or replacement of a field sensor. T1200 (Hardware
Additions) is intentionally excluded because it describes introducing hardware as
an initial-access vector, not sensor removal or substitution. CAPEC provides the
more direct physical-security mappings.

### Residual risk and known limitations

- No sensor-side physical-tamper or liveness control currently operates because the
  firmware is not implemented.
- An attacker may remove power or communications before a tamper event is sent. An
  enclosure switch is tamper-evident, not tamper-proof, and can itself be bypassed or
  damaged.
- Possession of an enrolled node's private key would allow a replacement device to
  authenticate. Hardware-backed key storage, secure boot, flash encryption, and
  resistance to physical key extraction have not been implemented or evaluated by
  Vestrix.
- The collector allow-list identifies a credential, not the continued physical
  integrity, location, or orientation of the node that uses it.
- No claim is made that a model trained before a node is moved or replaced remains
  accurate. Hardware and cross-environment benchmarks do not yet exist.

## 2. Stream injection — attacker on the same network segment attempts to inject spoofed/fabricated CSI data

### Attack description

An attacker with local network access may attempt to connect as a sensor, replay a
previous observation, alter data in transit, or submit fabricated CSI or fabricated
classification inputs. The intended outcome may be a false intrusion, a false
"all-clear" result, or contamination of evidence and model inputs.

This threat is not limited to application-layer JSON. Published WiFi-sensing work
has shown that controlled RF interference can alter measured CSI and steer
classification outcomes ([Sharma et al., *Wi-Spoof*](#references)). That literature
supports treating CSI authenticity and transport authenticity as separate
properties: a valid TLS peer can still report CSI that was manipulated before or at
measurement.

### Controls

| Status | Control | Security effect |
|---|---|---|
| `IMPLEMENTED` | The asyncio TCP collector requires mutual TLS and validates client certificates against the configured CA. | Rejects unauthenticated TCP clients and protects the confidentiality and integrity of accepted data in transit. |
| `IMPLEMENTED` | OpenSSL leaf-certificate CRL checking rejects certificates listed in the configured CRL. The allow-list and CRL-backed TLS context are atomically reloadable for new connections through SIGHUP on supported platforms. | Lets an operator revoke an issued node certificate or change enrollment without restarting the collector. Existing connections are not retroactively terminated. |
| `IMPLEMENTED` | The collector requires one certificate CN, checks it against an exact node allow-list, and binds the payload `node_id` to that CN. | Prevents an authenticated node from claiming a different allow-listed node identity through the payload alone. |
| `IMPLEMENTED` | Strict payload schema, type, size, timestamp, and numeric-bound validation is performed before handoff. | Rejects malformed or out-of-contract events; it does not establish that well-formed CSI is physically truthful. |
| `IMPLEMENTED` | A per-node, strictly increasing `sequence_number` is enforced in collector memory. Replayed or out-of-order values are rejected before handoff. | Detects replay within the lifetime of the collector process for a given certificate identity. |
| `PLANNED` | ESP32 mTLS client, device-certificate provisioning, private-key protection, and monotonic sequence generation. | Required to complete the authenticated sensor-to-collector path. The firmware is not built. |

### Standards mapping

- **MITRE ATT&CK for ICS [T1692.002 — Unauthorized Message: Reporting Message](https://attack.mitre.org/techniques/T1692/002/):** applies to forged sensor telemetry in an ICS/OT deployment and is the closest cross-domain analogue elsewhere.
- **MITRE ATT&CK Enterprise [T1565.002 — Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002/):** applies to alteration of data while it is being transferred.
- **MITRE ATT&CK Enterprise [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/):** applies when local-segment positioning is used to intercept or redirect traffic and enable follow-on manipulation or replay.
- **CAPEC [594 — Traffic Injection](https://capec.mitre.org/data/definitions/594.html):** applies to crafted traffic injected to affect a networked system without relying on bulk flooding.

### Residual risk and known limitations

- The server-side collector control is implemented, but no end-to-end ESP32 mTLS
  path exists until the firmware client is built and tested.
- mTLS authenticates possession of a private key. It does not prove that the
  reported CSI was measured at the enrolled location, was produced by uncompromised
  firmware, or represents a real physical event.
- A physically compromised node or stolen node credential can submit well-formed,
  authenticated fabricated data. The CN allow-list is not hardware attestation.
- The current ingest schema carries a `csi_window_sha256` reference rather than the
  raw CSI window. Format validation of that digest does not prove that the
  referenced data exists or that it was measured by the node.
- Replay state is held in process memory. A collector restart loses the last-seen
  sequence values, so the present mechanism does not provide replay continuity
  across restarts or node re-enrollment.
- The collector checks the configured CRL and can atomically reload both that CRL
  and the node allow-list on SIGHUP. Revocation remains an operator action: run the
  CA revocation helper, distribute the regenerated CRL to the configured path, and
  signal each collector process. A failed reload retains the last valid state.
- `check_expiry.sh` flags node certificates within 30 days of expiry by default; it
  provides visibility only. Automated enrollment and rotation, OCSP, HSM-backed
  key storage, and passphrase-protected private keys are not implemented.
- RF-domain manipulation occurs before TLS protection and is not mitigated by mTLS
  or JSON validation.
- No adversarial CSI robustness result is available for Vestrix. Published results
  against other CSI systems must not be treated as a measured Vestrix attack success
  rate or as evidence that Vestrix resists those attacks.

## 3. Log tampering — attacker attempts to alter or delete forensic evidence records after the fact

### Attack description

An attacker with access to evidence storage may edit an earlier JSONL record,
insert or reorder records, delete selected records or a suffix, replace the entire
file, or attempt to forge a new history. Secure-audit-log research treats compromise
of the logging host and subsequent corruption of its local records as a core threat
([Schneier and Kelsey](#references)). NIST forensic guidance likewise makes evidence
integrity and documented handling part of a defensible forensic process
([NIST SP 800-86](#references)).

### Controls

| Status | Control | Security effect |
|---|---|---|
| `IMPLEMENTED` | Each canonical JSONL record contains a sequence number, the previous record hash, a SHA-256 `record_hash`, and an Ed25519 signature over the canonical record bytes. | Modification, insertion, reordering, or forgery without the signing key causes hash, linkage, sequence, canonicalization, or signature verification to fail. |
| `IMPLEMENTED` | The Python logger validates the existing chain before append and serializes appends under a shared file lock. | Reduces accidental or concurrent chain corruption at the supported append interface. It does not make the underlying file write-once. |
| `IMPLEMENTED` | The independent Rust `vestrix-verify` CLI shares no collector or Python forensics code and validates UTF-8/JSON form, the exact schema, canonical bytes, sequence continuity, hash linkage, SHA-256 hashes, and Ed25519 signatures. | Provides an independent, read-only check of the records that are present. |
| `IMPLEMENTED` | The Python OpenTimestamps interface can snapshot a chain tip and write a backend receipt; the Rust verifier can inspect a limited offline proof subset and intentionally refuses to report full Bitcoin-anchor success. | Provides fail-closed scaffolding and partial proof binding without overstating timestamp assurance. |
| `PLANNED` | A pinned production OpenTimestamps submission client and complete verification against an independently trusted Bitcoin best chain. | Intended to bind selected chain tips to an external time source and make later history replacement or truncation detectable relative to a retained checkpoint. |

### Standards mapping

- **MITRE ATT&CK Enterprise [T1565.001 — Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/):** applies to insertion, deletion, or alteration of stored evidence data.
- **MITRE ATT&CK Enterprise [T1070.004 — File Deletion](https://attack.mitre.org/techniques/T1070/004/):** applies when evidence files are deleted to remove indicators.
- **CAPEC [268 — Audit Log Manipulation](https://capec.mitre.org/data/definitions/268.html):** applies to alteration of audit data to hide activity or mislead review.
- **CAPEC [93 — Log Injection-Tampering-Forging](https://capec.mitre.org/data/definitions/93.html):** applies specifically to injected, manipulated, or forged log entries that impair accountability and forensic analysis.

### Residual risk and known limitations

- The chain is tamper-evident, not immutable. An attacker with filesystem access can
  edit or delete the JSONL file; verification detects many such changes but does not
  prevent them.
- A valid prefix is indistinguishable from a deliberately truncated chain unless a
  trusted party has retained an expected record count or later chain tip. The
  verifier intentionally accepts an empty file as a valid empty chain, so complete
  file deletion is not intrinsically detected.
- Full OpenTimestamps submission and authoritative Bitcoin best-chain verification
  are not implemented. Vestrix therefore does not currently claim an independently
  verified external timestamp or resistance to backdating.
- If an attacker obtains both the signing key and writable evidence storage before a
  trusted checkpoint is externalized, the attacker may construct and sign a
  replacement history that passes local chain verification.
- A valid signature proves that the configured logger key signed the record. It does
  not prove that the sensor observation or classification recorded in it is true.
- Signing-key custody, filesystem authorization, backup retention, export of trusted
  chain tips, and evidence-chain-of-custody procedures remain operator
  responsibilities.
- The collector-to-forensics adapter is currently a no-op boundary. The logger is
  implemented as a separate component, but accepted collector events are not yet
  connected to it by the default collector configuration.

## 4. Alert suppression — attacker attempts to suppress, delay, or interfere with alert delivery

### Attack description

An attacker may power down or isolate a sensor, block sensor-to-collector traffic,
reset connections, exhaust collector or network resources, stop a forwarding
process, alter downstream rules, or prevent a SIEM notification from reaching an
operator. Sensor-network literature has long identified availability as difficult
to preserve because individual sensor nodes and their communications are
resource-constrained and susceptible to denial of service ([Wood and
Stankovic](#references)). Without an independent liveness signal, silence may be
misinterpreted as an absence of intrusion rather than a failed or suppressed sensor.

### Controls

| Status | Control | Security effect |
|---|---|---|
| `IMPLEMENTED` | The canonical alert mapper produces validated Wazuh JSON and OCSF Detection Finding events, and the Wazuh decoder/rules generate defined alerts for supported intrusion and `sensor_tamper` events. | Provides deterministic downstream interpretation for an event that reaches the integration. It does not guarantee transport or operator notification. |
| `IMPLEMENTED` | The Wazuh integration includes a correlation rule for a Vestrix intrusion following a supported authentication anomaly. | Can raise the severity of a received alert when corroborating telemetry is present. It does not detect a missing Vestrix event. |
| `PLANNED` | Connect authenticated collector handoff to the signed logger and canonical SOC event path. | Intended to preserve accepted evidence and feed both SOC mappings from the same validated event. The current collector adapter is a no-op, so this path is not end to end. |
| `PLANNED` | Sensor heartbeat/liveness records and missed-heartbeat alerts. | Intended to make loss of expected telemetry observable instead of treating silence as normal operation. |
| `PLANNED` | Correlation of a sensor-tamper or liveness failure with missing or delayed alert traffic. | Intended to identify combined physical interference and alert-path impairment. No such correlation rule is currently shipped. |

### Standards mapping

- **MITRE ATT&CK for ICS [T0878 — Alarm Suppression](https://attack.mitre.org/techniques/T0878/):** applies to preventing protection alarms from notifying operators in an ICS/OT deployment and is a behavioral analogue elsewhere.
- **MITRE ATT&CK for ICS [T1691.002 — Block Operational Technology Message: Reporting Message](https://attack.mitre.org/techniques/T1691/002/):** applies to blocked reporting telemetry in an ICS/OT deployment and is the closest cross-domain analogue elsewhere.
- **MITRE ATT&CK Enterprise [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/):** applies to disabling sensors, logging agents, SIEM ingestion, or other defensive tooling.
- **MITRE ATT&CK Enterprise [T1498 — Network Denial of Service](https://attack.mitre.org/techniques/T1498/):** applies when network capacity is exhausted to make the collector or alert destination unavailable.
- **CAPEC [125 — Flooding](https://capec.mitre.org/data/definitions/125.html):** applies to resource exhaustion through a high volume of interactions.
- **CAPEC [595 — Connection Reset](https://capec.mitre.org/data/definitions/595.html):** applies to injected resets intended to terminate a communication channel.
- **CAPEC [601 — Jamming](https://capec.mitre.org/data/definitions/601.html):** applies to intentional radio interference. High-capability RF jamming is explicitly out of scope below, but the pattern identifies the behavior.

### Residual risk and known limitations

- No heartbeat, missed-liveness detector, durable alert queue, delivery
  acknowledgement, retry policy, or independent out-of-band notification channel is
  implemented. Silence is not currently a reliable security signal.
- The Wazuh and OCSF components map and classify events; they do not deliver them to
  an operator or prove that an operator received them.
- No in-repository dispatcher currently connects collector ingest to the signed
  logger, canonical alert mapper, and Wazuh/OCSF destinations as one operational
  path.
- mTLS provides peer authentication and transport integrity, not availability. It
  does not prevent connection exhaustion, network outage, deliberate packet loss,
  or loss of sensor power.
- The shipped Wazuh rules intentionally do not alert on low-confidence and
  borderline classifications. An attacker who can influence CSI or the upstream
  classification may be able to keep an event below an alert threshold. Vestrix has
  not tested this attack path.
- End-to-end alert latency, loss behavior, queue saturation, recovery after outage,
  and operation during collector or SIEM restart have not been benchmarked.
- A common failure affecting the sensor, network path, collector, and alert platform
  can suppress both the originating event and evidence of the suppression.

## Explicitly Out of Scope

The following risks belong to the operator's broader physical, network, platform,
and supply-chain security program. They are not controlled by Vestrix itself:

- Nation-state-level, wide-area, or sustained high-power RF jamming and coordinated
  spectrum denial. Local loss of communications remains an in-scope condition for
  planned liveness detection, but Vestrix does not claim to defeat the jammer.
- Supply-chain compromise of ESP32 silicon, malicious chip fabrication, or compromise
  introduced before the hardware reaches the operator. Vendor selection, receiving
  inspection, and procurement assurance are operator controls.
- Physical security of the collector server, signing-key host, storage media,
  network equipment, Wazuh manager, and SIEM infrastructure, including building,
  rack, power, and environmental controls.
- Security and availability of the operator's CA, certificate-enrollment process,
  DNS, routing, switching, time sources, backups, and external notification systems.
- SOC staffing, escalation, incident response, retention schedules, legal hold,
  evidence transport, and jurisdiction-specific determinations of admissibility.

These exclusions do not make their failure harmless. They define the boundary at
which the operator must apply controls outside the Vestrix codebase.

## References

1. NIST, [*Considerations for Managing Internet of Things (IoT) Cybersecurity and Privacy Risks*, NISTIR 8228](https://doi.org/10.6028/NIST.IR.8228), 2019.
2. L. Zhang et al., [*Privacy-Preserving Cross-Environment Human Activity Recognition*](https://doi.org/10.1109/TCYB.2021.3126831), IEEE Transactions on Cybernetics, 2023.
3. A. Sharma et al., [*Wi-Spoof: Generating Adversarial Wireless Signals to Deceive Wi-Fi Sensing Systems*](https://doi.org/10.1016/j.jisa.2025.104052), Journal of Information Security and Applications, 2025.
4. B. Schneier and J. Kelsey, [*Secure Audit Logs to Support Computer Forensics*](https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html), ACM Transactions on Information and System Security, 1999.
5. NIST, [*Guide to Integrating Forensic Techniques into Incident Response*, NIST SP 800-86](https://doi.org/10.6028/NIST.SP.800-86), 2006.
6. A. D. Wood and J. A. Stankovic, [*Denial of Service in Sensor Networks*](https://doi.org/10.1109/MC.2002.1039518), IEEE Computer, 2002.

---

- **Document version:** 1.0.1
- **Last updated:** 2026-08-02
- **Project license:** Apache License 2.0
- **Maintenance note:** This is a living document. It must be updated as controls,
  firmware, validation results, dependencies, and external technique mappings evolve.
