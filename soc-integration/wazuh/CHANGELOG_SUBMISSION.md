# Wazuh submission changelog

## 2026-08-02 — v1 submission candidate

### Scope

Prepared the existing Vestrix native decoder and rules for upstream review in
`upstream/vestrix_integration/`, ready to be copied to
`integrations/vestrix_integration/` in `wazuh/integrations`. The package adds
numbered copies of the tested XML and a Wazuh-format `test.ini`; it does not
change the live-tested source XML or test logic. The OCSF mapper remains a
Vestrix-side integration and is outside the proposed Wazuh contribution.

### Decoder inventory

| Source file | Decoder name | Function |
|---|---|---|
| `decoders/local_decoder.xml` | `vestrix` | Selects JSON records whose `source` is `vestrix`, inherits the built-in `json` decoder, preserves its own decoder name, and uses `JSON_Decoder` for field extraction. |

There is no `vestrix_fields` decoder in the tested submission candidate. That
name exists only in an earlier design document and must not be listed as
shipped unless a separately tested implementation is added later.

### Rule inventory and level rationale

| Rule ID | Level | Purpose and rationale |
|---:|---:|---|
| `100200` | `0` | Base grouping rule for canonical Vestrix events. Level 0 deliberately consumes supported benign, low-confidence, and borderline records without generating an alert. |
| `100201` | `10` | Alerts on an intrusion event whose prevalidated `confidence_level` is `high`. Level 10 represents a significant physical-security detection without treating the CSI result alone as the maximum-severity incident. |
| `100202` | `12` | Alerts when an intrusion also has finalized `pacs_event_status=missing`. Level 12 reflects the added access-control anomaly. Wazuh does not infer the missing PACS event; an upstream enricher must set it. |
| `100203` | `12` | Alerts on `sensor_tamper`. Level 12 reflects possible impairment or evasion of a physical-security sensor. The rule handles a received tamper event; it does not implement tamper sensing. |
| `100210` | `1` | Non-alerting (`no_log`) helper for built-in OpenSSH rules `5712` and `5763`. It is level 1 rather than level 0 so `if_matched_sid` history can retain it for correlation. |
| `100211` | `14` | Correlates a level-10 high-confidence Vestrix intrusion with a preceding supported SSH authentication anomaly inside 120 seconds. Level 14 is reserved here for the composite incident because it combines physical and authentication evidence; it is not a claim about standalone model accuracy. |

### Validation recorded for this candidate

- Loaded the decoder and rules in the official
  `wazuh/wazuh-manager:4.14.5` container.
- Asserted six standalone samples with `wazuh-logtest -U`, covering three
  alerting outcomes, two non-alerting confidence outcomes, and one benign
  negative test.
- Verified rule `100211` in one persistent `wazuh-logtest` session after eight
  same-source invalid-user SSH events selected built-in rule `5712` and helper
  rule `100210`.
- Re-ran all six standalone samples after the decoder-name fix; every asserted
  rule ID, level, and decoder name returned `Unit test OK`.
- Saved the actual phase output in
  [`sample_events/logtest_output.txt`](sample_events/logtest_output.txt).

### Known submission limitations

- Compatibility with Wazuh versions earlier than 4.14.5 is untested.
- The authentication correlation depends on built-in rule IDs `5712` and
  `5763` and is manager-global because authentication events are not yet
  enriched with Vestrix `site_id` or `zone_id`.
- The PACS rule depends on a finalized status from an external enricher.
- The current IDs do not collide on that commit, but `100200–100211` are in
  Wazuh's [documented local/custom range](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).
  A maintainer-approved upstream core ID block is still required, followed by
  synchronized XML and `test.ini` updates.
- `test.ini` now covers a positive detection, a negative non-match, and the
  decoder-name collision regression. The official upstream lint/test run
  remains pending until final IDs are confirmed.
- The destination was confirmed on 2026-08-02 from the live
  `wazuh/integrations` repository and its `CONTRIBUTING.md`.
- Active response, SCA, and threat-intelligence content are explicitly marked
  not applicable. A dashboard remains planned but not built.
- Vestrix is Apache-2.0 licensed. Contributor licensing requirements for
  `wazuh/integrations` must be confirmed before submitting copied XML.
