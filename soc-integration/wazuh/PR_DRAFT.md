# Draft PR: add Vestrix JSON decoder and physical-security rules

> **Destination unresolved:** do not open this PR until the repository and
> branch checks in `UPSTREAM_PATH_DECISION.md` select the current official
> contribution route. The legacy paths below apply only if that route is
> confirmed; otherwise adapt this draft to the confirmed workflow.

## Description

This PR adds native Wazuh decoding and rules for JSON security events emitted
by Vestrix, an open-source WiFi CSI physical-intrusion detection system.

The decoder routes records with `"source":"vestrix"` through Wazuh's built-in
JSON decoder while retaining the decoder name `vestrix`. The rules provide a
non-alerting base event, alerts for high-confidence intrusion and sensor-tamper
events, an alert for an externally finalized missing PACS/badge event, and a
time-based correlation between a high-confidence physical intrusion and a
supported OpenSSH authentication anomaly.

This contribution only covers native Wazuh decoder/rule content. It does not
add the separate Vestrix OCSF mapper.

## Proposed changes

- For a confirmed legacy ruleset PR, add
  `ruleset/decoders/0585-vestrix_decoders.xml`,
  `ruleset/rules/1000-vestrix_rules.xml`, and
  `ruleset/testing/tests/vestrix.ini`.
- For a confirmed Ruleset-as-Code or detection-engineering workflow, adapt the
  same decoder/rule content and test cases to that repository's documented
  format and paths; do not assume the legacy layout.

The candidate filename numbers were free on Wazuh branch `4.14.8` at commit
`f17b906579d1655b9a5093453c450eadf828f840` on 2026-08-02. They must be
rechecked after the upstream target branch is confirmed.

## Rule behavior

| Rule | Level | Result |
|---:|---:|---|
| `100200` | `0` | Groups canonical Vestrix events without alerting. |
| `100201` | `10` | High-confidence physical-intrusion alert. |
| `100202` | `12` | Intrusion with externally finalized missing PACS/badge event. |
| `100203` | `12` | Sensor-tamper alert. |
| `100210` | `1` | `no_log` helper retaining supported OpenSSH anomalies for correlation. |
| `100211` | `14` | High-confidence physical intrusion within 120 seconds after the supported authentication anomaly. |

Rule `100211` is level 14 because it represents a composite incident combining
physical-intrusion and authentication-anomaly evidence. The level is not an
accuracy or performance claim for Vestrix's CSI classifier.

The `100200–100211` IDs shown above are the live-tested Vestrix IDs, not a
proposed final upstream allocation. Wazuh
[documents `100000–120000` for local custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html),
and the branch `4.14.8` core rules use no IDs in that band. A
maintainer-approved core ID block is therefore required before submission;
the XML and `test.ini` must be updated together when that block is assigned.

## Testing performed

The source decoder and rules were loaded into the official
`wazuh/wazuh-manager:4.14.5` container and exercised with
`/var/ossec/bin/wazuh-logtest`.

- Six standalone inputs were asserted with `-U rule-id:level:decoder`:
  - high-confidence intrusion: `100201:10:vestrix`;
  - intrusion with finalized missing PACS event: `100202:12:vestrix`;
  - sensor tamper: `100203:12:vestrix`;
  - borderline intrusion: `100200:0:vestrix`;
  - low-confidence intrusion: `100200:0:vestrix`; and
  - benign event: `100200:0:vestrix`, with no generated alert.
- The correlation path was tested in one persistent `wazuh-logtest` session.
  Eight same-source invalid-user SSH events selected built-in rule `5712` and
  helper `100210`; the following Vestrix event selected `100211` at level 14.
- A six-sample standalone regression was repeated after the decoder fix. Every
  assertion returned `Unit test OK`.

During live testing, the original decoder layout exposed a naming collision
with Wazuh's generic JSON path: the event could retain the generic decoder name
instead of the expected Vestrix identity. The tested fix makes `vestrix` a
child of `json`, sets `use_own_name=true`, and keeps field extraction in
`JSON_Decoder`. Phase 2 then reports `name: 'vestrix'` consistently.

## Assumptions and limitations

- Only Wazuh 4.14.5 has been tested. Earlier 4.x compatibility is untested.
- Rule `100202` consumes `pacs_event_status=missing` from an external enricher;
  Wazuh does not determine that a badge event is absent.
- Rule `100201` trusts a prevalidated `confidence_level` and does not calculate
  or duplicate Vestrix confidence thresholds.
- The correlation helper depends on Wazuh built-in rule IDs `5712` and `5763`.
  Those IDs must be checked against the target version.
- Authentication events do not currently contain Vestrix site/zone fields, so
  the 120-second correlation is manager-global rather than site-scoped.
- OCSF conversion, Vestrix transport, model training, and detection-accuracy
  benchmarking are outside this PR.
- The tested candidate contains the decoder `vestrix`; it does not contain a
  separate `vestrix_fields` decoder.
- The live `wazuh/wazuh` `main` branch checked on 2026-08-02 no longer contains
  `ruleset/decoders`, `ruleset/rules`, or `ruleset/testing`. Branch `4.14.8`
  was used for the packaging audit because it retains the layout documented by
  the contribution guide and matches the tested 4.14 line. Maintainers must
  confirm the destination branch before the PR is opened.

## Checklist

### Completed preparation

- [x] Decoder and rules loaded successfully in a live Wazuh 4.14.5 manager.
- [x] Positive, suppression, benign-negative, and correlation behavior was
      validated with `wazuh-logtest`.
- [x] No deployment-specific site, zone, node, credential, or network values
      are hardcoded in the XML logic.
- [x] Decoder/rule elements and grouping follow documented Wazuh XML syntax.
- [x] The submitted native XML contains no OCSF-specific mapping logic.
- [x] This preparation task did not alter the tested decoder/rule XML logic.
- [x] Prepared numbered candidate files `0585-vestrix_decoders.xml` and
      `1000-vestrix_rules.xml` after checking branch `4.14.8` at commit
      `f17b906579d1655b9a5093453c450eadf828f840`.
- [x] Searched that branch's rules, decoders, and tests for `100200`, `100201`,
      `100202`, `100203`, `100210`, and `100211`; no collisions were found.
- [x] Checked the rule-ID convention and flagged the current IDs as local
      custom-range IDs rather than final upstream core IDs.
- [x] Added `test.ini` with a positive detection, a negative non-match, and a
      decoder-name collision regression.

### Blocking before submission

- [ ] **Destination repo/branch confirmed against current `wazuh/wazuh` state
      — NOT YET DONE.** Complete `UPSTREAM_PATH_DECISION.md` first.
- [ ] Recheck `0585` and `1000` immediately before submission.
- [ ] Obtain a maintainer-approved upstream core rule-ID block and update both
      the rule XML and `test.ini`; do not submit `100200–100211` as core IDs.
- [ ] Run the target repository's ruleset lint and test suite successfully.
- [ ] Check this description against the target branch's current PR template
      and contribution instructions.
- [ ] Confirm Wazuh contributor licensing requirements for XML originating in
      the Apache-2.0 Vestrix repository.

## Supporting evidence

- Vestrix live-test procedure: `soc-integration/wazuh/README.md`
- Saved phase output: `soc-integration/wazuh/sample_events/logtest_output.txt`
- Sample inputs: `soc-integration/wazuh/sample_events/`
