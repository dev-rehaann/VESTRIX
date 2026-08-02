# Add Vestrix physical-security event integration

## Target

- Repository: [`wazuh/integrations`](https://github.com/wazuh/integrations)
- Base branch: `main`
- New directory: `integrations/vestrix_integration/`

The contribution workflow is to fork the repository, create a feature branch,
add the directory above, and open a pull request against `wazuh/integrations`.

## Summary

This PR adds native Wazuh decoding and rules for JSON security events emitted
by Vestrix, a WiFi CSI physical-intrusion detection system.

The decoder selects records with `"source":"vestrix"` and retains the decoder
name `vestrix`. The rules cover a non-alerting base event, high-confidence
physical intrusion, sensor tampering, an externally finalized missing
PACS/badge event, and a time-based composite of physical intrusion with a
supported OpenSSH authentication anomaly.

## Included components

- `ruleset/decoders/0585-vestrix_decoders.xml`
- `ruleset/rules/1000-vestrix_rules.xml`
- `ruleset/testing/test.ini`
- integration and component status documentation

Active response, SCA, and threat-intelligence content are not implemented and
are identified as not applicable in their component directories. A Vestrix
dashboard is a known future gap and is identified as planned, not completed.

The separate Vestrix OCSF mapper is not included in this PR.

## Rule behavior

| Rule | Level | Result |
|---:|---:|---|
| `100200` | `0` | Groups canonical Vestrix events without alerting. |
| `100201` | `10` | High-confidence physical-intrusion alert. |
| `100202` | `12` | Intrusion with an externally finalized missing PACS/badge event. |
| `100203` | `12` | Sensor-tamper alert. |
| `100210` | `1` | `no_log` helper retaining supported OpenSSH anomalies for correlation. |
| `100211` | `14` | High-confidence physical intrusion within 120 seconds after the supported authentication anomaly. |

Rule `100211` is level 14 because it combines physical-intrusion and
authentication-anomaly evidence. This level is not a claim about standalone
CSI-classifier accuracy.

The `100200–100211` IDs are the live-tested Vestrix IDs. They are in Wazuh's
documented local/custom range, so final upstream allocation requires maintainer
approval. The rule XML and `test.ini` must be updated together if new IDs are
assigned.

## Testing performed

The source decoder and rules were loaded into the official
`wazuh/wazuh-manager:4.14.5` container and exercised with
`/var/ossec/bin/wazuh-logtest`.

- Six standalone inputs validated high-confidence intrusion, missing PACS,
  sensor tamper, borderline and low-confidence suppression, and a benign event.
- The level-14 path was validated in one persistent session after eight
  same-source invalid-user SSH events selected built-in rule `5712` and helper
  rule `100210`.
- A six-sample regression was repeated after fixing a decoder-name collision;
  every assertion returned `Unit test OK`.

The original decoder layout could leave Vestrix JSON under Wazuh's generic
`json` decoder name. The tested fix makes `vestrix` a child of `json`, sets
`use_own_name=true`, and delegates extraction to `JSON_Decoder`. Phase 2 then
reports `name: 'vestrix'` consistently.

## Assumptions and limitations

- Only Wazuh 4.14.5 has been tested; earlier 4.x compatibility is untested.
- Rule `100202` consumes `pacs_event_status=missing` from an external enricher.
- Rule `100201` trusts a prevalidated `confidence_level`.
- The correlation helper depends on built-in rule IDs `5712` and `5763`, which
  must be checked against the target version.
- Authentication correlation is manager-global because those events do not
  currently contain Vestrix site or zone fields.
- OCSF conversion, model training, and detection-accuracy benchmarking are out
  of scope.
- No dashboard is included in this submission candidate.

## Checklist

### Completed

- [x] Destination repository and base branch confirmed against the live
      `wazuh/integrations` repository.
- [x] Package placed under the required lowercase, underscore-separated
      `vestrix_integration/` directory structure.
- [x] Decoder and rules loaded successfully in a live Wazuh 4.14.5 manager.
- [x] Positive, suppression, benign-negative, and correlation behavior tested.
- [x] `test.ini` includes a clean detection, a non-match, and the decoder-name
      collision regression.
- [x] Tested decoder/rule/test logic remains unchanged during restructuring.
- [x] No deployment-specific site, zone, node, credential, or network values
      are hardcoded in the XML logic.
- [x] Omitted components and the dashboard gap are documented explicitly.

### Open before submission

- [ ] **Rule-ID range approved by a Wazuh maintainer.**
- [ ] **Official upstream test and lint commands run successfully.**
- [ ] Built-in dependency IDs `5712` and `5763` rechecked for the target Wazuh
      version.
- [ ] Current PR template and contributor licensing requirements checked.

## Supporting evidence

- Local verification procedure: `soc-integration/wazuh/README.md`
- Saved phase output: `soc-integration/wazuh/sample_events/logtest_output.txt`
- Sample inputs: `soc-integration/wazuh/sample_events/`
