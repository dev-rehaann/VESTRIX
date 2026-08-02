# Vestrix Wazuh integration submission guide

**Status:** v1 submission candidate documentation

**Validated with:** `wazuh/wazuh-manager:4.14.5`

## Purpose and scope

This integration lets a Wazuh manager decode JSON alerts emitted by Vestrix,
a WiFi Channel State Information (CSI) physical-intrusion detection system.
Vestrix reports classified security events such as a high-confidence physical
intrusion or sensor tampering. It does not send raw CSI to Wazuh through this
integration.

The native Wazuh submission consists of:

- `decoders/local_decoder.xml`: the `vestrix` JSON decoder;
- `rules/local_rules.xml`: grouping, alerting, and correlation rules; and
- the sample inputs and saved `wazuh-logtest` evidence under `sample_events/`.

The checked-in, live-tested XML contains one decoder named `vestrix`. The
`vestrix_fields` name found in an earlier design document is not present in the
submission candidate; JSON field extraction is performed by Wazuh's built-in
`JSON_Decoder` inside the `vestrix` decoder.

The OCSF mapper under `../ocsf/` is a separate Vestrix output path and is not
part of the proposed Wazuh upstream contribution.

## Prerequisites and compatibility

- A Wazuh manager. The integration was tested against the official Wazuh
  manager container at version **4.14.5**.
- Compatibility with Wazuh 4.x versions earlier than 4.14.5 has not been
  tested. Compatibility must not be assumed from the XML syntax alone.
- Vestrix events must arrive as one JSON object per log record and include
  `"source":"vestrix"`.
- Confidence bands must be derived and validated before Wazuh ingestion. The
  rules consume `confidence_level`; they do not calculate a numeric threshold.
- Rule `100202` requires an upstream PACS/badge enricher to set
  `pacs_event_status=missing` after its correlation window closes.
- Rules `100210` and `100211` depend on Wazuh 4.14.5 built-in OpenSSH rule IDs
  `5712` and `5763`. These dependencies must be rechecked for every target
  Wazuh version.

## Install on a Wazuh manager

The following deployment procedure is for local review and testing. Run it
from `soc-integration/wazuh/` on a system that can copy files to the manager.

1. Back up any destination files with the same names. Do not overwrite an
   existing local decoder or rule file that contains unrelated customizations.
2. Install the decoder and rules as separate files in Wazuh's custom-content
   directories:

   ```console
   sudo install -m 0640 decoders/local_decoder.xml /var/ossec/etc/decoders/vestrix_decoder.xml
   sudo install -m 0640 rules/local_rules.xml /var/ossec/etc/rules/vestrix_rules.xml
   ```

   If local policy requires specific ownership, apply the same owner and group
   used by other files in those directories.

3. Test a mapped JSON line before restarting:

   ```console
   printf '%s\n' '{"class":"intrusion","confidence":0.97,"confidence_level":"high","node_id":"node-07","site_id":"hq-karachi","source":"vestrix","zone_id":"server-room-west"}' | sudo /var/ossec/bin/wazuh-logtest -U 100201:10:vestrix
   ```

   A successful check ends with `Unit test OK`.

4. Restart the manager so normal event analysis uses the new content:

   ```console
   sudo systemctl restart wazuh-manager
   sudo systemctl status wazuh-manager --no-pager
   ```

   On a non-systemd installation, use the service-management command supported
   by that installation. Wazuh documents `service wazuh-manager restart` as
   the SysV alternative.

For the repository's container-based verification workflow, follow
[`README.md`](README.md). Its Compose configuration mounts the tested files at
`/var/ossec/etc/decoders/local_decoder.xml` and
`/var/ossec/etc/rules/local_rules.xml`.

## Concrete input and output example

The following single-line payload is the actual Wazuh JSON produced from
[`sample_events/high_confidence_intrusion.json`](sample_events/high_confidence_intrusion.json):

```json
{"class":"intrusion","confidence":0.97,"confidence_level":"high","csi_window_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","event_id":"vestrix-20260713T201501Z-node-07-0042","model_id":"rf-csi-v1.4.2","node_id":"node-07","pacs_event_id":"pacs-884103","pacs_event_status":"matched","pacs_reader_id":"reader-west-02","record_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","schema_version":"1.0","seq":1201,"sequence_number":4421,"shap_top_feature":"subcarrier_variance_12_18","shap_top_value":0.41,"site_id":"hq-karachi","source":"vestrix","ts_utc":"2026-07-13T20:15:01Z","zone_id":"server-room-west"}
```

On the live Wazuh 4.14.5 manager, `wazuh-logtest` produced the following
relevant phase output:

```text
**Phase 2: Completed decoding.
    name: 'vestrix'
    class: 'intrusion'
    confidence: '0.970000'
    confidence_level: 'high'

**Phase 3: Completed filtering (rules).
    id: '100201'
    level: '10'
    description: 'Vestrix: high-confidence physical intrusion at hq-karachi/server-room-west, sensor node-07'
    groups: '['vestrix', 'physical_intrusion', 'physical_security', 'intrusion_detection']'
**Alert to be generated.

Unit test OK
```

The complete saved output for all samples and the level-14 correlation check
is in [`sample_events/logtest_output.txt`](sample_events/logtest_output.txt).

## Decoder naming collision found during validation

Live-manager testing exposed a decoder-identity collision with Wazuh's generic
JSON decoding path. A clean Vestrix JSON event could be claimed under the
generic `json` decoder name instead of retaining the application-specific
decoder identity expected by the Vestrix rules.

The tested fix uses one custom decoder that:

- declares `<parent>json</parent>`;
- sets `<use_own_name>true</use_own_name>`; and
- delegates all extraction to `JSON_Decoder`.

This makes phase 2 report `name: 'vestrix'` while retaining Wazuh's standard
JSON extraction. The fix was verified in the live 4.14.5 manager, including a
post-fix six-sample regression. The submission does not restore the earlier
two-decoder design.

## Upstream packaging requirements

As of 2026-08-02, the former
[`wazuh/wazuh-ruleset`](https://github.com/wazuh/wazuh-ruleset) repository is
archived and directs ruleset contributions to
[`wazuh/wazuh/ruleset`](https://github.com/wazuh/wazuh/tree/master/ruleset).

The live repository was checked on 2026-08-02. Its `main` branch no longer has
decoder, rule, or ruleset-test directories. The latest matching 4.14 branch,
`4.14.8`, retained them at commit
`f17b906579d1655b9a5093453c450eadf828f840`. At that commit the highest
numbered decoder was `0580-macos_decoders.xml` and the highest numbered rule
file was `0999-malicious-ioc-rules.xml`.

Candidate copies are prepared as:

- `upstream/decoders/0585-vestrix_decoders.xml`;
- `upstream/rules/1000-vestrix_rules.xml`; and
- `test.ini`.

Their placement is conditional:

- **If submitting through a confirmed legacy ruleset PR:** place the decoder
  at `ruleset/decoders/0585-vestrix_decoders.xml`, the rules at
  `ruleset/rules/1000-vestrix_rules.xml`, and the test file at
  `ruleset/testing/tests/vestrix.ini`, after rechecking filenames and IDs on
  the target commit.
- **If submitting through a confirmed Ruleset-as-Code or detection-engineering
  workflow:** adapt these source artifacts to that repository's documented
  structure and format. Do not assume it mirrors the legacy layout.

[`UPSTREAM_PATH_DECISION.md`](UPSTREAM_PATH_DECISION.md) records the blocking
destination decision and the live checks required before either placement is
used.

No occurrences of Vestrix rule IDs `100200–100211` were found in the branch's
rules, decoders, or tests. However, those IDs are inside Wazuh's
[documented `100000–120000` local/custom range](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html),
and no core rules in the checked branch use that band. They remain unchanged
in the candidate to preserve tested logic, but they are not presented as final
upstream IDs.

Before opening the upstream PR:

1. confirm the destination repository and branch using
   `UPSTREAM_PATH_DECISION.md`;
2. recheck candidate filename availability against that branch;
3. obtain an upstream core rule-ID block and update the rule XML and `test.ini`
   together;
4. run the upstream ruleset test and lint commands; and
5. recheck the target branch's current PR template and contribution guidance.

## References

- [Wazuh ruleset contribution instructions](https://github.com/wazuh/wazuh/blob/master/ruleset/README.md#contribute)
- [Wazuh custom decoder documentation](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
- [Wazuh custom rule documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Vestrix local verification procedure](README.md)
