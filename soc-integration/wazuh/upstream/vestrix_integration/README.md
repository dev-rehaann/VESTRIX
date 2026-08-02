# Vestrix-Wazuh Integration

## Introduction

This integration decodes Vestrix JSON physical-security events and applies
Wazuh rules for high-confidence intrusion, missing PACS correlation, sensor
tampering, and a composite authentication-anomaly correlation.

## Prerequisites

- Wazuh manager. Version 4.14.5 is the only version tested.
- One-line JSON events containing `"source":"vestrix"`.
- Prevalidated `confidence_level` values from Vestrix.

Compatibility with earlier Wazuh 4.x versions is untested.

## Installation and configuration

Install the XML files on the Wazuh manager:

- `ruleset/decoders/0585-vestrix_decoders.xml` under
  `/var/ossec/etc/decoders/`;
- `ruleset/rules/1000-vestrix_rules.xml` under `/var/ossec/etc/rules/`.

Preserve existing local files and permissions, then restart `wazuh-manager`.
The rule IDs remain subject to maintainer approval before upstream submission.

## Integration steps

Configure the operator's Vestrix-to-Wazuh transport to deliver one mapped JSON
event per record. The decoder selects only events whose `source` is `vestrix`.

## Integration testing

`ruleset/testing/test.ini` contains a positive detection, a negative non-match,
and a regression for the previously fixed JSON decoder-name collision. The
source integration was live-tested with `wazuh-logtest` on Wazuh 4.14.5.

## Included and omitted components

- Rules and decoder: included.
- Active response: not applicable; alerting/logging only.
- SCA: not applicable to this physical-layer sensor integration.
- Threat intelligence: not currently provided or consumed.
- Dashboard: planned, not yet built.

## Provenance and maintenance

- Original source: [Vestrix](https://github.com/dev-rehaann/VESTRIX).
- Adapted by: Vestrix contributors.
- Tested version: Wazuh 4.14.5.
- Maintainer: Vestrix project maintainers.
- Support boundary: community-maintained and provided as-is.

## Sources

- [Wazuh integrations repository](https://github.com/wazuh/integrations)
- [Wazuh integrations contribution guide](https://github.com/wazuh/integrations/blob/main/CONTRIBUTING.md)
