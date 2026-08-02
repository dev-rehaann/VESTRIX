# Wazuh upstream path decision

**Status:** RESOLVED

**Decision:** Target the `main` branch of
[`wazuh/integrations`](https://github.com/wazuh/integrations). Submit the local
`upstream/vestrix_integration/` directory as
`integrations/vestrix_integration/` in that repository.

**Confirmed:** 2026-08-02

## Confirmation basis

The live repository and its root
[`CONTRIBUTING.md`](https://github.com/wazuh/integrations/blob/main/CONTRIBUTING.md)
were checked on the date above. The guide directs contributors to:

1. fork `wazuh/integrations`;
2. create a branch;
3. add a lowercase, underscore-separated directory under `integrations/`; and
4. submit a pull request to `wazuh/integrations`.

It lists `ruleset/`, `active_response/`, `sca/`, `threat_intel/`, and
`dashboards/` as integration component directories. The Vestrix package uses
that structure and includes explicit status files for components that are not
implemented.

## Superseded decision

The earlier unresolved choice between a legacy flat `wazuh/wazuh` ruleset PR
and an unspecified Ruleset-as-Code workflow is superseded. Neither is the
target for this submission package.

## Remaining submission gates

- Obtain maintainer approval for the final upstream rule-ID allocation.
- Run the official upstream checks from the current target branch.
- Recheck the target repository's PR template and licensing requirements
  immediately before submission.
