# Wazuh upstream path decision

**Status:** Blocking — requires live confirmation against the current
`wazuh/wazuh` repository and its root `CONTRIBUTING.md` before submission.

**Last reviewed:** 2026-08-02

## Possible submission paths

### A. Legacy flat ruleset pull request

Use this path only if the selected `wazuh/wazuh` branch still accepts new
integrations through `ruleset/decoders/`, `ruleset/rules/`, and
`ruleset/testing/tests/`. In that case, recheck the numeric filenames and rule
IDs against the target commit before opening the PR.

### B. Ruleset-as-Code or detection-engineering workflow

Use this path only if the current `wazuh/wazuh` contribution documentation
links to an official repository or workflow for detection content. No specific
RaC repository name or directory layout is confirmed by this package. Follow
that repository's own `CONTRIBUTING.md`, schema, tests, naming, and licensing
requirements; do not assume it mirrors the legacy XML layout.

## Required live checks

Immediately before submission:

1. Inspect the current default branch and intended release branch of
   `wazuh/wazuh`.
2. Confirm whether `ruleset/decoders/`, `ruleset/rules/`, and
   `ruleset/testing/tests/` exist and accept external integration PRs.
3. Read the current root `CONTRIBUTING.md`, if present, plus any contribution
   document it links.
4. Check whether those documents link to a separate official RaC,
   detection-content, or detection-engineering repository.
5. If a separate repository is linked, verify its supported content format,
   destination paths, test command, ID policy, license, and PR template.
6. Record the selected repository, branch, and commit in `PR_DRAFT.md` before
   opening the PR.

Until these checks select a route, the files under `upstream/` are portable
source artifacts, not assertions about their final upstream paths.

## Fallback

If neither repository route can be confirmed, Wazuh's documented community
fallback is its users mailing list. Subscribe by emailing
`wazuh+subscribe@googlegroups.com`, then ask maintainers for the current
decoder/rule contribution path.
