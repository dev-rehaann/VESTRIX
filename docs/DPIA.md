# Vestrix Data Protection Impact Assessment Template

| Field | Value |
|---|---|
| Document status | Proactive template; not a completed deployment assessment |
| Template version | 0.1.0 |
| Last updated | 2026-08-02 |
| Project | Vestrix open-source WiFi CSI intrusion-detection system |
| Controller | `[OPERATOR TO COMPLETE]` |
| Deployment / locations | `[OPERATOR TO COMPLETE]` |
| DPIA owner | `[OPERATOR TO COMPLETE]` |
| Data Protection Officer (DPO), if designated | `[OPERATOR TO COMPLETE]` |
| Approval date and approver | `[OPERATOR TO COMPLETE]` |
| Next review date | `[OPERATOR TO COMPLETE]` |

> **Important:** This document is a starting template. It is not a completed
> DPIA for any deployment, does not establish a lawful basis, and does not show
> that residual risks are acceptable. The deploying operator must replace the
> placeholders, verify every statement against its actual configuration, seek
> appropriate advice, approve the result before processing begins, and keep it
> under review.

No production Vestrix deployment or processing of real personal data had taken
place when this template version was prepared. The assessment is anticipatory:
it records foreseeable risks before Vestrix reaches production maturity and
gives operators a structured starting point for an assessment under Article 35
of the GDPR.

## 1. Purpose and scope of the DPIA

### 1.1 Purpose

Vestrix uses WiFi Channel State Information (CSI) to detect physical presence,
movement, and potential intrusion in a protected space. Although the default
design does not identify a person, occupancy and movement observations can
reveal whether a space is occupied, how occupancy changes, and patterns of
behavior over time. When those observations relate to an identified or
identifiable person—directly or through a zone, time, work schedule, access
record, household, or another data source—they may be personal data. A device
identifier, hash, or pseudonym does not by itself make associated data
anonymous.

Article 35 requires the controller to carry out a DPIA before processing that
is likely to result in a high risk to individuals' rights and freedoms. The
assessment must describe the processing and purposes, assess necessity and
proportionality, assess risks, and identify measures addressing those risks.
WiFi CSI sensing can involve innovative technology, systematic monitoring,
vulnerable individuals, workplace monitoring, or matching with other datasets.
An operator must therefore screen its actual deployment and document whether a
DPIA is legally required. This template takes the cautious position that a DPIA
is appropriate even where the final legal screening remains deployment-specific.

### 1.2 Scope

This template covers the intended Vestrix path from sensing through alert use:

```text
CSI sensor -> collector -> signal processing / ML classification
           -> forensic log -> Wazuh / OCSF -> SOC or SIEM
```

It covers raw CSI where an operator chooses to capture or retain it, derived
features, classifications, confidence and explanation data, timestamps and
zone metadata, forensic records, SOC alerts, backups, exports, and optional
correlation with access-control data. It does not assess the operator's wider
network, physical security, employment practices, incident response, or SIEM
except where those systems receive or affect Vestrix data.

### 1.3 Controller, processor, and software-project roles

Roles depend on facts, not product labels:

- The deploying operator normally decides why Vestrix is used, where sensors
  are placed, which people and spaces are monitored, what data is retained, who
  receives alerts, and how alerts are acted upon. The operator is therefore
  normally the **controller** and remains responsible for completing and
  approving its DPIA.
- The Vestrix open-source project publishes software. Merely publishing code or
  documentation does not make the project a controller or processor for a
  self-hosted operator deployment. Vestrix is a processor-adjacent technical
  tool, not a substitute for the controller's governance.
- A cloud host, managed security provider, installer, or support provider that
  processes operator data on documented instructions may be a **processor**.
  The operator must identify that party, complete appropriate Article 28 terms,
  assess subprocessors and transfers, and record the allocation of duties.
- A party that uses Vestrix data for its own purposes, or determines additional
  purposes or essential means, may instead be a controller or joint controller.

`[OPERATOR TO COMPLETE: identify every controller, joint controller, processor,
subprocessor, recipient, and the contract or other arrangement governing each.]`

A homeowner must obtain jurisdiction-specific advice on whether a personal or
household exemption applies. Monitoring shared, workplace, neighboring, or
publicly accessible space may fall outside such an exemption.

### 1.4 Consultation and approval record

| Participant | Consulted? | Advice or views | Decision / response |
|---|---|---|---|
| DPO, if designated | `[YES/NO/N/A]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |
| Information-security owner | `[YES/NO]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |
| Workers, occupants, or representatives | `[YES/NO]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |
| Processor(s) and SIEM provider | `[YES/NO/N/A]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |
| Legal or other specialist adviser | `[YES/NO/N/A]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |

The controller should seek and document the views of affected individuals or
their representatives where appropriate. If it does not consult them, or does
not follow material concerns raised, it should record and justify that decision.

## 2. Description of processing

### 2.1 Intended purpose

The template purpose is detection and investigation of unauthorized physical
presence or movement in defined protected zones, followed by a proportionate
security response. Vestrix is not designed for identity recognition, employee
performance measurement, attendance scoring, health inference, advertising,
or general behavioral analytics.

`[OPERATOR TO COMPLETE: state the precise purpose, protected interests,
locations, operating times, expected benefits, and actions that may follow an
alert. Delete or amend the template purpose if it is not accurate.]`

### 2.2 What Vestrix senses

CSI describes how WiFi signals propagate between radio endpoints. Movement and
changes in a physical environment can change CSI measurements. A processing
pipeline can derive signal features and classify a window as normal activity,
possible intrusion, or another configured class.

By default and by design, Vestrix does **not** require or intend to capture:

- images or video;
- audio or speech;
- MAC addresses of third-party devices;
- names or direct human identifiers; or
- biometric identifiers or biometric identification templates.

This is a design boundary, not proof that all outputs are anonymous. Timestamped
presence and movement observations can become identifying when linked to a
small household, a worker's schedule, badge/access-control data, CCTV, device
logs, or another dataset. A custom model that attempts unique-person,
health-related, emotion, or other sensitive inference is outside this template
and requires a new assessment before use.

### 2.3 Data categories

Depending on the deployment, Vestrix and connected systems may process:

| Category | Examples | Privacy relevance |
|---|---|---|
| Raw or buffered radio measurements | CSI windows, packet timing, radio metadata | May encode presence and movement patterns; storage is deployment-specific and is not governed by a Vestrix retention engine. |
| Derived signal data | Filtered windows, statistical features, feature hashes | May retain behaviorally meaningful patterns even without names. |
| Detection output | Class, confidence, model ID, top SHAP feature contributions | Describes activity at a time and place and may influence a security response. SHAP data explains feature contribution; it is not anonymization. |
| Sensor and event metadata | Node ID, site ID, zone ID, timestamps, sequence numbers | Can link an event to a specific place, household, shift, worker group, or access period. |
| Forensic integrity data | Raw-CSI and feature hashes, model-config hash, previous/record hash, Ed25519 signature | Supports evidence integrity and correlation. Hashing does not make linkable event data anonymous. |
| SOC / SIEM data | Event ID, class, confidence level, zone, node, model, record hash | Broadens access and may be copied, enriched, exported, or retained under separate SIEM policies. |
| Optional access-control correlation | PACS status, reader ID, event ID | May directly or indirectly associate an alert with an identifiable badge holder and materially increases re-identification risk. Current PACS integration is a placeholder contract, not an end-to-end feature. |

Data subjects may include residents, household members, employees, contractors,
visitors, customers, neighboring individuals within sensing range, emergency
responders, and alleged intruders. The operator must map the actual sensing
boundary; radio propagation and through-wall sensing can make the affected area
different from the intended physical zone.

### 2.4 Data flow, retention points, and access

The following describes the repository's intended architecture. It must not be
treated as a statement that every stage is implemented or enabled.

| Stage | Data and operation | Current Vestrix state | Retention point | Expected access |
|---|---|---|---|---|
| 1. Sensor | Capture CSI and optionally buffer or pre-filter it. | ESP32 firmware and sensor-side controls are not yet implemented. | Sensor memory, flash, or another operator-selected store. | Device administrators and anyone with physical or administrative access. |
| 2. Collector | Authenticate the node and accept an event containing `node_id`, timestamp, sequence number, and `csi_window_sha256`. | Server-side mTLS, allow-listing, identity binding, validation, and in-process replay checking are implemented. The current collector schema receives a CSI-window hash, not the raw window. The firmware client is not implemented. | Collector operational logs and any configured handoff destination. | Collector administrators and service accounts. |
| 3. Processing / ML | Clean signals, derive features, classify activity, and produce confidence and SHAP contributions. | The architecture and schemas define this stage; the production signal pipeline and trained model are not implemented. | Operator-selected feature, model, training, and raw-window stores. | ML operators, security engineers, and service accounts selected by the operator. |
| 4. Forensic log | Append explicitly typed `ingestion_accepted` or `classification_decision` records, chain links, hashes, and signatures to canonical JSONL. | Chain format version 2, its Python logger, and the independent Rust verifier are implemented. An ingestion record contains collector schema/sequence metadata but no ML fields; only a classification record contains feature/model/class/confidence/SHAP fields. The default adapter durably appends accepted collector events. Rejected attempts remain operational logs, and append failure causes rejection. | Local or operator-selected append-only JSONL store, backups, and any exported chain tips or timestamp proofs. | Evidence custodians, incident responders, legal teams, and system administrators as authorized by the operator. |
| 5. SOC / SIEM | Map a canonical alert to Wazuh JSON and OCSF Detection Finding, including site/zone and optional PACS correlation fields. | Mapper and tested Wazuh rules are implemented; no end-to-end dispatcher or operator-notification guarantee exists. | Wazuh, SIEM, ticketing, notification, archive, and backup systems. | SOC analysts, incident responders, administrators, service providers, and any downstream recipients configured by the operator. |

The controller must create a deployment-specific diagram showing every actual
store, log, backup, export, recipient, remote-support path, subprocessor, and
international transfer. The [architecture](architecture.md), [threat model](threat-model.md),
[forensic chain format](../forensics/CHAIN_FORMAT.md), and [SOC schema](../soc-integration/SCHEMA.md)
provide technical detail but do not replace that record.

### 2.5 Scale and context

`[OPERATOR TO COMPLETE]`

| Factor | Deployment answer |
|---|---|
| Physical zones and sensing boundary | `[OPERATOR TO COMPLETE]` |
| Public, workplace, residential, or restricted context | `[OPERATOR TO COMPLETE]` |
| Categories and approximate number of people affected | `[OPERATOR TO COMPLETE]` |
| Whether children or other vulnerable people may be sensed | `[OPERATOR TO COMPLETE]` |
| Collection frequency and operating schedule | `[OPERATOR TO COMPLETE]` |
| Estimated events and data volume | `[OPERATOR TO COMPLETE]` |
| Raw CSI retained? Where and for how long? | `[OPERATOR TO COMPLETE]` |
| Derived features retained? Where and for how long? | `[OPERATOR TO COMPLETE]` |
| Forensic and SOC retention periods | `[OPERATOR TO COMPLETE]` |
| Data combined with access control, CCTV, HR, or other sources? | `[OPERATOR TO COMPLETE]` |
| Recipients, processors, and international transfers | `[OPERATOR TO COMPLETE]` |

## 3. Necessity and proportionality assessment

### 3.1 Relationship to the stated purpose

CSI sensing can detect changes in a protected radio environment without
recording visual or audio content. This may reduce intrusion into private life
compared with continuously recording cameras or microphones. It does not make
CSI sensing automatically necessary or proportionate. Persistent, through-wall,
or workplace monitoring can itself be intrusive, particularly when individuals
cannot see, understand, or avoid it.

The controller must demonstrate:

1. the deployment is capable of achieving a specific, legitimate security
   purpose;
2. the sensing area, schedule, event classes, and downstream use are limited to
   that purpose;
3. a less intrusive measure cannot reasonably achieve the same result; and
4. the benefit is not outweighed by effects on occupants' rights and freedoms.

`[OPERATOR TO COMPLETE: record evidence for each point.]`

### 3.2 Alternatives considered

The controller must compare at least:

| Alternative | Potential privacy advantage | Reason accepted or rejected |
|---|---|---|
| Locks, access control, door/window contacts, or conventional alarm sensors | May detect entry without continuous occupancy or movement analysis. | `[OPERATOR TO COMPLETE]` |
| Passive infrared or other low-resolution presence sensors | May reveal less detailed movement information. | `[OPERATOR TO COMPLETE]` |
| Staff, patrol, or procedural controls | May avoid automated environmental monitoring but create other safety, cost, and privacy effects. | `[OPERATOR TO COMPLETE]` |
| Cameras or microphones | May provide stronger identification evidence but collect substantially richer visual or audio data. | `[OPERATOR TO COMPLETE]` |
| Reduced CSI scope | Fewer zones, shorter schedules, event-only processing, local processing, or no raw retention may reduce exposure. | `[OPERATOR TO COMPLETE]` |
| No monitoring | Avoids the processing and its privacy risks. | `[OPERATOR TO COMPLETE]` |

If a lower-intrusion alternative adequately meets the purpose, the controller
should use it or document why it is not reasonable.

### 3.3 Lawfulness, fairness, and transparency

`[OPERATOR TO COMPLETE: identify and document the Article 6 lawful basis. If
relying on legitimate interests, complete and retain an appropriate balancing
assessment. Do not assume consent is freely given in employment, tenancy, or
other relationships involving imbalance. Identify any applicable national law,
collective agreement, employment rule, or special-category-data issue.]`

Vestrix does not supply consent collection, privacy notices, signage, preference
management, or a lawful-basis decision. The operator must explain the processing
in clear language before it starts, including the sensing area, purpose, data
categories, retention, recipients, rights, contact point, and whether decisions
or security actions may follow an alert.

### 3.4 Data minimization and purpose limitation

Current design choices that can support minimization include:

- the collector's current event schema carries a SHA-256 reference to a CSI
  window rather than the raw CSI window itself;
- the forensic schema records raw/feature hashes, model provenance, a decision,
  confidence, and a feature-level SHAP snapshot rather than requiring raw CSI
  inside the forensic record; and
- the SOC schema omits several forensic fields and projects SHAP data to a
  narrow top-feature representation for Wazuh.

These are schema boundaries, not complete lifecycle controls. Raw CSI must be
created somewhere for sensing and may be stored elsewhere by the operator. Hash
values can remain linkable. SHAP data supports review of a model decision but
does not prevent secondary inference. Vestrix does not enforce a retention
period, delete expired records, aggregate occupancy data, or technically prevent
new purposes.

The operator should configure the smallest sensing area, shortest operating
schedule, least detailed event set, and shortest retention that meet the stated
security need. Normal/benign activity should not be forwarded or retained merely
because the schema permits it. Raw CSI should be retained only where the
controller documents why a hash and derived event are insufficient.

### 3.5 Accuracy and human intervention

No production accuracy or cross-environment benchmark exists. CSI models can be
sensitive to room geometry, placement, hardware, interference, and changes over
time. A confidence score is not proof that an intrusion occurred. The controller
must validate the deployed model in each environment, monitor error rates, and
provide proportionate human review before an alert leads to an adverse or
high-impact action. Vestrix alerts should not be repurposed as evidence of
employee misconduct, attendance, or individual behavior without a new legal and
technical assessment.

## 4. Identification and assessment of risks

### 4.1 Rating method

This template uses qualitative ratings:

- **Likelihood:** unlikely, possible, or likely.
- **Severity:** low, moderate, or high impact on an individual.
- **Overall risk:** low, medium, or high, based on both likelihood and severity.

The ratings below are cautious starting values, not findings for a specific
deployment. The controller must reassess inherent and residual risk using its
actual scale, location, affected people, retention, access, and mitigations.

### 4.2 Risk register

| ID | Risk to individuals | Initial likelihood / severity / overall | Relevant Vestrix control | Gap and operator action |
|---|---|---|---|---|
| R1 | Occupancy records disclose when a home, workplace, or protected zone is empty or occupied, enabling stalking, burglary, coercion, or other physical harm. | Possible / High / **High** | mTLS, certificate allow-listing, payload identity binding, and strict validation protect the implemented collector path against some unauthorized network access. | These controls do not provide authorization, encryption at rest, or safe downstream sharing. Apply least-privilege access, encryption at rest, secure backups, alert-content minimization, and short retention. Do not expose live occupancy dashboards publicly. |
| R2 | Timestamped movement reveals behavioral patterns such as sleep/wake times, work schedules, breaks, religious activity, disability-related routines, or household habits even without a name. | Possible / High / **High** | Default schemas avoid names, images, audio, and biometric identifiers; forensic records can reference raw CSI by hash. | Zone and time can still identify or single out people. Restrict zones and hours, avoid continuous history where event-only processing suffices, aggregate where possible, and prohibit behavioral or performance monitoring. |
| R3 | Vestrix data is re-identified by matching it with PACS/badge records, CCTV, HR schedules, device logs, or other datasets. | Possible / High / **High** | Separate node/event identifiers and a defined SOC schema make data flows inspectable. PACS correlation is currently only a placeholder contract. | Vestrix has no anonymization or linkage-prevention layer. Keep datasets separated, restrict correlation privileges, document every match purpose, and repeat the DPIA before enabling identity linkage or new inference. |
| R4 | Forensic records are used beyond physical intrusion detection—for employment discipline, attendance, productivity scoring, tenancy enforcement, family surveillance, or model training—creating unfair function creep. | Possible / High / **High** | Signed hash-chain records and model provenance support detection of record alteration and review of which model produced an event. | Integrity is not purpose limitation. Adopt binding policy, role restrictions, review/approval for new uses, staff training, and auditable access. Do not treat a tamper-evident log as permission to retain or reuse it indefinitely. |
| R5 | Wazuh/OCSF/SIEM integration distributes event, zone, confidence, SHAP, and optional access-control data to more people or systems than the original purpose requires. | Likely / Moderate to High / **High** | The canonical SOC schema defines and validates the fields sent to Wazuh and OCSF. | Vestrix does not control SIEM RBAC, exports, dashboards, tickets, notifications, or retention. Minimize forwarded fields, use need-to-know roles, audit access, assess recipients/processors, and align deletion across every downstream copy. |
| R6 | Long-lived or append-only forensic records frustrate storage limitation, erasure, restriction, or correction, and backups preserve data after the operational need ends. | Likely without operator controls / Moderate to High / **High** | Hash chaining and signatures make alteration detectable; the Rust CLI verifies integrity independently. | Vestrix has no retention or DSAR engine. Set retention before deployment. Design bounded chain segments or rotation periods so an expired segment can be deleted as a unit without silently corrupting an active chain; document treatment of backups, exported tips, and legal holds. Obtain legal advice before promising erasure that the design cannot perform. |
| R7 | Unauthorized access, stolen sensor credentials, compromised hosts, or malicious administrators expose or falsify events, leading to loss of confidentiality, false accusations, or unsafe security action. | Possible / High / **High** | Collector mTLS and anti-replay checks, Ed25519 signatures, hash linking, strict schemas, and the independent verifier reduce some transport-integrity and evidence-tampering risks. | Firmware mTLS is not implemented end to end; replay state is not durable; there is no built-in at-rest encryption, operator RBAC, credential rotation, or access-audit system. Implement these controls in the deployment and follow the residual risks in the [threat model](threat-model.md). |
| R8 | False positives, false negatives, model drift, or environmental change cause unnecessary intervention, failure to protect, reputational harm, or adverse treatment. | Possible / Moderate to High / **High** | The record format supports confidence, model/config provenance, feature hashes, and SHAP contributions for review. | The production ML pipeline and real-world validation are not complete. Validate per environment, monitor drift and error rates, keep a human in the response path, provide challenge/correction procedures, and avoid solely automated high-impact decisions. |
| R9 | Covert or unexpected sensing undermines autonomy and trust, especially for workers, tenants, children, visitors, or people sensed through walls or outside the intended zone. | Possible / High / **High** | No current Vestrix technical control resolves transparency or sensing-boundary risk. | Map and test the real radio boundary, avoid neighboring/public areas, give clear advance notice and on-site indication, consult affected groups, provide a contact and complaint route, and offer alternatives or opt-out where appropriate and lawful. |

### 4.3 Residual-risk decision

This project-level template cannot calculate deployment residual risk. The
controller must record, for every risk:

| Risk ID | Measures adopted | Owner | Due date | Residual likelihood | Residual severity | Residual risk | Approved / rejected |
|---|---|---|---|---|---|---|---|
| `[R1–R9]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` | `[OPERATOR TO COMPLETE]` |

If the assessment shows a high residual risk that the controller cannot reduce,
the controller must consult the competent supervisory authority before
processing where Article 36 or applicable local law requires it, and should
obtain jurisdiction-specific advice on that procedure.

## 5. Measures to reduce risk

### 5.1 Technical controls present in the repository

The following controls exist, subject to the implementation limits in the
[threat model](threat-model.md):

- **Transport authentication and integrity:** the collector implements mTLS,
  CA validation, an exact certificate-CN allow-list, and binding between the
  certificate CN and payload `node_id`. The ESP32 client is not implemented, so
  this is not yet an end-to-end production control.
- **Input and replay checks:** the collector enforces a strict payload schema,
  numeric and timestamp bounds, message-size limits, and a per-node increasing
  sequence number. Replay state is held in memory and is lost on restart.
- **Forensic integrity:** the logger uses a SHA-256 hash chain and Ed25519
  signatures, and the independent Rust CLI verifies canonical form, sequence,
  links, hashes, and signatures. These controls address integrity, not
  confidentiality, retention, lawfulness, or data-subject rights.
- **Data-flow schemas:** the collector, forensic, and SOC schemas constrain
  expected fields and make unintended additions easier to detect. They do not
  govern separate raw-data stores or downstream SIEM enrichment.
- **Explainability and provenance fields:** the forensic and SOC contracts
  support model ID, model-config hash, confidence, feature hash, and SHAP
  contributions. These can support human review and avoid requiring a full raw
  window in every alert. The production ML/SHAP generation path is not yet
  implemented, and explainability is not anonymization.
- **Independent verification:** the verifier is separated from the writer,
  reducing reliance on the component that created the evidence.

### 5.2 Controls not provided by Vestrix

As of this template version, Vestrix does **not** provide:

- automatic retention, expiry, deletion, legal-hold, or backup-deletion policy
  enforcement;
- a raw-CSI lifecycle or deletion mechanism;
- data-subject access, export, correction, restriction, objection, or erasure
  request tooling;
- consent, lawful-basis, privacy-notice, signage, or preference-management
  tooling;
- anonymization, aggregation, differential privacy, or a technical barrier to
  dataset matching and re-identification;
- built-in user RBAC, access reviews, or audit logs for reads and exports;
- encryption at rest or deployment-wide key management;
- automatic certificate revocation, rotation, or durable replay state;
- an end-to-end dispatcher connecting the collector through ML and SOC stages
  (the direct accepted-event collector-to-forensics handoff is implemented);
- an implemented production model, SHAP generator, or real-world accuracy and
  generalization results;
- a visible sensor-active indicator, opt-out mechanism, or sensing-boundary
  enforcement;
- processor-contract, subprocessor, international-transfer, breach-response,
  or supervisory-authority consultation workflows; or
- a guarantee that a connected SIEM, ticketing system, or notification service
  deletes or restricts data consistently.

The operator must implement or procure the measures its completed DPIA finds
necessary. Where a required measure cannot be implemented, the operator must
reassess whether the deployment should proceed or whether its scope should be
reduced.

### 5.3 Recommended operator measures

At minimum, the operator should consider:

1. local processing and event-only forwarding where raw CSI is not necessary;
2. strict zone, schedule, and radio-boundary limits;
3. short, documented retention by data category and by downstream system;
4. chain segmentation/rotation compatible with the retention schedule;
5. encryption at rest and in backup, managed keys, certificate rotation, and
   secure credential storage;
6. least-privilege roles separating SOC response, system administration,
   evidence custody, HR, and other functions;
7. read/export audit logs, periodic access review, and alerting for bulk access;
8. field minimization before Wazuh/OCSF export and restricted PACS correlation;
9. human confirmation before consequential action;
10. clear notices, worker/occupant consultation, a visible indication where
    appropriate, and a usable rights/complaints contact;
11. deployment-specific accuracy, boundary, security, and failure testing; and
12. incident response, breach assessment, processor oversight, and transfer
    safeguards.

## 6. Operator responsibilities checklist

The deploying operator, normally acting as controller, must complete this
checklist before production processing. Vestrix does not complete these duties
on the operator's behalf.

### Governance and legal basis

- [ ] Identify the controller, any joint controllers, processors,
  subprocessors, and recipients; document their responsibilities and contracts.
- [ ] Screen whether Article 35 or applicable national rules require a DPIA;
  record the result even if the conclusion is that no DPIA is mandatory.
- [ ] Complete this deployment-specific DPIA, obtain approval before processing,
  and record the advice of the DPO where one is designated.
- [ ] Define a specific security purpose and an Article 6 lawful basis; complete
  any required legitimate-interests or other supporting assessment.
- [ ] Determine whether the deployment could process special-category,
  criminal-offence, employment, child, tenant, or other specially regulated data.
- [ ] Record the processing in the applicable record of processing activities.
- [ ] Consult affected workers, occupants, residents, or representatives where
  appropriate, and document how their views affected the deployment.
- [ ] Consult the competent supervisory authority before processing where
  required because high residual risk cannot be mitigated.

### Scope, transparency, and fairness

- [ ] Map and test the real sensing boundary, including through-wall,
  neighboring, shared, and publicly accessible areas.
- [ ] Limit sensors, zones, event classes, operating hours, and alert recipients
  to what is necessary for the documented purpose.
- [ ] Provide clear advance privacy information and appropriate on-site notices
  to employees, visitors, residents, contractors, and other affected people.
- [ ] Provide a contact and process for questions, complaints, objections, and
  rights requests; offer an alternative or opt-out where appropriate and lawful.
- [ ] Prohibit use for identity recognition, attendance, productivity,
  performance, health, or behavioral profiling unless a new DPIA and lawful
  basis expressly cover that purpose.
- [ ] Require proportionate human review before alerts produce adverse or
  similarly significant effects.

### Data lifecycle and individual rights

- [ ] Inventory every copy: sensor buffers, raw CSI, feature stores, collector
  logs, forensic chains, SOC/SIEM, tickets, notifications, exports, and backups.
- [ ] Define and technically enforce a retention period for each category and
  system; justify any difference between raw, derived, forensic, and SOC data.
- [ ] Design forensic chain rotation and deletion so expired segments can be
  disposed of consistently with integrity, backup, legal-hold, and erasure duties.
- [ ] Avoid raw CSI retention unless its necessity is documented; do not assume
  a hash or pseudonymous node ID is anonymous.
- [ ] Build and test procedures for access, correction, restriction, objection,
  portability where applicable, and erasure; identify how requests will be
  located where Vestrix has no human-identity index.
- [ ] Ensure processors and downstream systems can support the same retention
  and rights outcomes.

### Security and operations

- [ ] Enforce least privilege, role separation, strong authentication, access
  reviews, and audit logging for reads, searches, exports, and configuration.
- [ ] Encrypt data at rest and backups; manage and rotate encryption, signing,
  and node credentials; define revocation and compromise procedures.
- [ ] Minimize fields and recipients in Wazuh/OCSF, tickets, dashboards, and
  notifications; separately approve any PACS or other dataset correlation.
- [ ] Validate model accuracy, false-positive/negative rates, drift, sensor
  placement, and sensing boundaries in the actual environment.
- [ ] Maintain incident-response and personal-data-breach procedures, including
  processor notification and supervisory/data-subject notification assessment.
- [ ] Assess international transfers, remote support, cloud hosting, and
  subprocessors; implement required transfer safeguards.
- [ ] Train administrators, analysts, responders, and managers on purpose limits,
  confidentiality, alert uncertainty, and individual-rights handling.

### Review triggers

- [ ] Review the DPIA on a defined schedule and before adding zones, increasing
  scale or operating hours, extending retention, or changing recipients.
- [ ] Repeat or materially update it before storing new raw data, correlating
  identity/access datasets, adding new models or inferred classes, monitoring
  workers, enabling remote/cloud processing, or making consequential decisions.
- [ ] Review after a security incident, material accuracy failure, complaint,
  legal change, hardware/firmware change, or change in the nature, scope,
  context, purpose, or risk of the processing.

## 7. Document status and disclaimer

This document is an anticipatory template maintained by the Vestrix project. It
is not a completed assessment of any particular installation and has not been
approved by a supervisory authority. It is not legal advice, does not determine
whether GDPR or another law applies, and does not ensure or certify compliance.
Controllers remain responsible for their deployment choices and should obtain
review from a qualified lawyer, DPO, or other appropriate adviser.

The template reflects the repository state and public guidance available on
2026-08-02. It must be reviewed as Vestrix gains firmware, ML, retention,
deployment, or data-rights functionality and whenever legal or regulatory
guidance changes.

### References

1. European Union, [Regulation (EU) 2016/679, Article 35 — Data protection impact assessment](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679).
2. European Data Protection Board, [endorsed WP29 Guidelines on Data Protection Impact Assessment (WP248 rev.01)](https://www.edpb.europa.eu/endorsed-wp29-guidelines_en).
3. European Data Protection Board, [Guidelines 07/2020 on the concepts of controller and processor in the GDPR](https://www.edpb.europa.eu/documents/guideline/guidelines-072020-on-the-concepts-of-controller-and-processor-in-the-gdpr_en).
4. UK Information Commissioner's Office, [Data Protection Impact Assessments](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/). ICO guidance concerns the UK GDPR and is informative rather than authoritative for EU GDPR deployments; operators must check current guidance from their competent authority.
5. Vestrix, [Threat Model](threat-model.md), [Architecture](architecture.md), [Forensic Chain Format](../forensics/CHAIN_FORMAT.md), and [SOC Alert Schema](../soc-integration/SCHEMA.md).

### Version history

| Version | Date | Change |
|---|---|---|
| 0.1.0 | 2026-08-02 | Initial proactive operator DPIA template. |
