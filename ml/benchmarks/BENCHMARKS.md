# Vestrix Benchmarks

## Purpose

This file is the permanent benchmark record for Vestrix and is updated for every release. A release without a new benchmark records that fact rather than reusing an earlier result as if it were new. Published numbers are never overwritten or removed. Corrections, regressions, and replacement runs are appended as new dated entries with links to the earlier results they supersede.

This record exists to prevent the inflated-benchmark failure mode common in WiFi CSI sensing research. The [project rationale](../../docs/INITIALIZATION.md) identifies RuView's retracted "100% presence detection" claim as a concrete example. A same-room or otherwise in-distribution score must not be presented as evidence of cross-room, cross-device, or production performance. Every claim must identify its dataset, split, hardware, firmware, model, and raw supporting results.

> No production accuracy claims exist for Vestrix as of this document's creation. This section will be populated as real benchmark runs are completed and will never be edited to remove or soften an unflattering earlier result — only appended to with dated new entries.

## Methodology

Copy this section for each benchmark run. Replace every `PENDING` field and link the completed entry from the versioned results log.

### Benchmark run: `PENDING — YYYY-MM-DD / short identifier`

#### Dataset

| Field | Value |
|---|---|
| Dataset name and version | `PENDING` |
| Dataset location or DOI | `PENDING` |
| Collection dates | `PENDING` |
| Size | `PENDING — recordings, sessions, samples/windows, duration, subjects, rooms, and devices` |
| Classes and class counts | `PENDING` |
| Environment description | `PENDING — room dimensions/layout, construction, furniture, occupancy, sensor placement, and relevant RF conditions` |
| Collection protocol and labeling method | `PENDING` |
| Exclusions or discarded data | `PENDING — include reasons and counts; write "None" if applicable` |

#### Train/test split

| Field | Value |
|---|---|
| Split type | `PENDING — same-room (in-distribution), leave-one-room-out, or leave-one-device-out; list each evaluated split` |
| Split unit | `PENDING — subject, session, room, device, or another unit` |
| Train/validation/test sizes | `PENDING` |
| Held-out subjects, sessions, rooms, and devices | `PENDING` |
| Fold construction | `PENDING — folds, grouping rules, stratification, and random seed` |

Data-leakage self-check:

- [ ] Confirm that no recording session or derived window appears in more than one split.
- [ ] Confirm that no subject appears in both train and test. If subjects overlap by design, identify them and label the result in-distribution rather than generalized.
- [ ] Confirm that room and device overlap matches the declared split type. Any overlap must be listed explicitly.
- [ ] Confirm that duplicate or near-duplicate samples were grouped before splitting.
- [ ] Confirm that normalization, feature selection, calibration, resampling, and augmentation were fitted or derived from training data only.
- [ ] Confirm that test labels and test-set results were not used for model selection or threshold tuning.

Any unchecked item requires an explanation and limits the claims that may be made from the run.

#### Collection hardware and firmware

| Field | Value |
|---|---|
| ESP32 model, board revision, and device IDs | `PENDING` |
| Antenna and physical placement | `PENDING` |
| WiFi channel, bandwidth, and CSI collection settings | `PENDING` |
| Firmware version or commit | `PENDING` |
| ESP-IDF version | `PENDING` |
| Calibration or device-specific preprocessing | `PENDING — write "None" if not used` |

#### Model and confidence calibration

| Field | Value |
|---|---|
| Model type | `PENDING` |
| Model version | `PENDING — for example, rf_v1.4.2` |
| Training code commit and configuration | `PENDING` |
| Decision threshold | `PENDING` |
| Confidence calibration method | `PENDING — method, calibration split, and calibration metrics; write "None" if not used` |

## Required Reported Metrics

Complete every table for each benchmark run. Use counts as well as rates, define the positive class, and state whether multiclass rates are micro-, macro-, weighted-, or one-vs-rest aggregates.

### Aggregate and per-class performance

- **Overall accuracy:** `PENDING`
- **Evaluation sample count:** `PENDING`
- **Positive class:** `PENDING`

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| `PENDING — class name` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |

### Confusion matrix

Report the full matrix as raw counts. Add rows and columns for every class; do not replace it with a single aggregate score.

| Actual \ Predicted | `PENDING — class A` | `PENDING — class B` |
|---|---:|---:|
| `PENDING — class A` | `PENDING` | `PENDING` |
| `PENDING — class B` | `PENDING` | `PENDING` |

### Error rates

- **False positive rate (FPR = FP / (FP + TN)):** `PENDING`
- **False negative rate (FNR = FN / (FN + TP)):** `PENDING`
- **Aggregation method, if multiclass:** `PENDING`

### Per-environment and per-room breakdown

Do not report only a blended result.

| Environment | Room | Device(s) | Samples | Accuracy | FP rate | FN rate | Macro F1 | Notes |
|---|---|---|---:|---:|---:|---:|---:|---|
| `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |

### Distribution and generalization breakdown

Report in-distribution, leave-one-room-out, and leave-one-device-out results as separate rows. A missing evaluation must be marked `NOT TESTED`, not omitted.

| Split type | Held-out unit(s) | Samples | Accuracy | FP rate | FN rate | Macro F1 | Raw result link |
|---|---|---:|---:|---:|---:|---:|---|
| Same-room / in-distribution | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| Leave-one-room-out | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |
| Leave-one-device-out | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |

### Adversarial and evasion conditions

Publish every tested condition, including negative, failed, or otherwise unflattering results. Examples include slow movement, motion along weak sensing paths, deliberate evasion attempts, environmental interference, and placement changes. Mark this section `NOT TESTED` if no such evaluation was performed.

| Condition | Procedure | Samples | Accuracy | FP rate | FN rate | Observed failures | Raw result link |
|---|---|---:|---:|---:|---:|---|---|
| `PENDING or NOT TESTED` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` | `PENDING` |

## Versioned Results Log

Append one row per published benchmark run. Do not edit or delete earlier rows when a later run changes a result.

| Date | Vestrix version | Model version | Dataset version | Split type | Accuracy | FP rate | FN rate | Link to raw results/confusion matrix |
|---|---|---|---|---|---:|---:|---:|---|
| **PENDING — no benchmark run yet** | — | — | — | — | — | — | — | — |

## Known Limitations

These limitations apply to ESP32 CSI benchmarks generally and must be considered in addition to run-specific limitations:

- CSI phase is affected by oscillator mismatch, carrier and sampling frequency offsets, packet timing, and device noise. Phase-derived features require explicit sanitization and validation.
- ESP32 chip, board, antenna, RF front-end, orientation, and placement differences can produce device-specific signatures that a model may learn instead of the target event.
- Firmware, ESP-IDF, CSI configuration, preprocessing, or hardware revisions can change the input distribution. Results must be re-validated after such changes; an earlier benchmark does not automatically transfer.
- Multipath behavior depends on room geometry, construction materials, furniture, sensor placement, occupancy, and neighboring RF traffic. Same-room performance does not establish cross-room performance.
- Cross-room and cross-device generalization are expected to be weaker than in-distribution performance and must be measured separately.
- Packet loss, interference, traffic generation, channel selection, and effective sampling rate can differ between collection and deployment.
- Windowed samples from one recording are correlated. Randomly splitting windows can inflate results even when exact samples do not overlap.
- Label timing and human annotation can be uncertain, especially near transitions between activity classes.
- Dataset class balance may not match deployment prevalence. Accuracy alone can conceal an operationally unacceptable false positive or false negative rate.
- Tested subjects, movement patterns, environments, and evasion conditions cannot represent every deployment. Untested conditions must not be described as supported.
- Confidence scores are not probabilities unless calibration has been measured on appropriately held-out data, and calibration may drift across rooms and devices.
