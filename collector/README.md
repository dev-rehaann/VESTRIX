# collector

mTLS ingest service that receives CSI data from sensor nodes.

Status: collector-side mTLS ingest, certificate-CN allow-listing, payload validation,
in-memory anti-replay checks, and the signed forensic handoff are implemented and
tested. Configure `VESTRIX_FORENSICS_PRIVATE_KEY` with an unencrypted Ed25519 PKCS#8
private-key path and, optionally, `VESTRIX_FORENSICS_STORE` with the JSONL path.
Accepted events are acknowledged only after a durable signed append; append failure
rejects the event. Rejected ingest attempts remain structured collector decision
logs and are not appended to the signed chain.

The chain-format-v2 adapter emits an `ingestion_accepted` record containing the
mapped `raw_csi_hash`, `collector_schema_version`, and
`collector_sequence_number`. It does not emit ML-only feature, model, class,
confidence, or SHAP fields. ESP32 client provisioning and automated certificate
enrollment/rotation are not implemented.
