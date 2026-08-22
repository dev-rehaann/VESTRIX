# collector

mTLS ingest service that receives CSI data from sensor nodes.

Status: collector-side mTLS ingest, certificate-CN allow-listing, payload validation,
in-memory anti-replay checks, and the signed forensic handoff are implemented and
tested. Configure `VESTRIX_FORENSICS_PRIVATE_KEY` with an unencrypted Ed25519 PKCS#8
private-key path and, optionally, `VESTRIX_FORENSICS_STORE` with the JSONL path.
Accepted events are acknowledged only after a durable signed append; append failure
rejects the event. Rejected ingest attempts remain structured collector decision
logs and are not appended to the signed chain.

The version-1 collector-ingest profile records `csi_window_sha256` as
`raw_csi_hash`, uses the SHA-256 of empty content when features are unavailable,
identifies the adapter in the model fields, records `collector_event_accepted` with
confidence `1.0` (transport acceptance, not ML confidence), and stores the collector
schema version and sequence number in `top_shap`. ESP32 client provisioning and
automated certificate enrollment/rotation are not implemented.
