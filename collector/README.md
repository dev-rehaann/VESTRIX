# collector

mTLS ingest service that receives CSI data from sensor nodes.

Status: collector-side mTLS ingest, certificate-CN allow-listing, CRL-based
revocation, SIGHUP reload of the allow-list and CRL, payload validation, and
in-memory anti-replay checks, and the signed forensic handoff are implemented and
tested. Configure `VESTRIX_FORENSICS_PRIVATE_KEY` with an unencrypted Ed25519 PKCS#8
private-key path and, optionally, `VESTRIX_FORENSICS_STORE` with the JSONL path.
Accepted events are acknowledged only after a durable signed append; append failure
rejects the event. Rejected ingest attempts remain structured collector decision
logs and are not appended to the signed chain. `certs/check_expiry.sh` flags node
certificates nearing expiry (30 days by default).

Revoke a certificate issued by the current CA tooling with
`bash certs/revoke_node.sh <node-id>`, distribute the regenerated `ca.crl` to the
configured `tls.crl_path`, and send SIGHUP to each collector process. Certificates
issued by the previous stateless script must be reissued before they can be tracked
and revoked through the CA database.

The chain-format-v2 adapter emits an `ingestion_accepted` record containing the
mapped `raw_csi_hash`, `collector_schema_version`, and
`collector_sequence_number`. It does not emit ML-only feature, model, class,
confidence, or SHAP fields.

ESP32 client provisioning, automated certificate enrollment/rotation, OCSP, HSM
support, and passphrase-protected private keys are not implemented.
