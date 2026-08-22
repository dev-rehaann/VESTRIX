# collector

mTLS ingest service that receives CSI data from sensor nodes.

Status: collector-side mTLS ingest, certificate-CN allow-listing, CRL-based
revocation, SIGHUP reload of the allow-list and CRL, payload validation, and
in-memory anti-replay checks are implemented and tested. `certs/check_expiry.sh`
flags node certificates nearing expiry (30 days by default).

Revoke a certificate issued by the current CA tooling with
`bash certs/revoke_node.sh <node-id>`, distribute the regenerated `ca.crl` to the
configured `tls.crl_path`, and send SIGHUP to each collector process. Certificates
issued by the previous stateless script must be reissued before they can be tracked
and revoked through the CA database.

ESP32 client provisioning, automated certificate enrollment/rotation, OCSP, HSM
support, and passphrase-protected private keys are not implemented.
