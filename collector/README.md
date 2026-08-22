# collector

mTLS ingest service that receives CSI data from sensor nodes.

Status: collector-side mTLS ingest, certificate-CN allow-listing, payload validation,
and in-memory anti-replay checks are implemented and tested. ESP32 client
provisioning and automated certificate enrollment/rotation are not implemented.
