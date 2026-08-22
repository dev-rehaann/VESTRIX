# forensics

Hash-chained event logger and OpenTimestamps anchoring interface.

Status: hash-chain logging, Ed25519 signing and verification, and concurrency-safe
append are implemented and tested. Chain format version 2 structurally distinguishes
`ingestion_accepted` records from `classification_decision` records and omits
inapplicable ML fields from ingestion records. The collector's default adapter fails
closed when append cannot complete. Collector rejections remain operational logs,
not signed-chain records. The production OpenTimestamps backend remains a
placeholder.
