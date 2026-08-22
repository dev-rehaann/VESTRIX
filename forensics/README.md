# forensics

Hash-chained event logger and OpenTimestamps anchoring interface.

Status: hash-chain logging, Ed25519 signing and verification, and concurrency-safe
append are implemented and tested. The collector's default adapter now appends each
accepted ingest event using the version-1 collector-ingest profile and fails closed
when the append cannot complete. Collector rejections remain operational logs, not
signed-chain records. The production OpenTimestamps backend remains a placeholder.
