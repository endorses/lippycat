# Structured Protocol Logs

The structured protocol logging guide is part of the lippycat manual:

- [Structured Protocol Logs](manual/src/part5-advanced/structured-protocol-logs.md)

The versioned field and type contract remains in
[`structured-protocol-log-schema.md`](structured-protocol-log-schema.md).

RADIUS observations are available with `--log-streams radius` (and included in
the default stream set). The `radius` stream uses the same bounded queues,
overflow counters, TSV/JSONL encoders, rotation hooks, and graceful draining as
other streams. It records every message independently, including identity-free
responses and unsuccessful/ambiguous associations. It needs no LI task.
The [schema contract](structured-protocol-log-schema.md#radius-observation-stream-v1-additive-extension)
documents the exact attribute allowlist and binary representation; credentials,
authenticators and unknown attributes are absent from routine logs.
