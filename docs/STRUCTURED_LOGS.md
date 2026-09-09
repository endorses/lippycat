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

## RADIUS command selection

```bash
lc sniff radius -r radius.pcap --log-dir ./logs --log-streams radius
```

`sniff radius`, `tap radius`, and protocol-neutral `process` use the same optional
stream and schema. Dedicated `sniff radius` writes logs after ordinary selection
and reuses the same capture observation and scope as packet/CLI output, without
counting validation twice. Nonmatching competing requests still reach association
before selection. Logs do not activate LI, enable PCAP files, or establish capture
origin trust. Identity selection and transaction limits use shared `radius.*`
configuration. Each selected valid observation has its own record; an identity-free
response may carry a unique observational request association. Counters remain
separate from record fields. See [RADIUS operations](RADIUS.md) for state pressure,
scope and no-secret limitations. Distributed completion remains gated on Phase 7.
