# Synthetic RADIUS acceptance fixtures

These deterministic fixtures define Phase 0 acceptance inputs for the
[identity contract](../../../../docs/design/radius-identity-contract.md) and
[observation contract](../../../../docs/design/radius-observation-contract.md).
They contain only synthetic identifiers and documentation IP addresses. They
are not production traffic or evidence of production decoder or MDF support.

Tests call `radiusfixture.Write(t)` to generate inputs in `t.TempDir()`.
No PCAP or raw binary files are committed or written into the source tree.
The independent observation golden lives in `testdata/expected.json` and is
embedded into the helper so tests do not depend on their working directory.

From the repository root:

```bash
GOCACHE=/tmp/lippycat-go-cache go test ./internal/pkg/testutil/radiusfixture
```

`acceptance.pcap` uses Ethernet link type 1 and deterministic microsecond
timestamps. `expected.json` maps each one-based PCAP record to its timestamp,
capture scope, administrative deployment binding, transport endpoints, code,
Identifier, outcome, ordered attribute value bytes, and expected association.
Capture scopes and deployment bindings are replay metadata: classic PCAP does
not encode them. Replay must assign each record its manifest scope. `poi-a` and
`poi-b` are shorthand for distinct configured POI/capture epochs; the transport
tuple deliberately overlaps between them. These bindings come from trusted
deployment configuration, not NAS attributes in the packet.

All six supported codes occur in both IP families. Authentication, accounting,
custom port 19120, multiple clients sharing Identifier 7, and overlapping tuples
in different scopes are included. Requests and responses have explicit expected
association references. The verifier checks compatible codes and reversed
endpoints within each scope independently of the generator's references.
Authenticators are deterministic opaque bytes, not shared-secret signatures;
association is observational.

Known-line mappings use operator-a/nas-a/poi-a with NAS-Port-Id `line-a` or DSL
Forum vendor 3561/type 1 `circuit-a`. The same wire values in
operator-b/nas-b/poi-b must not match either operator-a scoped criterion.
`matches_operator_a_nas_line` and `matches_operator_a_circuit_line` describe
direct scoped predicate results, not full LI authorization. Repeated User-Name,
grouped versus split VSAs, an unknown attribute, and a binary User-Name retain
their exact wire order and bytes. Calling-Station-Id uses
`02-00-00-00-00-01`; Ethernet addresses intentionally differ.

`raw/*.bin` contains the exact validated RADIUS message for every valid record,
including its original Authenticator. These are generated payload expectations for X2
tests, not encoded X2 PDUs. The first record contains UDP trailing bytes
`deadbeef`, excluded from its raw golden. Invalid AVP length, invalid nested VSA
length, truncated RADIUS data, a real IPv4 first fragment (24 bytes of a 28-byte
UDP datagram), and an IPv6 atomic fragment have no raw golden or attribution.
The IPv4 final fragment is intentionally absent. Fragment rejection precedes
RADIUS validation; generic packet output should retain the captured frame.

The standard-library-only checker independently parses generated PCAP/IP/UDP
headers, checks lengths and checksums where complete, walks AVP and nested VSA
boundaries, compares ordered observations and raw goldens, and verifies known
line scope and response associations. A separate check compares the generated observation manifest with the
committed JSON golden. Production decoder, task admission,
timeout/ambiguity behavior, and MDF interoperability require later-phase tests.
The fixture checker runs as part of `go test ./...`.
