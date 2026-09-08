# RADIUS identity and target contract

Date: 2026-09-08

Status: Phase 0 implementation contract and synthetic deployment profile. This
document specifies future runtime behavior; it does not claim that the RADIUS
matcher or X1 support is implemented. No operator has supplied a production
attribute mapping or approved the synthetic profile.

This resolves the identity decisions in the
[implementation plan](../plans/radius-poi-implementation.md). Association,
observation, and X2 decisions are specified in the
[observation contract](radius-observation-contract.md).

## Exact User-Name and textual targets

The matching key for User-Name is its complete value byte string, excluding the
AVP type and length. Equality is case-sensitive and length-sensitive. There is no
trimming, realm addition/removal, wildcard, substring, percent decoding, SIP
parsing, Unicode normalization, or case folding, including in realms.

An ordinary textual User-Name target is the UTF-8 encoding of the supplied Unicode
string, with no transformation. Require valid UTF-8, a nonempty value, and at most
253 encoded bytes. Reject invalid UTF-8 rather than replacing it with U+FFFD.
CLI, YAML, and X1 adapters must retain this meaning after their own syntax-level
unescaping. XML text means parsed character data: XML entity decoding occurs
before UTF-8 encoding. XML-forbidden characters and malformed XML are rejected
by the XML input boundary; arbitrary bytes use the AVP representation below.

An X1 `nai` must additionally satisfy the NAI grammar of RFC 7542 section 2.2 and
be NFC already. Validate NFC without rewriting the input. All grammar forms,
including username-only and realm-only NAIs, retain literal exact-match meaning;
`@example.test` is not a realm wildcard. Reject syntax-invalid or non-NFC `nai`
targets with a validation error directing the administrator to a complete
User-Name AVP when those bytes are intentional. This is a deliberate exact
observation profile, not AAA realm routing or normalization. NAI syntax and its
UTF-8/NFC basis are described in
[RFC 7542 sections 2.1–2.2](https://www.rfc-editor.org/rfc/rfc7542.html#section-2.1).

A structurally valid captured User-Name with invalid UTF-8 remains opaque bytes.
It can match a byte target supplied using `radiusAttribute`, but cannot match a
textual target. Display representations must distinguish valid text from hex
bytes; do not replace invalid bytes or concatenate repeated values. A zero-length
User-Name cannot be provisioned as a target. Packet validation must complete
before extracting any identity, including when a later AVP is malformed.

Keep the administrative kind (`nai`, account name, or line identity), original
target, and compiled byte predicate separate. X1 `nai` exclusively compiles to a
dedicated RADIUS User-Name filter. Phase 4 removes obsolete SIP filters and their
authorization evidence during migration; it does not change NAI targets into SIP
URI targets. Explicit SIP URI targets keep their own filtering path.

## Subscriber MAC profile

Select profile `calling-station-id-uppercase-hyphen-v1` explicitly for the
synthetic deployment. Its only subscriber MAC source is Calling-Station-Id
(attribute 31). The complete captured value must match
`^[0-9A-F]{2}(-[0-9A-F]{2}){5}$`: exactly 17 ASCII bytes representing six octets.
The canonical example is `02-00-00-00-00-01`. Require the same spelling for
ordinary textual MAC targets. An X1 `macAddress` adapter validates its schema
representation and yields exactly six octets; comparison is between those six
octets and the parsed captured value. Reject any non-six-octet target.

Lowercase hex, colons, dotted notation, bare hex, surrounding whitespace,
SSID/suffix decoration, NULs, and extra octets are outside this profile. They
produce no MAC identity; they do not make an otherwise structurally valid
RADIUS packet malformed. They may still be present in raw packet outputs. No
automatic fallback tries another convention. A malformed configured MAC target
is an activation/configuration error, never an empty or wildcard predicate.

The convention follows the uppercase hyphenated Calling-Station-Id form described
for IEEE 802.1X in
[RFC 3580 section 3.21](https://www.rfc-editor.org/rfc/rfc3580.html#section-3.21).
Selecting it here is a synthetic deployment decision, not evidence that an
arbitrary BRAS uses that convention. A production deployment must attest that
its selected attribute represents the subscriber. Ethernet source/destination,
NAS MACs, Calling-Station-Id decorations, and Called-Station-Id are never fallback
subscriber identities. MAC criteria require a configured profile; without it,
reject their provisioning while allowing other RADIUS observations.

## Complete AVP target subset

`radiusAttribute` represents exactly one complete binary AVP encoded as hex.
Accept ASCII hexadecimal digits in either case, with an even number of digits;
accept only leading/trailing XML whitespace (space, tab, CR, LF), consistent
with the XML hexBinary boundary. Reject internal whitespace, `0x`, separators,
non-hex characters, empty values, and concatenated AVPs. Canonical serialization
uses uppercase hexadecimal without whitespace. Decode first, then validate all
lengths; the same rules apply through activation, modification, restoration,
distribution, and round-trip serialization.

| Target           | Required decoded structure                                                                                           | Match key                    |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| User-Name        | Type 1; outer length equals decoded byte count; 1–253 value bytes                                                    | `(1, value bytes)`           |
| NAS-Port-Id      | Type 87; outer length equals decoded byte count; 1–253 value bytes                                                   | `(87, value bytes)`          |
| Agent-Circuit-Id | Type 26; four-byte big-endian vendor ID 3561 (`00000DE9`); exactly one type-1 vendor sub-attribute; 1–63 value bytes | `(26, 3561, 1, value bytes)` |

Every outer length includes its type/length octets and must fit one byte. For
the supported VSA, the vendor sub-attribute length includes its type/length
octets, must equal `2 + value length`, and the outer length must equal
`6 + vendor sub-attribute length`. The Agent-Circuit-Id size bound follows the
vendor format in
[RFC 4679 section 3.3.1](https://www.rfc-editor.org/rfc/rfc4679.html#section-3.3.1).
Reject zero-length target values, extra trailing bytes, additional sub-attributes
(even of unrelated types), unsupported outer types, other vendors, and other
vendor types. There is no target-side grouping shorthand or arbitrary byte
search. Raw account and line values may contain non-UTF-8 bytes; the byte target
does not perform text decoding.

Examples, including each complete AVP:

| Meaning                        | Hex                                        |
| ------------------------------ | ------------------------------------------ |
| User-Name `alice@example.test` | `0114616C696365406578616D706C652E74657374` |
| NAS-Port-Id `line-a`           | `57086C696E652D61`                         |
| Agent-Circuit-Id `circuit-a`   | `1A1100000DE9010B636972637569742D61`       |
| Opaque User-Name bytes `FF 00` | `0104FF00`                                 |

Captured packets have a different grouping rule from target provisioning.
Validate the complete RADIUS message and all outer AVP boundaries first. For
vendor 3561, validate every contained type/length/value boundary, including
unrecognized subtypes; type-1 values must respect the supported format. Unknown
vendors remain opaque after outer vendor-header validation; do not guess their
inner encoding. A malformed supported vendor container anywhere in the message
prevents identity attribution for the entire message. Valid unknown attributes
remain preserved in wire order and do not cause rejection merely for being
unknown.

After validation, any one repeated instance can satisfy a predicate. The same
Agent-Circuit-Id in a standalone VSA or grouped with valid other vendor
sub-attributes matches identically. Different instances never concatenate to
form a match. Container bytes remain unchanged for packet and X2 outputs.

## Task criteria and ownership

Support conjunctions of `nai`, subscriber MAC under the selected profile, and
the AVP subset above, within one configured dedicated POI scope. Each criterion
must independently match an exact instance in the same fully validated message
for direct attribution. Different repeated instances may satisfy different
criteria; no adjacency or same-container requirement is implied. An identical
criterion repeated twice does not require two wire occurrences. A response can
inherit a previously complete conjunction only under the association contract;
partial criteria are never accumulated across packets, requests, or tasks.

Each task owns its complete predicate and current generation independently.
Two tasks that match one request retain two separate references. Flattening
their filter IDs into an OR, or combining half of one task with half of another,
cannot authorize either task. Ordinary filters do not confer LI authorization.
Reject unsupported combinations, including RADIUS plus SIP/phone/IP/service
identity criteria, OR/negated predicates, and unsupported AVP-based NAS scope.
Do not silently discard an unsupported criterion. This initial release selects
dedicated deployment scope, not new conjunctive NAS-attribute target support.

## Dedicated POI scope and synthetic known lines

A profile binds one trusted capture deployment to one operator/NAS/access-domain
uniqueness boundary. Use dedicated POI capture inputs, isolation of mirrored
traffic, and authenticated source admission to enforce that boundary. An
interface name or packet-carried NAS identifier by itself is not evidence of
operator isolation. RADIUS proxies require a separately isolated feed covering
only the configured domain; if a mixed feed cannot prove line-value uniqueness,
reject line targeting there. Transport addresses and NAS attributes remain
separate observed fields and do not implicitly broaden or narrow scope.

Provisioning must explicitly select a resolved mapping profile bound to the POI;
bind that profile and its revision to task/filter evidence. If X1 cannot express
the deployment binding, the dedicated X1 endpoint has one administrator-configured
profile and activation is validated against it. There is no unspecified default
operator. Capture sources outside that profile, missing scope evidence, profile
changes, and unsupported remote scope capabilities reject LI admission. A
profile change invalidates existing task evidence and requires revalidation;
do not relabel queued observations into the new scope. Restart/reconnect capture
epochs are defined by the association contract, separately from this persistent
administrative profile.

The [synthetic fixtures](../../testdata/radius/) define these known-line mappings:

| Synthetic administrative line | Dedicated deployment         | Explicit resolved criterion        |
| ----------------------------- | ---------------------------- | ---------------------------------- |
| `operator-a/line-001`         | `operator-a / nas-a / poi-a` | NAS-Port-Id bytes `line-a`         |
| `operator-a/line-001`         | `operator-a / nas-a / poi-a` | Agent-Circuit-Id bytes `circuit-a` |
| `operator-b/line-001`         | `operator-b / nas-b / poi-b` | NAS-Port-Id bytes `line-a`         |
| `operator-b/line-001`         | `operator-b / nas-b / poi-b` | Agent-Circuit-Id bytes `circuit-a` |

These are alternative explicitly selected mappings, not an automatic OR.
The fixtures deliberately reuse both concrete values across operators. An
operator-a task must never own operator-b observations. `alice@example.test`
and `02-00-00-00-00-01` are synthetic subscriber identities, not a derivation
rule connecting every account or MAC to a line. Upstream inventory must resolve
administrative `lineID` to concrete values and sufficient scope before activation.
Unresolved administrative names, unknown profiles, absent scope, or a claim that
`line-a` is globally unique are rejected. lippycat does not query inventory or
infer a mapping from value spelling.

Production acceptance requires operator documentation identifying the emitting
NAS configuration, subscriber MAC convention, exact line attribute/value bytes,
uniqueness boundary, and a non-sensitive known-line trace verified against those
records. No such operator evidence is supplied in this repository. The fixture
profile permits implementation and reproducible acceptance work; it does not
establish a production operator agreement or standardized administrative-to-X1
conversion.
