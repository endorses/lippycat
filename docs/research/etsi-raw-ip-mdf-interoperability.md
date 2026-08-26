# ETSI raw-IP delivery and MDF interoperability

**Date:** 2026-08-26

**Scope:** standards-based raw IPv4/IPv6 delivery from a lippycat POI to an
independently implemented MDF over ETSI X2/X3

**Decision:** implement uncorrelated raw-IP CC as an explicit ETSI TS 103 221-2
X3 destination profile; do not claim portable correlated raw-IP IRI/CC until a
service-specific LI architecture defining communication lifecycle and
correlation has been selected

## Executive summary

ETSI TS 103 221-2 explicitly defines IPv4- and IPv6-packet payload formats and
permits both formats in X2 and X3 PDUs. It therefore provides a standardized
wire representation for handing complete IP packets from a point of
interception (POI) to a mediation and delivery function (MDF).

The same specification does not define a universal raw-IP communication model.
It delegates selection of X2 versus X3, correlation-ID generation, and some
conditional-attribute use to the relevant LI architecture. It also permits a
POI that does not correlate a PDU with other PDUs to set the Correlation ID to
zero.

Consequently, lippycat can interoperate with independently implemented MDFs for
a deliberately limited base profile:

- complete IPv4 or IPv6 packets carried as X3 content;
- no synthetic flow IRI;
- Correlation ID zero;
- explicit destination capability for this profile;
- standard XID, timestamp, sequence, direction, and target metadata.

This is portable raw content delivery, not correlated IRI/CC session delivery.
A normalized five-tuple, idle timeout, TCP termination policy, and generated
BEGIN/END events would be lippycat-specific semantics unless adopted from an
additional standardized LI architecture. Such behavior must not be presented
as generic TS 103 221-2 interoperability.

## 1. Standards boundary

### 1.1 Raw IP is a defined X2/X3 payload

ETSI TS 103 221-2 V1.4.1 clause 5.4.1, table 7 defines:

| Value | Payload format | X2 | X3 |
|---:|---|:---:|:---:|
| 5 | IPv4 Packet | Yes | Yes |
| 6 | IPv6 Packet | Yes | Yes |
| 7 | Ethernet Frame | No | Yes |
| 8 | RTP Packet | No | Yes |

Clauses 5.4.6 and 5.4.7 require the payload to contain an IPv4 packet encoded
according to RFC 791 or an IPv6 packet encoded according to RFC 8200. Clause
5.4.1 recommends choosing the payload with the most encapsulation when several
formats are available; it specifically prefers an IPv4 packet over a stripped
RTP packet when the IPv4 data is available.

This establishes a standard byte-level representation for raw IP. It does not,
by itself, establish the interception service semantics around those bytes.

Primary reference:

- [ETSI TS 103 221-2 V1.4.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.04.01_60/ts_10322102v010401p.pdf), clauses 5.4.1 and 5.4.6 to 5.4.9

### 1.2 Payload format does not select X2 or X3

Clause 5.1 states that each PDU is sent over an X2 or X3 interface and that the
choice for a particular PDU is given by the relevant LI architecture. The
payload table permits IPv4 and IPv6 on both interfaces, reinforcing that the
payload-format value cannot be used as the routing decision.

For lippycat, destination configuration must therefore select the handover
profile and interface. Seeing `PayloadFormatIPv4` or `PayloadFormatIPv6` is not
sufficient grounds to infer X3, even though the portable profile recommended by
this report deliberately assigns raw packet content to X3.

### 1.3 Correlation is conditional and architecture-defined

Clause 5.2.8 requires PDUs associated with the same communication session to
use the same Correlation ID when the POI correlates them. The value must be
unique within its context, but the generation scheme is defined by the relevant
LI architecture. Cross-POI conventions are explicitly outside the scope of TS
103 221-2.

The same clause requires Correlation ID zero when the POI does not correlate a
PDU with any other X2/X3 PDU. This supplies a standards-defined representation
for independent raw packet PDUs without requiring lippycat to invent session
semantics.

Annex A nevertheless requires X2 and X3 to provide information needed by the
MDF to correlate HI2 and HI3 where applicable. Uncorrelated raw CC is therefore
a narrower capability than a complete correlated interception product.

Primary reference:

- [ETSI TS 103 221-2 V1.4.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.04.01_60/ts_10322102v010401p.pdf), clause 5.2.8 and annexes A.1.10, A.1.11, A.3.10, and A.3.11

## 2. Why arbitrary-MDF interoperability needs a profile

“Arbitrary MDF” cannot mean that every conforming MDF must accept every
optional payload and architecture. TS 103 221-2 is intentionally a flexible
internal interface used by multiple LI architectures. Two implementations may
both conform to it while supporting different payload sets, mediation models,
or national profiles.

For this report, implementation independence means:

> Any MDF that declares support for the same named ETSI profile can consume
> lippycat output without vendor-specific interpretation.

That requires the profile to state at least:

- the X2/X3 interface used for each product;
- accepted payload formats;
- correlation behavior;
- required conditional attributes;
- sequencing context;
- whether IRI accompanies CC;
- applicable downstream handover or service-specific standard.

Without this declaration, successful TLS delivery only proves transport
compatibility. It does not prove that the MDF can mediate the received product.

## 3. Portable base profile for lippycat

### 3.1 Profile definition

Define a destination capability named, for example:

```text
etsi-ts-103-221-2-raw-ip-x3-uncorrelated
```

Its normative lippycat behavior should be:

1. Carry a complete IPv4 or IPv6 network-layer packet in an X3 PDU.
2. Use payload format 5 for IPv4 and 6 for IPv6.
3. Set Correlation ID to zero.
4. Do not generate synthetic X2 IRI, communication BEGIN, CONTINUE, END, or
   REPORT events.
5. Populate the XID assigned through X1.
6. Populate the interception timestamp from the packet's capture timestamp.
7. Populate payload direction relative to the target when it is determinable;
   otherwise use the standardized unknown value.
8. Populate the matched target identifier using the TS 103 221-2 encoding.
9. Maintain X3 sequence numbers in the context required by clause 5.3.9.
10. Deliver only to destinations that explicitly declare this profile.

Ethernet frames should be a separate capability. Payload format 7 is permitted
only on X3 and exposes link-layer data that an MDF accepting raw IP is not
necessarily prepared to mediate.

### 3.2 Provisioning rules

An IPv4/IPv6 address or CIDR target may be activated only when every selected
destination:

- has X3 enabled;
- declares the uncorrelated raw-IP profile;
- supports the required IP version;
- has an established policy for accepting Correlation ID zero.

`X2Only` must be rejected for this profile. `X2andX3` should also be rejected
unless a separate correlated or IRI-producing profile is selected, because the
base profile has no defined X2 product to send.

Unknown or legacy destinations must fail closed. Backward-compatible treatment
of absent destination capability metadata is inappropriate for a newly enabled
raw-IP path.

### 3.3 Suggested model

```go
type DestinationProfile string

const (
    ProfileTS1032212VoIP DestinationProfile =
        "etsi-ts-103-221-2-voip"
    ProfileTS1032212RawIPX3Uncorrelated DestinationProfile =
        "etsi-ts-103-221-2-raw-ip-x3-uncorrelated"
)

type RawIPCapabilities struct {
    IPv4    bool
    IPv6    bool
    Ethernet bool
    AcceptsZeroCorrelationID bool
}
```

These fields must be durable, included in destination equivalence and
modification, returned through status APIs, and validated before task state or
filters change.

## 4. Relationship to ETSI handover specifications

ETSI TS 102 232-1 defines the external IP handover envelope. It uses a
communication identity and IRI types BEGIN, CONTINUE, END, and REPORT. Its
sequence-number guidance says service-specific standards define which events
start a new sequence context; as general guidance, a session starts when an
IRI-BEGIN would be sent and ends when an IRI-END would be sent.

This does not create a universal rule that each observed IP five-tuple is an LI
communication. The relevant service-specific standard or architecture still
has to define the events and identity applicable to the intercepted service.

Primary reference:

- [ETSI TS 102 232-1 V3.33.1](https://www.etsi.org/deliver/etsi_ts/102200_102299/10223201/03.33.01_60/ts_10223201v033301p.pdf), clauses 5.2.5, 5.2.9, and 5.2.10

The MDF may mediate TS 103 221-2 data into TS 102 232 products, but lippycat
cannot assume how that mediation is performed unless the destination profile
states it.

## 5. Correlated raw-IP sessions are a separate capability

A future profile may provide correlated X2 IRI and X3 CC, but it must name the
additional architecture that defines its semantics. Only then should lippycat
implement:

- bidirectional communication identity;
- session start and end events;
- TCP close/reset handling;
- UDP and other-protocol inactivity behavior;
- tuple-reuse rules;
- fragmentation handling;
- generated IRI content;
- mapping of the X2/X3 Correlation ID into the MDF's handover communication
  identity;
- restart, eviction, and task-deactivation behavior.

A normalized five-tuple may be part of such an implementation, but it is not a
generic requirement of TS 103 221-2. Timeout values and reuse behavior must
come from the selected profile or be explicitly identified as deployment
policy agreed by both endpoints.

Recommended capability separation:

| Capability | Product | Correlation | IRI lifecycle |
|---|---|---|---|
| Raw-IP X3 uncorrelated | Complete IP packets on X3 | Zero | None |
| Raw-IP session profile | Architecture-defined X2 and X3 | Required | Architecture-defined |

## 6. Capability discovery and configuration

The portable profile still requires both endpoints to agree that it is
supported. Suitable mechanisms, in descending order of preference, are:

1. a standardized X1 configuration or generic-object capability declaration;
2. a published ETSI conformance profile supported by both products;
3. explicit destination configuration in lippycat;
4. a deployment-time interoperability test recorded as destination metadata.

Automatic probing must not send live intercepted content. If no standardized
capability negotiation exists for the chosen revisions, explicit configuration
is preferable to inference from a destination's general `X3Enabled` flag.

## 7. Implementation outline

1. Extend destination configuration and persistence with a named profile and
   raw-IP capabilities.
2. Extend X1 capability validation so IP targets require the explicit raw-IP
   profile at every selected destination.
3. Permit only `X3Only` for the uncorrelated profile.
4. Re-enable the raw-IP encoder behind that validation gate.
5. Strip link-layer framing when necessary so payload formats 5 and 6 contain
   exactly the network-layer packet required by the standard.
6. Set Correlation ID to zero; remove target-derived correlation hashes.
7. Preserve capture timestamps and add standardized conditional attributes.
8. Route by destination profile and X3 capability, never by payload format.
9. Add bounded metrics for accepted packets, encoding failures, unsupported
   link types, ambiguous direction, and destination/profile mismatch.
10. Keep the correlated-session path disabled until a further profile is
    selected and implemented.

## 8. Required tests

- IPv4 and IPv6 payloads are byte-exact network-layer packets.
- Ethernet input is either stripped correctly or rejected; it is never labelled
  as IPv4/IPv6 while retaining an Ethernet header.
- Every raw-IP PDU has Correlation ID zero.
- No X2 or synthetic IRI is emitted by the uncorrelated profile.
- Direction is `to target`, `from target`, or `unknown` as appropriate.
- Capture timestamps survive queueing and reconnection.
- Sequence contexts comply with TS 103 221-2 clause 5.3.9.
- `X2Only`, `X2andX3`, absent profile, unsupported IP version, and legacy
  capability metadata fail before filter installation.
- Payload format never changes the selected interface or destination.
- Multiple matching XIDs remain separate unless the relevant architecture
  explicitly permits the Additional XID Related Information attribute.
- Socket-backed tests validate the exact wire representation against an MDF
  fixture implementing only the declared profile.
- Race tests cover activation, modification, deactivation, delivery, and
  destination capability replacement.

## 9. Interoperability claim

After implementation and conformance testing, lippycat may accurately claim:

> lippycat supports uncorrelated raw IPv4 and IPv6 content delivery over X3
> using the ETSI TS 103 221-2 PDU and payload formats, for destinations that
> declare support for the lippycat base raw-IP profile.

It should not claim generic correlated raw-IP IRI/CC support or compatibility
with every TS 103 221-2 MDF. Those claims require an additional shared LI
architecture or service-specific profile.

## 10. Conclusion

The standards support an implementation-independent raw-IP wire format, but
not an implementation-independent raw-IP session model. The correct portable
first step is uncorrelated X3 delivery using complete IPv4/IPv6 packets and a
zero Correlation ID, protected by explicit destination capability validation.

This approach maximizes interoperability without embedding assumptions about a
particular MDF. It also leaves a clean extension point for a future standardized
correlated IRI/CC profile rather than making lippycat's local flow heuristics
part of its external protocol contract.
