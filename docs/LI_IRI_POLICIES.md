# Selective IRI delivery at the point of interception

lippycat's X1 v1.23.1 capability profile applies IRI policies to task-associated
SIP and RADIUS X2 product. It follows TS 103 120 v1.24.1 policy evaluation and
retains lippycat's existing POI role: it sends X2/X3 to an MDF. Mediation-level
IRI policy references are rejected because their per-LIID HI2/HI3 scope belongs
to an MDF. They are not interpreted as per-destination X2 overrides.

## Interoperability profile

The published X1 v1.23.1 schema adds policy references but does not supply X1
generic-object adapter types for the TS 103 120 IRI groups. The latter's original
types derive from HI1 objects, which cannot be used directly where X1 requires
a `GenericObject` subtype.

lippycat supplies a deployment adapter with the project-owned namespace
`urn:lippycat:li:x1:iri-policy:1`. Its `IRIPolicyObject` and `IRIRuleObject`
types extend X1 `GenericObject` and reuse the unchanged official IRI groups.
The ADMF must use this same adapter. This namespace is not an ETSI namespace,
and this capability profile does not claim to implement an MDF or every optional
X1 extension.

The offline validation entry point is
`internal/pkg/li/x1/xsd/profile.xsd`. Exact upstream files and SHA-256 provenance
are retained under that directory. The generation script
`internal/pkg/li/x1/generate-schema.py` verifies the sources and records the
offline import adjustments and generated-model adaptation.

Generic-object operations are CreateObject, ModifyObject, DeleteObject,
GetObject, ListObjectsOfType, DeleteAllObjects, and GetAllGenericObjectDetails.
Create rejects an existing ID, including an identical definition, with error 2050. Modification replaces the whole definition. Delete rejects an object
still referenced by another policy or task; DeleteAllObjects rejects an in-use
graph. ListObjectsOfType takes a URI-qualified name, for example
`Q{urn:lippycat:li:x1:iri-policy:1}IRIPolicyObject`.

Provision rules before policies, then attach policy UUIDs to the task's
`listOfIRIPolicyReferences`. X1 carries these references as a sequence without
the separate order field used by HI1. This deployment profile evaluates that
sequence in XML order. Within each policy, rule references have explicit,
positive, unique `Order` values and are evaluated in ascending order. This
profile accepts order values through `18446744073709551615` (unsigned 64-bit).

## Evaluation

All criteria in a rule must match. Values within an NF-type or event criterion
are alternatives. The first matching rule determines `Delivered` or
`NotDelivered`, and evaluation stops across the entire task policy list. No
policy or no matching rule leaves delivery unchanged. A policy needs at least
one rule reference; a rule needs at least one criterion and a supported action.

The built-in event criterion is `ETSI / IRIEvents / All`. The built-in actions
are `ETSI / IRIAction / Delivered` and `ETSI / IRIAction / NotDelivered`.
The published ETSI NF-type dictionary has no values. Unknown dictionary entries,
unresolved references, unsupported criteria, and unsupported action parameters
are rejected during provisioning.

An explicitly configured national dictionary can map observed SIP or RADIUS
facts to additional event values. Those names are deployment definitions, not
standardized IRI event names inferred by lippycat. Missing facts needed to decide
a reached rule cause an evaluation error and suppress that product. Reliable
classification with no matching configured event is a normal nonmatch.

SIP policy evaluation uses the parsed wire message, including the CSeq method
for response selectors. It runs after signaling learning needed by X3 and
before X2 sequence allocation and encoding. RADIUS evaluation precedes durable
correlation allocation. IRI suppression does not suppress authorized X3 media.

## Optional fact profile

Without a profile file, `ETSI / IRIEvents / All` remains available. For national
event mappings, configured NF facts, or a known downstream handover format, use:

```bash
lc process --config /etc/lippycat/example.yaml \
  --li-iri-policy-profile /etc/lippycat/iri-profile.json
```

The same flag works on `tap` and its protocol subcommands. Its shared YAML key
is `li.iri_policy_profile`; the environment variable is
`LIPPYCAT_LI_IRI_POLICY_PROFILE`. An explicit flag overrides environment and YAML.
The default is no file. The profile is read once during construction; restart
after changing it.

This synthetic profile illustrates the structure. Its national values are
examples requiring agreement with the ADMF; they are not definitions of a
country's deployed dictionary:

```json
{
  "version": 1,
  "nf_types": [{ "Owner": "DE", "Name": "NFType", "Value": "ExamplePOI" }],
  "events": [
    {
      "entry": { "Owner": "DE", "Name": "IRIEvents", "Value": "ExampleInvite" },
      "sip": { "method": "INVITE" }
    },
    {
      "entry": { "Owner": "DE", "Name": "IRIEvents", "Value": "ExampleAnswer" },
      "sip": {
        "method": "INVITE",
        "response": true,
        "status_min": 200,
        "status_max": 299
      }
    },
    {
      "entry": { "Owner": "DE", "Name": "IRIEvents", "Value": "ExampleAccess" },
      "radius": { "code": 1 }
    }
  ]
}
```

Each mapping selects exactly one protocol. An omitted SIP method matches any
method of the selected request/response kind. `response` defaults to `false`.
For responses, an omitted status range means 100 through 699; a supplied range
must be within those bounds. Request selectors cannot specify status ranges.
Method tokens must use uppercase. Supported RADIUS codes are 1, 2, 3, 4, 5,
and 11. Multiple mappings may assign the same event value.

`nf_types` supplies the known NF facts for this POI. Optional
`handover_format` is a dictionary entry describing the configured downstream
handover format. Merely emitting X2 does not establish that format. Set it only
when the downstream arrangement is known. National dictionary owners use
uppercase two-letter country-code syntax. Supported ETSI handover values are
those in the bundled TS 103 120 dictionary.

Profiles must be regular JSON files no larger than 1 MiB, with at most 256
event mappings and 256 NF entries. Unknown fields, duplicate keys, malformed
choices, unsupported versions, and unknown dictionary entries fail startup.
These limits supplement the existing bounded X1 messages and administrative
state; they do not promise that every individual maximum fits simultaneously.

## Changes, restart, and telemetry

Object definitions are detached from callers and compiled against their source
generations. A rule or policy update validates all affected task definitions
before changing live authority. Affected tasks advance generation together;
queued X2 and X3 from their old generations are revoked before the new graph is
published. A failed or uncertain administrative commit cannot leave mixed
policy authority active.

The semantic revision of the fact profile is part of a policy-dependent task's
authorization. A changed mapping cannot silently reuse old replay permission.
Whitespace and equivalent mapping order do not change that revision.

Encrypted administrative state version 3 stores policy objects. Version 2 is
read with an empty policy graph and migrates on the next successful write.
Restored objects are administrative data until confirmed by the ADMF. Dependent
tasks and replay need a complete valid object graph from the same GetAllDetails
snapshot as the task definitions. Missing or malformed object lists do not
authorize policy-dependent delivery. The existing 1 MiB ADMF query-response
limit still applies to both received bytes and namespace-normalized XML;
oversized responses fail synchronization. X1 requests use a 10 MiB limit for
both representations and are normalized before mutation. Compact input can
therefore be rejected when making its namespace scope explicit exceeds the
limit.

Preserve a backup of the prior encrypted state and its keys before upgrading if
an older binary must be available for rollback: an older binary does not read
version 3 state. Restoring administrative data still requires current ADMF
confirmation; a backup is not delivery authority.

Processor status exposes `li_iri_policy` with object, policy, rule, and confirmed
object counts, plus cumulative `suppressed` and `evaluation_errors` counters.
Policy suppression is reported separately from delivery loss. Diagnostics omit
policy content, target values, and intercepted data.

## Public references

- [ETSI TS 103 221-1 v1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf):
  clauses 4.1.4 and 6.8, Annexes C and F.
- [ETSI TS 103 120 v1.24.1](https://www.etsi.org/deliver/etsi_ts/103100_103199/103120/01.24.01_60/ts_103120v012401p.pdf):
  clauses 7.7, 7.8, and 8.2.14.
