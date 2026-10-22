# Pinned X1 and IRI policy schemas

`sources.json` records exact public source URLs and SHA-256 hashes. `upstream/`
contains those unmodified sources. Files at this directory's root have only
`xs:import` locations added or replaced to resolve every dependency locally.
`generate-schema.py` verifies the source hashes and repeats those adjustments.
The source tags are X1 v1.23.1 and TS 103 120 v1.24.1, including the compatible
TS 103 280 schema and XML Signature dependency shipped in the latter tag.

The published X1 schema has no IRI-policy adapter from the X1 `GenericObject`
base to the TS 103 120 IRI groups. `Lippycat_IRIPolicy.xsd` supplies that adapter
under `urn:lippycat:li:x1:iri-policy:1`, a project-owned deployment namespace.
It reuses the official IRI groups unchanged. This requires agreement with the
ADMF; it does not represent an ETSI-defined adapter or an MDF implementation.
`profile.xsd` imports both sides for offline instance validation.

To regenerate `schema/x1.go`, install the pinned generator and run:

```sh
go install github.com/xuri/xgen/cmd/xgen@v0.0.0-20260902022537-fb39bae424fe
python3 internal/pkg/li/x1/generate-schema.py --xgen "$(go env GOPATH)/bin/xgen"
```

The script generates from the unchanged X1 core schema, whose imports have no
locations, and keeps the existing separate common and hashed-ID bindings. It
then adds the LI build tag, preserves extension-base ordering required by XML
Schema, normalizes the new UUID-reference slice, and adds the explicit derived
object runtime field. Strict polymorphic XML handling lives in handwritten
`schema/generic_object.go`; xgen cannot represent `xsi:type` polymorphism.

For example, validate a synthetic wire fixture with:

```sh
xmllint --nonet --noout --schema internal/pkg/li/x1/xsd/profile.xsd fixture.xml
```
