# Compact offline packet field inventory

Phase-0 contract, verified against `internal/pkg/types/packet.go`,
`internal/pkg/offline/summary.go`, `internal/pkg/tui/offline_indexer.go`,
`internal/pkg/tui/offline_sip.go`, `internal/pkg/tui/components/detailspanel.go`
and `internal/pkg/tui/store/packet_flow.go`. Every declared field in PacketDisplay
and its seven nested metadata types appears below. New fields require inventory,
codec-version and parity-oracle review together.

S = source-decodable from **effective normalized bytes** or original capture
context, F = finalized analysis metadata, D = derived retained content,
P = presentation-only value. B = complete ordered base; A = analyzer EOF plus
amendments. Classification describes the safe persistence/readiness contract,
not a promise that existing parser implementations are already stateless.
All fields are observable through returned Detail.Packet even when a widget does
not currently render them. “Detail/API” means that full-object contract, not that
the details panel renders every field. List means the scalar DisplayFields
projection; filter means an accessor/metadata-presence or flow lookup consumer.

No field in PacketDisplay is safely discardable as presentation-only. Formatting
(timezone, colors, widths, hex-dump layout, selection) is P outside this struct.
Protocol and Info remain A even if some individual packets can be labeled earlier.
Source-decodable application fields also remain A: their presence, parser choice
and overrides depend on final classification. Pending never means nil/zero.

| PacketDisplay field | Class | Consumers                                                | Ready |
| ------------------- | ----- | -------------------------------------------------------- | ----- |
| `Timestamp`         | S     | list, detail, export/order                               | B     |
| `SrcIP`             | S     | list, filter, detail, statistics, flow                   | B     |
| `DstIP`             | S     | list, filter, detail, statistics, flow                   | B     |
| `SrcPort`           | S     | list, filter, detail, flow                               | B     |
| `DstPort`           | S     | list, filter, detail, flow                               | B     |
| `Protocol`          | F     | list, filter, detail, protocol statistics, flow fallback | A     |
| `Transport`         | S     | list projection, flow, detail/API                        | B     |
| `Length`            | S     | list, filter, detail, statistics                         | B     |
| `Info`              | F     | list, filter (including SIP fallback), detail            | A     |
| `RawData`           | S/D   | detail hex/tree, effective-byte export                   | B     |
| `NodeID`            | S     | list, filter, detail, flow                               | B     |
| `Interface`         | S     | list, filter, detail                                     | B     |
| `VoIPData`          | F     | metadata presence filter, detail/API                     | A     |
| `DNSData`           | F     | metadata presence filter, detail/API                     | A     |
| `EmailData`         | F     | metadata presence filter, detail/API                     | A     |
| `TLSData`           | F     | metadata presence filter, detail/API                     | A     |
| `HTTPData`          | F     | metadata presence filter, detail/API                     | A     |
| `LinkType`          | S/D   | list projection, detail decoder, export                  | B     |

RawData uses source bytes only for proven unchanged outputs; fragments, rewritten
ESP and derived tunnel output use owned D bytes. LinkType is the effective decoder
context, separate from original context; Length is display length, separate from
captured/original lengths. NodeID and Interface come from frozen source attribution,
not from packet header decoding. Missing ports preserve the exact empty string.

The following tables enumerate nested fields. All are A-ready, including fields
marked S, until packet-local analyzer equivalence is established. F fields must
be retained if populated; D includes bytes/text or collections that may originate
in a reassembled message. An S field overridden by stateful processing becomes
an explicit retained F override. Default zero/nil values are preserved exactly;
never fill an unpopulated packet field from richer normalized protocol events.

## VoIPMetadata

| Field               | Type                 | Class | Consumers (A-ready) |
| ------------------- | -------------------- | ----- | ------------------- |
| `CallID`            | `string`             | F     | filter, detail/API  |
| `Method`            | `string`             | S     | filter, detail/API  |
| `CSeqMethod`        | `string`             | S     | detail/API          |
| `Status`            | `int`                | S     | filter, detail/API  |
| `From`              | `string`             | S     | filter, detail/API  |
| `To`                | `string`             | S     | filter, detail/API  |
| `FromTag`           | `string`             | S     | filter, detail/API  |
| `ToTag`             | `string`             | S     | filter, detail/API  |
| `User`              | `string`             | S     | filter, detail/API  |
| `ContentType`       | `string`             | S     | detail/API          |
| `Body`              | `string`             | D     | detail/API          |
| `Headers`           | `map[string]string`  | D     | detail/API          |
| `RawSIP`            | `[]byte`             | D     | detail/API          |
| `IMSI`              | `string`             | S     | filter, detail/API  |
| `IMEI`              | `string`             | S     | filter, detail/API  |
| `AccessNetworkInfo` | `*AccessNetworkInfo` | S     | detail/API          |
| `VisitedNetworkID`  | `string`             | S     | detail/API          |
| `IsRTP`             | `bool`               | S     | filter, detail/API  |
| `SSRC`              | `uint32`             | S     | filter, detail/API  |
| `PayloadType`       | `uint8`              | S     | detail/API          |
| `SequenceNum`       | `uint16`             | S     | filter, detail/API  |
| `SeqNumber`         | `uint16`             | S     | detail/API          |
| `Timestamp`         | `uint32`             | S     | detail/API          |
| `Codec`             | `string`             | F     | filter, detail/API  |
| `MergeFromCallID`   | `string`             | F     | detail/API          |

## AccessNetworkInfo

| Field        | Type                | Class | Consumers (A-ready) |
| ------------ | ------------------- | ----- | ------------------- |
| `AccessType` | `string`            | S     | detail/API          |
| `BSSID`      | `string`            | S     | detail/API          |
| `CellID`     | `string`            | S     | detail/API          |
| `LocalIP`    | `string`            | S     | detail/API          |
| `Parameters` | `map[string]string` | S     | detail/API          |

## DNSMetadata

| Field                 | Type          | Class | Consumers (A-ready) |
| --------------------- | ------------- | ----- | ------------------- |
| `TransactionID`       | `uint16`      | S     | detail/API          |
| `IsResponse`          | `bool`        | S     | detail/API          |
| `Opcode`              | `string`      | S     | detail/API          |
| `ResponseCode`        | `string`      | S     | detail/API          |
| `Authoritative`       | `bool`        | S     | detail/API          |
| `Truncated`           | `bool`        | S     | detail/API          |
| `RecursionDesired`    | `bool`        | S     | detail/API          |
| `RecursionAvailable`  | `bool`        | S     | detail/API          |
| `AuthenticatedData`   | `bool`        | S     | detail/API          |
| `CheckingDisabled`    | `bool`        | S     | detail/API          |
| `QuestionCount`       | `uint16`      | S     | detail/API          |
| `AnswerCount`         | `uint16`      | S     | detail/API          |
| `AuthorityCount`      | `uint16`      | S     | detail/API          |
| `AdditionalCount`     | `uint16`      | S     | detail/API          |
| `QueryName`           | `string`      | S     | filter, detail/API  |
| `QueryType`           | `string`      | S     | filter, detail/API  |
| `QueryClass`          | `string`      | S     | detail/API          |
| `Answers`             | `[]DNSAnswer` | S     | filter, detail/API  |
| `QueryResponseTimeMs` | `int64`       | F     | filter, detail/API  |
| `CorrelatedQuery`     | `bool`        | F     | detail/API          |
| `TunnelingScore`      | `float64`     | S     | detail/API          |
| `EntropyScore`        | `float64`     | S     | detail/API          |

## DNSAnswer

| Field   | Type     | Class | Consumers (A-ready)                    |
| ------- | -------- | ----- | -------------------------------------- |
| `Name`  | `string` | S     | detail/API                             |
| `Type`  | `string` | S     | detail/API                             |
| `Class` | `string` | S     | detail/API                             |
| `TTL`   | `uint32` | S     | filter (first answer only), detail/API |
| `Data`  | `string` | S     | detail/API                             |

## EmailMetadata

| Field               | Type        | Class | Consumers (A-ready) |
| ------------------- | ----------- | ----- | ------------------- |
| `Protocol`          | `string`    | S     | detail/API          |
| `IsServer`          | `bool`      | S     | detail/API          |
| `MailFrom`          | `string`    | F     | detail/API          |
| `RcptTo`            | `[]string`  | F     | detail/API          |
| `Subject`           | `string`    | F     | detail/API          |
| `MessageID`         | `string`    | F     | detail/API          |
| `ContentType`       | `string`    | F     | detail/API          |
| `Command`           | `string`    | S     | detail/API          |
| `ResponseCode`      | `int`       | S     | detail/API          |
| `ResponseText`      | `string`    | S     | detail/API          |
| `STARTTLSOffered`   | `bool`      | F     | detail/API          |
| `STARTTLSRequested` | `bool`      | F     | detail/API          |
| `Encrypted`         | `bool`      | F     | detail/API          |
| `AuthMethod`        | `string`    | F     | detail/API          |
| `AuthUser`          | `string`    | F     | detail/API          |
| `SessionID`         | `string`    | F     | detail/API          |
| `ServerBanner`      | `string`    | F     | detail/API          |
| `ClientHelo`        | `string`    | F     | detail/API          |
| `Timestamp`         | `time.Time` | F     | detail/API          |
| `MessageSize`       | `int`       | F     | detail/API          |
| `BodyPreview`       | `string`    | D     | detail/API          |
| `BodySize`          | `int`       | D     | detail/API          |
| `BodyTruncated`     | `bool`      | D     | detail/API          |
| `TransactionTimeMs` | `int64`     | F     | detail/API          |
| `Correlated`        | `bool`      | F     | detail/API          |
| `IMAPTag`           | `string`    | S     | detail/API          |
| `IMAPCommand`       | `string`    | S     | detail/API          |
| `IMAPMailbox`       | `string`    | F     | detail/API          |
| `IMAPUID`           | `uint32`    | S     | detail/API          |
| `IMAPSeqNum`        | `uint32`    | S     | detail/API          |
| `IMAPStatus`        | `string`    | S     | detail/API          |
| `IMAPFlags`         | `[]string`  | S     | detail/API          |
| `IMAPExists`        | `uint32`    | F     | detail/API          |
| `IMAPRecent`        | `uint32`    | F     | detail/API          |
| `IMAPUIDNext`       | `uint32`    | F     | detail/API          |
| `IMAPUIDValidity`   | `uint32`    | F     | detail/API          |
| `POP3Command`       | `string`    | S     | detail/API          |
| `POP3Status`        | `string`    | S     | detail/API          |
| `POP3MsgNum`        | `uint32`    | S     | detail/API          |
| `POP3MsgSize`       | `uint32`    | S     | detail/API          |
| `POP3MsgCount`      | `uint32`    | F     | detail/API          |
| `POP3TotalSize`     | `uint64`    | F     | detail/API          |

## TLSMetadata

| Field               | Type       | Class | Consumers (A-ready) |
| ------------------- | ---------- | ----- | ------------------- |
| `Version`           | `string`   | S     | detail/API          |
| `VersionRaw`        | `uint16`   | S     | detail/API          |
| `RecordVersion`     | `uint16`   | S     | detail/API          |
| `HandshakeType`     | `string`   | S     | detail/API          |
| `IsServer`          | `bool`     | S     | detail/API          |
| `SessionID`         | `string`   | S     | detail/API          |
| `SNI`               | `string`   | S     | filter, detail/API  |
| `CipherSuites`      | `[]uint16` | S     | detail/API          |
| `Extensions`        | `[]uint16` | S     | detail/API          |
| `SupportedVersions` | `[]uint16` | S     | detail/API          |
| `SupportedGroups`   | `[]uint16` | S     | detail/API          |
| `SignatureAlgos`    | `[]uint16` | S     | detail/API          |
| `ECPointFormats`    | `[]uint8`  | S     | detail/API          |
| `ALPNProtocols`     | `[]string` | S     | detail/API          |
| `SelectedCipher`    | `uint16`   | S     | detail/API          |
| `Compression`       | `uint8`    | S     | detail/API          |
| `JA3String`         | `string`   | S     | detail/API          |
| `JA3Fingerprint`    | `string`   | S     | filter, detail/API  |
| `JA3SString`        | `string`   | S     | detail/API          |
| `JA3SFingerprint`   | `string`   | S     | detail/API          |
| `JA4String`         | `string`   | S     | detail/API          |
| `JA4Fingerprint`    | `string`   | S     | detail/API          |
| `FlowKey`           | `string`   | F     | detail/API          |
| `CorrelatedPeer`    | `bool`     | F     | detail/API          |
| `HandshakeTimeMs`   | `int64`    | F     | detail/API          |
| `RiskScore`         | `float64`  | S     | detail/API          |
| `RiskFlags`         | `int`      | S     | detail/API          |

## HTTPMetadata

| Field                   | Type                | Class | Consumers (A-ready) |
| ----------------------- | ------------------- | ----- | ------------------- |
| `Type`                  | `string`            | S     | detail/API          |
| `IsServer`              | `bool`              | S     | detail/API          |
| `Method`                | `string`            | S     | filter, detail/API  |
| `Path`                  | `string`            | S     | filter, detail/API  |
| `Version`               | `string`            | S     | detail/API          |
| `StatusCode`            | `int`               | S     | filter, detail/API  |
| `StatusReason`          | `string`            | S     | detail/API          |
| `Host`                  | `string`            | S     | filter, detail/API  |
| `Server`                | `string`            | S     | detail/API          |
| `ContentType`           | `string`            | S     | detail/API          |
| `ContentLength`         | `int64`             | S     | filter, detail/API  |
| `UserAgent`             | `string`            | S     | detail/API          |
| `SessionID`             | `string`            | F     | detail/API          |
| `RequestTime`           | `int64`             | F     | detail/API          |
| `ResponseTime`          | `int64`             | F     | detail/API          |
| `IsHTTPS`               | `bool`              | S     | detail/API          |
| `HasAuth`               | `bool`              | S     | detail/API          |
| `CorrelatedResponse`    | `bool`              | F     | detail/API          |
| `RequestResponseTimeMs` | `int64`             | F     | detail/API          |
| `Headers`               | `map[string]string` | S     | detail/API          |
| `QueryString`           | `string`            | S     | detail/API          |
| `BodyPreview`           | `string`            | D     | detail/API          |
| `BodySize`              | `int`               | D     | detail/API          |
| `BodyTruncated`         | `bool`              | D     | detail/API          |

SIP TCP assembly can replace all VoIP fields and Protocol/Info at EOF: store the
final packet-local amendment, including fields whose UDP origin is S. SequenceNum
feeds filters while SeqNumber feeds the detail panel; preserve both independently.
DNS answer order and nil/empty distinction matter, including first TTL. TLS
fingerprints and risk fields are reproducible only with frozen algorithms/config;
TLS decrypted connection content is a separate retained result outside PacketDisplay.
HTTP/email body and envelope fields must preserve current opt-in limits and current
packet-local zeros, even where normalized events contain full stream transactions.
AccessNetworkInfo.Parameters and all headers retain exact maps, not formatted text.

Normalized events, call histories, correlated calls, TLS plaintext and protocol
statistics are separate A-ready artifacts. Their deterministic identities,
retention caps, counters and ordering have separate differential comparisons.
Base statistics may expose counts, bytes, sizes and endpoint frequencies only;
application protocol statistics are pending. Related flow using unknown-transport
Protocol fallback is A-dependent; a purely typed transport lookup may be B-ready.
An opaque QuerySpec.Match is A-dependent because its field dependencies are unknown.
