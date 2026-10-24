# SMS-over-IMS

VoIP capture decodes SIP `MESSAGE` bodies with media type
`application/vnd.3gpp.sms`. Decoding is independent of keyword filtering. Existing
SIP identity filters, capture restrictions, and signalling/media policies still
determine which traffic is eligible for output.

## Display and protocol support

The TUI's VoIP call details show decoded SMS text, encoding, SMS addresses when
available, and multipart assembly progress. SMS addresses are separate from SIP
routing identities. A SIP success response acknowledges the transaction; it is
not proof of handset delivery.

Incoming `SMS-DELIVER` and outgoing `SMS-SUBMIT` support the GSM 7-bit default
alphabet and extension table, and big-endian UCS2. User-data headers are parsed
before text decoding, including GSM7 fill bits and both concatenation reference
widths. RP acknowledgements and errors are recognized as control messages.

Multipart messages are joined by SMS concatenation information within their
capture/source and subscriber context, even when parts use different SIP
Call-IDs or connections. Out-of-order parts and identical duplicates are
supported. Missing parts, conflicting copies, expired assemblies, and resource
exhaustion remain explicit; partial text is not presented as a complete message.

Unsupported binary, compressed, or national-language-shift encodings are labelled
rather than interpreted as ordinary text. Ordinary `text/plain` SIP MESSAGE is
outside SMS-over-IMS filtering. Encrypted SIP or ESP must already be available as
plaintext; charset decoding does not decrypt traffic.

Hunters and taps attach structured SMS metadata to forwarded packets, allowing
processors and remote TUI clients to reuse the result. Local live capture and
offline analysis use the same decoder. Older peers may omit the optional field;
a complete captured SIP message can supply fallback decoding. Raw packet bytes
remain available for inspection.

## Optional keyword filtering

`hunt voip` and `tap voip` accept `--sms-keywords` and `--sms-keywords-file`.
With neither configured, SMS forwarding is unchanged by text content and packets
are not held while multipart display assembly completes.

```bash
lc hunt voip -i eth0 --processor processor:55555 --tls-ca ca.crt \
  --sms-keywords "urgent,maintenance"

lc tap voip -i eth0 --sip-user alice \
  --tls-cert server.crt --tls-key server.key \
  --sms-keywords-file /etc/lippycat/sms-keywords.txt
```

Configure the hunter's existing SIP selection filters on its processor as usual.
SMS keywords are an additional condition; they never select an otherwise
ineligible subscriber or enable RTP capture. An enabled keyword condition also
applies with `--signalling-policy=all`; `none` still suppresses signalling.
Ordinary calls, RTP, and non-SMS pager messages keep their existing policies.

Matching uses case-insensitive literal substrings. Any keyword from either source
can match; sources are combined. Files contain one keyword per line, ignoring
blank lines and lines beginning with `#`. An empty effective keyword set disables
filtering. Regex, stemming, and accent folding are not performed.

For multipart SMS, the filter waits for complete joined text and can match a
keyword split across parts. Eligible contributing SIP messages are retained and
released together on a match, with their original provenance and timestamps.
Responses and associated RP acknowledgements/errors follow the admitted
exchange. No text match is inferred from a control message alone.

Nonmatching or undecodable messages are suppressed only while filtering is
enabled. An incomplete, expired, conflicting, or resource-limited multipart
message does not become a match. Pending retained packets are released from
memory without being output in those cases. Retransmissions do not duplicate
assembled text or extend retention indefinitely. Replaced capture or selection
authority cannot authorize retained packets retroactively.

## Configuration and resource limits

Settings live under `hunter.voip.sms` or `tap.voip.sms`. Command flags override
configuration and environment values according to the normal CLI precedence.

```yaml
hunter:
  voip:
    sms:
      keywords: [urgent, maintenance] # Omit or use [] to disable filtering.
      keywords_file: ""
      max_assemblies: 1024
      max_bytes: 4194304
      max_segments: 255
      lifetime: 5m
      max_pending_messages: 4096
      max_pending_bytes: 16777216
```

`max_assemblies`, `max_bytes`, `max_segments`, and `lifetime` bound multipart
content and completed deduplication state. The two pending limits bound packet
and transaction retention used by an enabled keyword filter, including retained
metadata. Limits must be positive; `max_segments` cannot exceed the protocol's
255-part range. Expiry is measured from the first observation, not the latest
retransmission. Capture replacement, reset, and shutdown release pending state.
These defaults are storage controls, not throughput or latency guarantees.

TUI SMS content is additionally bounded by its call retention. Evicting packet
bytes does not remove text from a retained call; clearing the capture removes
the associated content and assembly context. SMS text is not added to logs,
metrics, status output, or structured protocol streams. Existing LI content
authorization remains independent of display metadata.
