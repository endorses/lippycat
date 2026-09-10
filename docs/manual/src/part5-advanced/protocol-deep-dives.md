# Protocol Deep Dives

lippycat's protocol analyzers extract structured metadata and support protocol-aware
filtering. These chapters cover each analyzer's behavior, metadata fields, and
practical investigations:

- [VoIP: SIP and RTP Analysis](voip.md): signaling, media streams, call quality, and per-call PCAPs.
- [DNS Analysis](dns.md): query correlation, metadata, and tunneling detection.
- [TLS Inspection](tls.md): handshakes, certificates, and fingerprints.
- [HTTP Analysis](http.md): requests, responses, and body capture.
- [Email Protocol Analysis](email.md): SMTP, IMAP, and POP3.
- [RADIUS Capture and POI](radius.md): authentication, accounting, and authorized POI operations.

For protocol subcommands and flags, see [CLI Capture with `lc sniff`](../part2-local-capture/sniff.md).
The examples use `jq`; see [Working with JSON Output](../part2-local-capture/sniff.md#working-with-json-output)
for shared output conventions, piping, and replay workflows.
