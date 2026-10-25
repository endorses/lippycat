# Initial SSH handshake parser

This package parses each ordered TCP direction independently. `Stream.Feed`
emits owned banner and first-KEXINIT observations through a synchronous callback.
The caller owns flow attribution, capture timestamps, endpoint roles, stream
expiry, reassembly and aggregate resource limits. A positive TCP gap must stop
the affected parser; tuple reuse creates new state.

Supported framing follows [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html):
SSH 2.0 and 1.99 identification, bounded pre-banner lines, initial uncompressed
binary packets, and complete KEXINIT lists. LF-only banners are accepted for
compatibility. Identification is limited to 255 bytes, initial packets to 35,000
bytes, and ignored preludes to 32 lines/8 KiB; individual prelude lines also fit
the 255-byte line buffer. Larger optional packets are unsupported. Length,
padding, alignment, reserved words and list bounds are checked before decoding.
Algorithm names follow [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html#section-6)'s
printable ASCII and 64-byte bounds.

Parsing stops at the first complete KEXINIT, or at an earlier NEWKEYS. Subsequent
bytes cannot create another initial fingerprint. `End` reports missing banners,
incomplete frames and banners without KEXINIT; these never fabricate a hash.
Unsupported SSH versions can retain a banner observation without a fingerprint.

`KEXINIT.Fingerprint` implements the maintained [HASSH 1.0 definition](https://github.com/corelight/hassh/blob/main/scripts/hassh.zeek):
MD5 of four exact ordered lists separated by semicolons. Client hashes use key
exchange, client-to-server encryption, MAC and compression; server hashes use the
server-to-client alternatives. Cookie, host-key list, languages and follows flag
do not enter the hash. No sorting or removal of negotiation markers occurs.
Unknown role produces no fingerprint. First-seen direction and port 22 alone are
insufficient role evidence. This is an observation of offered algorithms, without
claims about authentication, negotiated algorithms, users or application content.

No dependency is added. Tests include the published Cyberduck client vector,
the reference OpenSSH server lists with an independently computed expected MD5,
asymmetric directions, every two-part split, bytewise input, owned-result lifetime,
truncation, malformed framing/lists, resource limits, NEWKEYS and fuzz seeds.

The shared `eventanalysis` runtime owns one assembler per capture runtime and
separate SSH parser halves per connection. Its allocation-free prefix probes
recognize split SSH identification on any port. Positive gaps stop the affected
half; close, tuple replacement and capture-clock idle expiry retire the state.
An observed SYN or SYN/ACK independently proves endpoint roles; simultaneous-open
or conflicting evidence leaves roles unknown. The assembler's first-seen
direction and service port never establish role. Unknown-role complete KEXINITs
retain their lists with an unavailable fingerprint.

The runtime emits a banner observation followed by one complete or partial
terminal observation for each observed half. Complete observations use the
capture timestamp of the KEXINIT's final byte, including queued out-of-order
bytes. Snapshot identities are distinct and both directions share the existing
symmetric flow identity. Invalid UTF-8 or non-printing banner comments use a
lossless `strconv.QuoteToASCII` representation, including its quotes, with an
explicit escaped flag before entering UTF-8 wire strings.

Shared event policy enables SSH by default and configures global flow/byte
limits with `events.ssh.enabled`, `events.ssh.max_flows` and
`events.ssh.max_bytes`. Each admitted flow reserves 144,606 bytes for worst-case
two-half parser and owned-list state until close/expiry; reassembly pages and
dispatch queues retain their separate existing limits. Admission failures are
counted and cannot restart the rejected parser within the same TCP incarnation.
`internal/testutil/eventfixture.SSHMessages` records a real controlled
`x/crypto/ssh` client/server exchange and generates segmented checksum-correct
Ethernet/TCP frames for canonical runtime, tap, transport and offline tests.
