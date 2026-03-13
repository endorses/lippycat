# Filter Type Reference

This appendix documents all filter types supported by lippycat. Filters control which traffic hunters capture and forward to processors. They can be managed via the CLI (`lc set filter`, `lc list filters`) or interactively through the TUI.

## Filter Types

| Category | Type | Description | Example Pattern |
|----------|------|-------------|-----------------|
| **VoIP** | `sip_user` | SIP user/extension (glob) | `alicent@example.com` |
| | `sip_uri` | SIP URI (glob) | `sip:*@example.com` |
| | `phone_number` | Phone number (prefix/suffix) | `*456789` |
| | `call_id` | SIP Call-ID | `abc123@host` |
| | `codec` | RTP codec | `PCMU` |
| | `imsi` | IMSI from SIP headers | `262011234567890` |
| | `imei` | IMEI from SIP Contact parameters | `35399405123456` |
| **DNS** | `dns_domain` | Domain name (glob) | `*.example.com` |
| **TLS** | `tls_sni` | SNI hostname (glob) | `*.example.com` |
| | `tls_ja3` | JA3 client fingerprint | `e7d705a3286e19ea42f587b344ee6865` |
| | `tls_ja3s` | JA3S server fingerprint | `eb1d94daa7e0344597e756a1fb6e7054` |
| | `tls_ja4` | JA4 fingerprint | `t13d1516h2_8daaf6152771_...` |
| **HTTP** | `http_host` | Host header (glob) | `*.example.com` |
| | `http_url` | URL path (glob) | `/api/v1/*` |
| **Email** | `email_address` | Sender/recipient (glob) | `*@suspicious.com` |
| | `email_subject` | Subject line (glob) | `*confidential*` |
| **Universal** | `ip_address` | IP address or CIDR | `192.168.1.0/24` |
| | `bpf` | Raw BPF expression | `port 5060` |

## Wildcard Patterns

String-based filters (SIP users, domains, SNI, hosts, email addresses) support wildcards for flexible matching:

| Pattern | Type | Matches |
|---------|------|---------|
| `alicent` | Contains | Substring match anywhere |
| `*456789` | Suffix | Any prefix + `456789` |
| `alicent*` | Prefix | `alicent` + any suffix |
| `*alicent*` | Contains | Explicit contains |

This is especially useful for phone numbers that appear in different formats (E.164, 00-prefix, tech prefixes like `*31#`).

## IMSI/IMEI Extraction

IMSI and IMEI identifiers are extracted from SIP signaling:

- **IMSI**: Extracted from SIP `Authorization` and `P-Asserted-Identity` headers
- **IMEI**: Extracted from the `+sip.instance` parameter in SIP `Contact` headers

These filters are particularly useful in mobile/VoLTE environments where subscriber identity tracking is needed.

## IP Address Matching

The `ip_address` filter type supports both individual addresses and CIDR notation:

- `192.168.1.100` — matches a single host
- `10.0.1.0/24` — matches all addresses in the subnet
- IPv6 addresses and prefixes are also supported

IP filters use hash map lookup for individual addresses and radix trie lookup for CIDR ranges, providing O(1) and O(prefix length) performance respectively.

## BPF Filters

The `bpf` filter type accepts raw Berkeley Packet Filter expressions. These are applied at the capture level before protocol analysis, making them the most efficient way to reduce traffic volume.

See [Appendix C: BPF Filter Reference](bpf-reference.md) for the full BPF syntax.
