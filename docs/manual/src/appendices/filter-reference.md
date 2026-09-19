# Filter Type Reference

This appendix documents all filter types supported by lippycat. Filters control
which traffic hunters capture and forward to processors. Use `lc set filter` and
`lc list filters` for every type. The TUI can edit simple filter types and display
RADIUS filters, but structured RADIUS changes remain CLI/YAML-only.

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
| **RADIUS** | `radius_username` | Complete UTF-8 User-Name (exact) | `alice@example.test` |
| | `radius_mac` | Calling-Station-Id under an explicit MAC profile | `02-00-00-00-00-01` |
| | `radius_attribute` | Complete supported AVP encoded as hex | `57086c696e652d61` |
| | `radius_compound` | Scoped conjunction configured in YAML | See YAML below |
| **Universal** | `ip_address` | IP address or CIDR | `192.168.1.0/24` |
| | `bpf` | Raw BPF expression | `port 5060` |

## RADIUS Filters

RADIUS filters are exact rather than wildcard-based. User-Name matching is
case-sensitive, supported attribute hex accepts either case, and `radius_mac`
requires the exact uppercase-hyphen convention with
`calling-station-id-uppercase-hyphen-v1`. Inline filters use `--revision` and
the `--radius-*` scope flags documented under
[`lc set filter`](../part4-administration/cli-admin.md#set-filter-flags).

Compound filters use `lc set filter --file`. Every criterion revision must equal
the enclosing filter revision; increment them together when changing criteria,
scope, or enablement:

```yaml
filters:
  - id: radius-line-and-account
    type: radius_compound
    enabled: true
    revision: 1
    radius:
      group_id: line-and-account
      scope:
        operator_scope: operator-a/nas-a
        profile_revision: v1
      criteria:
        - filter_id: account
          filter_revision: 1
          kind: username
          value: alice@example.test
          target_kind: account
        - filter_id: line
          filter_revision: 1
          kind: attribute
          value: "57086C696E652D61"
          target_kind: line
```

See [RADIUS capture and POI](../part5-advanced/radius.md#distributed-trust-and-filter-synchronization)
for distribution compatibility and scope isolation.

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
