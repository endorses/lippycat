# List Command - Resource Listing

The `list` command displays available resources such as network interfaces and filters.

## Commands

### List Interfaces

List capture interfaces with their type, operational state, and IP addresses. This is a local command and needs no processor connection.

```bash
lc list interfaces
```

**Illustrative output:**

```text
NAME     TYPE       STATE  ADDRESSES                NOTES
eth0     Ethernet   up     192.168.1.42/24           default route
wlan0    Wi-Fi      down   —
lo       Loopback   up     127.0.0.1/8, ::1/128
any      Aggregate  —      —                        all network interfaces

7 additional capture devices hidden; use --all to show them.
```

The default view includes physical interfaces, loopback, VPN/tunnel interfaces, and unclassified network interfaces, including those that are down. `any` appears only when the capture library provides it. Bridges, container/VM links, and special capture sources such as D-Bus and NFQUEUE are hidden unless `--all` is used. Interfaces with a detected default route remain visible.

On Linux, OS metadata supplies interface classification, operational state, and IPv4/IPv6 default-route hints. Other systems use available metadata and report unknown values when details cannot be determined. A default-route hint identifies a route out of the host; choose the interface connected to the traffic you want to capture.

| Flag      | Description                                                       |
| --------- | ----------------------------------------------------------------- |
| `--all`   | Include bridges, virtual interfaces, and special capture sources. |
| `--names` | Print one interface name per line.                                |
| `--json`  | Print structured interface metadata as JSON.                      |
| `--check` | Test capture access on the displayed network interfaces.          |

```bash
# Include every capture device
lc list interfaces --all

# Names for scripts
lc list interfaces --names

# Metadata and capture-access results
lc list interfaces --json --check
```

`--names` cannot be combined with `--json` or `--check`. JSON retains the `interfaces` array and includes `type`, `state`, and `default_route` for each interface, a top-level `hidden_count`, and optional `warnings`. Addresses include their IP values and prefix lengths when available.

Listing alone does not test capture permissions and does not require root. With `--check`, the command briefly opens each displayed network interface without promiscuous mode, then closes it without reading packets. The table adds a `CAPTURE` column with `available`, `unavailable`, or `skipped`; failures appear in `NOTES`. Special capture sources are skipped. JSON includes `capture_access` and, for failures, `capture_error`. A successful check does not guarantee that a later capture with different options will succeed.

An unavailable interface does not make `--check` fail the command. Device-enumeration failures return a nonzero exit status and report the error on stderr; with `--json`, the error is a JSON object on stderr. Discovery warnings are written to stderr in text/names mode and included in the JSON result in JSON mode.

### List Filters

List filters configured on a remote processor (gRPC command).

**Security:** TLS is enabled by default. Use `--insecure` for local testing.

```bash
# List all filters (TLS with CA verification)
lc list filters -P processor.example.com:55555 --tls-ca ca.crt

# List filters for a specific hunter
lc list filters -P processor.example.com:55555 --tls-ca ca.crt --hunter hunter-1

# Local testing without TLS
lc list filters -P localhost:55555 --insecure
```

**Output:** JSON array of filter objects to stdout.

## See Also

- [cmd/sniff/README.md](../sniff/README.md) - Packet capture commands
- [cmd/watch/README.md](../watch/README.md) - Interactive TUI monitoring
