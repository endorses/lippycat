# List Command - Resource Listing

The `list` command displays available resources such as network interfaces and filters.

## Commands

### List Interfaces

List network interfaces available for monitoring (local command).

```bash
lc list interfaces
```

**Output Example:**
```
Network interfaces suitable for VoIP monitoring:
  eth0 - Ethernet adapter
  wlan0 - Wireless adapter
  enp0s3 - PCI Ethernet

Note: Interface selection should comply with your organization's network monitoring policies.
Only monitor interfaces you have explicit permission to access.
```

## Interface Filtering

The command filters out interfaces not typically useful for network monitoring:
- Loopback interfaces (`lo`, `loopback`)
- USB/Bluetooth interfaces
- Container interfaces (`docker*`, `veth*`)
- Virtual machine interfaces (`vmnet*`, `vbox*`)
- Tunnel interfaces (`isatap`, `teredo`)

## Permissions

Full interface listing requires appropriate privileges:

```bash
# As root (full access)
sudo lc list interfaces

# Without root (limited access, shows warning)
lc list interfaces
```

### List Filters

List filters configured on a remote processor (gRPC command).

**Security:** TLS is enabled by default. Use `--insecure` for local testing.

```bash
# List all filters (TLS with CA verification)
lc list filters -P processor.example.com:50051 --tls-ca ca.crt

# List filters for a specific hunter
lc list filters -P processor.example.com:50051 --tls-ca ca.crt --hunter hunter-1

# Local testing without TLS
lc list filters -P localhost:50051 --insecure
```

**Output:** JSON array of filter objects to stdout.

## See Also

- [cmd/sniff/README.md](../sniff/README.md) - Packet capture commands
- [cmd/watch/README.md](../watch/README.md) - Interactive TUI monitoring
