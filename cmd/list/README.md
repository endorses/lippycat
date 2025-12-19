# List Command - Resource Listing

The `list` command displays available resources such as network interfaces.

## Commands

### List Interfaces

```bash
# List network interfaces available for monitoring
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

## Future Subcommands

The list command is designed for extension:
- `lc list hunters` - List connected hunter nodes (planned)
- `lc list calls` - List active VoIP calls (planned)

## See Also

- [cmd/sniff/README.md](../sniff/README.md) - Packet capture commands
- [cmd/watch/README.md](../watch/README.md) - Interactive TUI monitoring
