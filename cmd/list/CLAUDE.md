# List Command - Architecture

The `list` command provides resource listing functionality.

## Structure

```
cmd/list/
├── list.go        - Base command (requires subcommand)
├── interfaces.go  - List network interfaces (local)
└── filters.go     - List filters on processor (gRPC, delegates to cmd/filter)
```

**Build Tags:** `cli`, `tui`, `hunter`, or `all`

## Subcommands

- `list interfaces` - Local command, lists network interfaces
- `list filters` - Remote command, queries processor via gRPC

**Security:** For remote commands (filters), TLS is enabled by default. Use `--insecure` for local testing.

## Implementation

### interfaces.go

Uses gopacket's pcap library to enumerate interfaces:

```go
devices, err := pcap.FindAllDevs()
```

**Security Filtering:**
- Filters sensitive interfaces (loopback, USB, containers, VMs)
- Sanitizes descriptions (removes MAC addresses, serial numbers)
- Limits description length to 50 characters

**Functions:**
- `isValidMonitoringInterface(name)` - Filter exclusion patterns
- `containsSensitiveInfo(desc)` - Check for sensitive keywords
- `sanitizeDescription(desc)` - Clean description output

## Extension Pattern

To add new list subcommands:

```go
// cmd/list/hunters.go
var huntersCmd = &cobra.Command{
    Use:   "hunters",
    Short: "List connected hunter nodes",
    Run:   runHunters,
}

func init() {
    ListCmd.AddCommand(huntersCmd)
}
```

## See Also

- [README.md](README.md) - User documentation
