# List Command - Architecture

The `list` command provides resource listing functionality.

## Structure

```
cmd/list/
├── list.go        - Base command (requires subcommand)
├── interfaces.go  - List network interfaces (local)
├── filters.go     - List filters on processor (gRPC, delegates to cmd/filter)
└── hunters.go     - List connected hunter nodes (gRPC)
```

**Build Tags:** `cli`, `tui`, `hunter`, or `all`

## Subcommands

- `list interfaces` - Local command, lists network interfaces
- `list filters` - Remote command, queries processor via gRPC
- `list hunters` - Remote command, lists connected hunters via gRPC

**Security:** For remote commands (filters), TLS is enabled by default. Use `--insecure` for local testing.

## Implementation

### interfaces.go

Uses `capture.DiscoverInterfaces()` to enumerate capture devices once through `pcap.FindAllDevs()` and enrich them with OS metadata. The same discovery result feeds table, `--names`, and `--json` output.

- Linux classification, operational state, and IPv4/IPv6 default-route hints come from OS metadata. Other platforms use best-effort metadata with explicit unknown fallbacks.
- Default filtering hides bridges, container/VM links, and special capture sources; default-route interfaces stay visible. Loopback, physical interfaces, tunnels, down interfaces, and unknown network interfaces remain visible. `any` is included only when pcap enumerates it.
- `--all` exposes hidden devices. `--names` cannot be combined with `--json` or `--check`.
- `--check` briefly opens displayed network devices nonpromiscuously and closes the handles without reading packets. It skips special capture sources. Per-device failures are reported as results, not command errors.
- Enumeration errors propagate through `RunE` for a nonzero exit status. Diagnostics go to stderr; JSON mode reports fatal discovery errors as JSON on stderr and includes discovery warnings in the result.
- Table cells sanitize terminal control characters. Root status alone is not treated as evidence of capture access.

`capture.ListInterfaces()` remains separate for the existing TUI interface picker. Its legacy filtering and description sanitization do not define the CLI discovery view; changing CLI discovery must not silently change TUI picker behavior.

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
