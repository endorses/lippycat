# Watch Command - Architecture

The `watch` command provides interactive TUI monitoring. It's a thin CLI wrapper around `internal/pkg/tui/`.

## Structure

```
cmd/watch/
├── watch.go   - Base command, defaults to live mode
├── live.go    - Live network capture
├── file.go    - PCAP file analysis
└── remote.go  - Remote node monitoring
```

**Build Tag:** `tui` or `all`

## Architecture Pattern

Watch commands are thin wrappers that:
1. Parse CLI flags and bind to Viper
2. Create TUI model with appropriate mode settings
3. Start Bubbletea program with capture in background

```go
// Pattern used by all watch subcommands
func runMode(cmd *cobra.Command, args []string) {
    logger.Disable()  // Prevent TUI corruption
    defer logger.Enable()

    model := tui.NewModel(
        bufferSize,
        interfaceName,
        filter,
        pcapFile,
        promiscuous,
        isRemoteMode,
        nodesFilePath,
        insecure,
    )

    p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())
    tui.SetCurrentProgram(p)

    // Start capture in background (mode-specific)
    go startCapture(ctx, p)

    p.Run()
}
```

## Mode Differences

| Mode | Capture Source | Background Task |
|------|---------------|-----------------|
| `live` | Network interface | `capture.StartLiveSniffer()` |
| `file` | PCAP file | `capture.StartOfflineSniffer()` |
| `remote` | gRPC stream | None (connections via TUI) |

## Key Integration Points

### With internal/pkg/tui/
- `tui.NewModel()` - Create TUI model with mode settings
- `tui.SetCurrentProgram()` - Enable packet bridge updates
- `tui.SetCaptureHandle()` - Enable graceful shutdown
- `tui.StartPacketBridge()` - Forward packets to TUI

### With internal/pkg/capture/
- `capture.StartLiveSniffer()` - Live interface capture
- `capture.StartOfflineSniffer()` - PCAP file reading
- `capture.InitWithContext()` - Context-aware capture loop

## Viper Configuration

```yaml
tui:
  buffer_size: 10000
  gpu:
    enabled: false
    backend: "auto"
    batch_size: 100
  tls:
    enabled: false
    ca_file: ""
    cert_file: ""
    key_file: ""
  tls_keylog: ""  # SSLKEYLOGFILE path for TLS decryption
```

Flags use `Changed()` check to allow config file defaults:

```go
if cmd.Flags().Changed("tls") {
    viper.Set("tui.tls.enabled", tlsEnabled)
}
```

## See Also

- [README.md](README.md) - User documentation
- [internal/pkg/tui/CLAUDE.md](../../internal/pkg/tui/CLAUDE.md) - TUI architecture
