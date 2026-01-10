# Show Command - Architecture

The `show` command provides remote processor diagnostics via gRPC, plus local configuration display.

## Structure

```
cmd/show/
├── show.go      - Base command (requires subcommand)
├── status.go    - Processor status (gRPC)
├── hunters.go   - Hunter details (gRPC)
├── topology.go  - Distributed topology (gRPC)
├── filter.go    - Filter details (delegates to cmd/filter)
└── config.go    - Local configuration display
```

**Build Tag:** `cli` or `all`

## Architecture

### Remote Commands (gRPC-based)

Commands that query remote processors:
- `show status` - Processor stats via `GetHunterStatus`
- `show hunters` - Hunter details via `GetHunterStatus`
- `show topology` - Full topology via `GetTopology`
- `show filter` - Filter details (delegated to cmd/filter)

All use:
- `internal/pkg/statusclient` for gRPC client
- `cmd/filter.AddConnectionFlags()` for connection flags
- `cmd/filter.OutputError()` for JSON error output
- JSON output to stdout for scripting

### Local Commands

- `show config` - Displays local TCP SIP configuration from `internal/pkg/voip`

## Integration Pattern

Remote show commands reuse the filter package's connection utilities:

```go
import "github.com/endorses/lippycat/cmd/filter"

func init() {
    filter.AddConnectionFlags(statusCmd)
    ShowCmd.AddCommand(statusCmd)
}

func runShowStatus(cmd *cobra.Command, args []string) {
    client, err := newStatusClient()
    if err != nil {
        filter.OutputError(err, filter.ExitConnectionError)
        return
    }
    defer client.Close()

    resp, err := client.GetStatus()
    // ...
}
```

## statusclient Package

`internal/pkg/statusclient/` provides:

```go
// Client creation
client, err := statusclient.NewStatusClient(config)
defer client.Close()

// Methods
resp, err := client.GetStatus()         // ProcessorStats + hunters summary
hunters, err := client.GetHunters(id)   // ConnectedHunter details
topo, err := client.GetTopology()       // Full topology tree

// JSON conversion
json, err := statusclient.StatusResponseToJSON(resp)
json, err := statusclient.HuntersToJSON(hunters)
json, err := statusclient.TopologyToJSON(topo)
```

## gRPC Methods Used

| Command | gRPC Method | Response |
|---------|-------------|----------|
| `show status` | `GetHunterStatus` | ProcessorStats |
| `show hunters` | `GetHunterStatus` | []ConnectedHunter |
| `show topology` | `GetTopology` | ProcessorNode (recursive) |
| `show filter` | `GetFilters` | Filter (via filterclient) |

## JSON Output Format

All remote commands output JSON for scripting:

```go
jsonBytes, err := statusclient.StatusResponseToJSON(resp)
cmd.Println(string(jsonBytes))
```

Errors also output JSON to stderr:

```go
filter.OutputError(err, filter.ExitConnectionError)
// Outputs: {"error":"...","code":"UNAVAILABLE"}
```

## Exit Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | ExitSuccess | Success |
| 1 | ExitGeneralError | General error |
| 2 | ExitConnectionError | Connection failed |
| 3 | ExitValidationError | Invalid input |
| 4 | ExitNotFoundError | Resource not found |

## Adding New Show Subcommands

```go
// cmd/show/newcmd.go
var newCmd = &cobra.Command{
    Use:   "newcmd",
    Short: "Show something new",
    Run:   runNewCmd,
}

func init() {
    filter.AddConnectionFlags(newCmd)
    ShowCmd.AddCommand(newCmd)
}

func runNewCmd(cmd *cobra.Command, args []string) {
    client, err := newStatusClient()
    if err != nil {
        filter.OutputError(err, filter.ExitConnectionError)
        return
    }
    defer client.Close()

    // Query and output JSON
}
```

## See Also

- [README.md](README.md) - User documentation
- [../filter/CLAUDE.md](../filter/CLAUDE.md) - Filter command architecture
- [../../internal/pkg/statusclient/](../../internal/pkg/statusclient/) - Status client package
