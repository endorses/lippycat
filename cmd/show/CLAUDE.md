# Show Command - Architecture

The `show` command provides diagnostics for TCP SIP processing. Queries runtime state from `internal/pkg/voip/`.

## Structure

```
cmd/show/
├── show.go     - Base command (requires subcommand)
├── health.go   - TCP assembler health
├── metrics.go  - Comprehensive TCP metrics
├── alerts.go   - Alert management
├── buffers.go  - Buffer statistics
├── streams.go  - Stream metrics
├── config.go   - Configuration display
└── summary.go  - System overview
```

**Build Tag:** `cli` or `all`

## Integration with internal/pkg/voip/

All show commands query the VoIP package's runtime state:

```go
// Health checks
voip.IsTCPAssemblerHealthy() bool
voip.GetTCPAssemblerHealth() map[string]interface{}

// Metrics
voip.GetTCPAssemblerMetrics() map[string]interface{}
voip.GetTCPStreamMetrics() TCPStreamMetrics
voip.GetTCPBufferStats() TCPBufferStats

// Alerts
voip.GetAlertManager() *AlertManager
alertManager.GetActiveAlerts() []Alert
alertManager.GetAlertHistory() []Alert
alertManager.ClearAllAlerts()

// Config
voip.GetConfig() *Config
```

## Output Format Pattern

Most commands support JSON output:

```go
func showMetrics(jsonOutput bool) {
    metrics := voip.GetTCPAssemblerMetrics()

    if jsonOutput {
        data, _ := json.MarshalIndent(metrics, "", "  ")
        fmt.Println(string(data))
        return
    }

    // Human-readable output
    fmt.Println("=== TCP Metrics ===")
    // ...
}
```

## Not Initialized Handling

All commands handle the case where no VoIP capture is running:

```go
health := voip.GetTCPAssemblerHealth()
if status, ok := health["status"].(string); ok && status == "not_initialized" {
    fmt.Println("TCP factory not initialized - no active VoIP capture")
    return
}
```

## Adding New Subcommands

```go
// cmd/show/newmetric.go
var newMetricCmd = &cobra.Command{
    Use:   "newmetric",
    Short: "Show new metric",
    Run: func(cmd *cobra.Command, args []string) {
        jsonOutput, _ := cmd.Flags().GetBool("json")
        showNewMetric(jsonOutput)
    },
}

func init() {
    newMetricCmd.Flags().Bool("json", false, "JSON output")
    ShowCmd.AddCommand(newMetricCmd)
}
```

## See Also

- [README.md](README.md) - User documentation
- [internal/pkg/voip/tcp_metrics.go](../../internal/pkg/voip/tcp_metrics.go) - Metrics implementation
