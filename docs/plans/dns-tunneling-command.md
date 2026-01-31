# DNS Tunneling Command Hook

## Overview

Add `--tunneling-command` flag to execute external commands when DNS tunneling is detected. Follows the existing `--pcap-command` and `--voip-command` patterns.

## Design Decisions

**Trigger**: Domain threshold crossing with debounce
- Alert when a domain's tunneling score crosses threshold (default: 0.7)
- Debounce per-domain to prevent alert fatigue (default: 5m)
- Track "last alerted" timestamp per domain

**Scope**: Processor and Tap nodes only
- Hunters detect and forward metadata, but don't execute commands
- Processor aggregates cross-hunter stats and triggers alerts
- Tap (standalone) triggers alerts from local detection

**Variables**: Both minimum and extended sets

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `%domain%` | Suspicious domain (or parent) | `evil.example.com` |
| `%score%` | Tunneling score (0.0-1.0) | `0.85` |
| `%entropy%` | Entropy score | `4.2` |
| `%queries%` | Query count observed | `1523` |
| `%srcips%` | Source IPs (comma-separated) | `192.168.1.10,192.168.1.20` |
| `%hunter%` | Hunter ID (distributed) or "local" | `hunter-01` |
| `%timestamp%` | Detection time (RFC3339) | `2025-01-11T14:30:22Z` |

## Implementation Plan

### Phase 1: Add Flags to Commands

**File:** `cmd/process/process.go`

- [x] Add `--tunneling-command` flag (string)
- [x] Add `--tunneling-threshold` flag (float64, default: 0.7)
- [x] Add `--tunneling-debounce` flag (duration, default: 5m)
- [x] Bind to viper: `processor.tunneling_command`, `processor.tunneling_threshold`, `processor.tunneling_debounce`

**File:** `cmd/tap/tap_dns.go`

- [x] Add `--tunneling-command` flag (string)
- [x] Add `--tunneling-threshold` flag (float64, default: 0.7)
- [x] Add `--tunneling-debounce` flag (duration, default: 5m)
- [x] Bind to viper (same keys as processor)

### Phase 2: Extend CommandExecutor

**File:** `internal/pkg/processor/command_executor.go`

- [x] Add `TunnelingCommand` to `CommandExecutorConfig`
- [x] Add `TunnelingMetadata` struct:
  ```go
  type TunnelingMetadata struct {
      Domain    string
      Score     float64
      Entropy   float64
      Queries   int64
      SrcIPs    []string
      HunterID  string
      Timestamp time.Time
  }
  ```

- [x] Implement `ExecuteTunnelingCommand(meta TunnelingMetadata)`:
  - Substitute all placeholders with shell-escaped values
  - Format score/entropy as "%.2f"
  - Format queries as integer
  - Join SrcIPs with commas
  - Execute async (same pattern as voip-command)

- [x] Add `OnTunnelingDetected()` callback factory method

**File:** `internal/pkg/processor/command_executor_test.go`

- [x] Add tests for tunneling placeholder substitution
- [x] Add tests for shell escaping of domain names

### Phase 3: Add Alert Tracking to TunnelingDetector

**File:** `internal/pkg/dns/tunneling.go`

- [x] Add `AlertConfig` struct:
  ```go
  type AlertConfig struct {
      Threshold float64       // Score threshold (default: 0.7)
      Debounce  time.Duration // Min time between alerts per domain (default: 5m)
      Callback  func(alert TunnelingAlert)
  }
  ```

- [x] Add `TunnelingAlert` struct:
  ```go
  type TunnelingAlert struct {
      Domain    string
      Score     float64
      Entropy   float64
      Queries   int64
      SrcIPs    []string
      HunterID  string
      Timestamp time.Time
  }
  ```

- [x] Add `lastAlerted map[string]time.Time` field to `TunnelingDetector`
- [x] Add `alertConfig *AlertConfig` field
- [x] Add `SetAlertConfig(config AlertConfig)` method
- [x] Modify `Analyze()` to check threshold and debounce:
  ```go
  if t.alertConfig != nil && stats.TunnelingScore >= t.alertConfig.Threshold {
      lastTime, exists := t.lastAlerted[domain]
      if !exists || time.Since(lastTime) >= t.alertConfig.Debounce {
          t.lastAlerted[domain] = time.Now()
          t.alertConfig.Callback(TunnelingAlert{...})
      }
  }
  ```

- [x] Add `hunterID string` field to track source (set per-packet or per-batch)
- [x] Add `srcIPs map[string]map[string]struct{}` to track unique source IPs per domain

**File:** `internal/pkg/dns/tunneling_test.go`

- [x] Add tests for alert threshold triggering
- [x] Add tests for debounce behavior
- [x] Add tests for source IP tracking

### Phase 4: Wire Callbacks in Processor

**File:** `internal/pkg/processor/processor.go`

- [x] Add `TunnelingThreshold` and `TunnelingDebounce` to `Config`
- [x] In `New()`, configure TunnelingDetector with AlertConfig:
  ```go
  if config.CommandExecutor != nil && config.CommandExecutor.TunnelingCommand != "" {
      p.dnsTunneling.SetAlertConfig(dns.AlertConfig{
          Threshold: config.TunnelingThreshold,
          Debounce:  config.TunnelingDebounce,
          Callback: func(alert dns.TunnelingAlert) {
              config.CommandExecutor.ExecuteTunnelingCommand(TunnelingMetadata{
                  Domain:    alert.Domain,
                  Score:     alert.Score,
                  Entropy:   alert.Entropy,
                  Queries:   alert.Queries,
                  SrcIPs:    alert.SrcIPs,
                  HunterID:  alert.HunterID,
                  Timestamp: alert.Timestamp,
              })
          },
      })
  }
  ```

**File:** `internal/pkg/processor/processor_packet_pipeline.go`

- [x] Pass hunter ID to Analyze() call (from batch.SourceID)
- [x] Pass source IP to Analyze() call (from packet metadata)

**File:** `cmd/process/process.go`

- [x] Read viper values and pass to processor config
- [x] Add to CommandExecutorConfig initialization

**File:** `cmd/tap/tap_dns.go`

- [x] Read viper values and pass to processor config
- [x] Add to CommandExecutorConfig initialization

### Phase 5: Documentation

**File:** `cmd/process/README.md`

- [x] Document `--tunneling-command` flag
- [x] Document `--tunneling-threshold` flag
- [x] Document `--tunneling-debounce` flag
- [x] Add usage examples
- [x] Add config file example to Configuration File section

**File:** `cmd/tap/README.md`

- [x] Document flags (same as process)
- [x] Add usage examples
- [x] Add config file example

## Configuration File

All tunneling options can be specified in `~/.config/lippycat/config.yaml`:

```yaml
processor:
  # DNS tunneling detection alerts
  tunneling_command: "/opt/scripts/alert.sh %domain% %score% %srcips%"
  tunneling_threshold: 0.7
  tunneling_debounce: "5m"
```

The viper keys follow the existing pattern:
- `processor.tunneling_command` - Command template to execute
- `processor.tunneling_threshold` - Score threshold (float64)
- `processor.tunneling_debounce` - Debounce duration (string, e.g., "5m", "30s")

These work for both `lc process` and `lc tap dns` commands since they share the same viper namespace.

## Key Files to Modify

| File | Changes |
|------|---------|
| `cmd/process/process.go` | Add flags, viper bindings, wire config |
| `cmd/tap/tap_dns.go` | Add flags, viper bindings, wire config |
| `internal/pkg/processor/command_executor.go` | Add TunnelingMetadata, ExecuteTunnelingCommand |
| `internal/pkg/processor/command_executor_test.go` | Add tunneling tests |
| `internal/pkg/dns/tunneling.go` | Add AlertConfig, threshold/debounce logic |
| `internal/pkg/dns/tunneling_test.go` | Add alert tests |
| `internal/pkg/processor/processor.go` | Wire AlertConfig callback |
| `internal/pkg/processor/processor_packet_pipeline.go` | Pass hunter ID and source IP |
| `cmd/process/README.md` | Document flags |
| `cmd/tap/README.md` | Document flags |

## Data Flow

```
Packet with DNS metadata
        ↓
processBatch() extracts DNS metadata
        ↓
dnsTunneling.Analyze(metadata, hunterID, srcIP)
        ↓
Updates domain stats, checks threshold
        ↓
If score >= threshold AND debounce expired:
        ↓
AlertConfig.Callback(TunnelingAlert)
        ↓
CommandExecutor.ExecuteTunnelingCommand()
        ↓
Async shell execution with placeholders
```

## Example Usage

```bash
# Tap mode with tunneling alerts
sudo lc tap dns -i eth0 \
  --tunneling-command '/opt/scripts/alert.sh %domain% %score% %srcips%' \
  --tunneling-threshold 0.7 \
  --tunneling-debounce 5m

# Process mode with all placeholders
lc process --listen :55555 \
  --tunneling-command 'curl -X POST https://siem.example.com/alert \
    -d "domain=%domain%&score=%score%&entropy=%entropy%&queries=%queries%&srcips=%srcips%&hunter=%hunter%&time=%timestamp%"' \
  --tunneling-threshold 0.8 \
  --tunneling-debounce 10m

# Combined with voip and pcap commands
lc process --listen :55555 \
  --per-call-pcap \
  --pcap-command 'gzip %pcap%' \
  --voip-command 'notify-voip.sh %callid%' \
  --tunneling-command 'notify-tunneling.sh %domain% %score%'
```

## Verification

1. Build project: `make build`
2. Start tap dns with tunneling command:
   ```bash
   sudo lc tap dns -i lo \
     --tunneling-command 'echo "ALERT: %domain% score=%score%" >> /tmp/tunneling-alerts.log' \
     --tunneling-threshold 0.5 \
     --insecure
   ```
3. Run test script: `./scripts/test-dns-tunneling.sh --all -n 100`
4. Check alerts: `tail -f /tmp/tunneling-alerts.log`
5. Verify debounce: Same domain shouldn't alert again within debounce window

## Notes

- Uses existing CommandExecutor infrastructure (timeout, concurrency, shell escaping)
- Alert callback runs in goroutine to not block packet processing
- Debounce state is per-process (not persisted across restarts)
- Source IP tracking uses map of sets to avoid duplicates
- Hunter ID is "local" for tap mode, actual hunter ID for distributed mode
