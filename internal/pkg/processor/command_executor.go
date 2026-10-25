//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// shellMetachars contains shell metacharacters that could enable injection attacks
const shellMetachars = ";|&$`\\\"'<>(){}[]!#~*?\n\r"

// shellEscape escapes a string for safe use in shell commands.
// It wraps the value in single quotes and escapes any embedded single quotes.
// This is the safest approach as single-quoted strings in sh/bash
// treat all characters literally except for single quotes themselves.
func shellEscape(s string) string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote)
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
}

// containsShellMetachars checks if a string contains shell metacharacters.
// This is used for logging/warning purposes.
func containsShellMetachars(s string) bool {
	return strings.ContainsAny(s, shellMetachars)
}

// CallMetadata contains information about a completed VoIP call
type CallMetadata struct {
	CallID   string
	DirName  string
	Caller   string
	Called   string
	CallDate time.Time
}

// TunnelingMetadata contains information about detected DNS tunneling
type TunnelingMetadata struct {
	Domain    string
	Score     float64
	Entropy   float64
	Queries   int64
	SrcIPs    []string
	HunterID  string
	Timestamp time.Time
}

// CommandExecutorConfig configures the command executor
type CommandExecutorConfig struct {
	PcapCommand      string        // Template with %pcap% placeholder
	VoipCommand      string        // Template with %callid%, %dirname%, %caller%, %called%, %calldate%
	TunnelingCommand string        // Template with %domain%, %score%, %entropy%, %queries%, %srcips%, %hunter%, %timestamp%
	Timeout          time.Duration // Command execution timeout (default: 30s)
	Concurrency      int           // Max concurrent command executions (default: 10)
	DryRun           bool          // Log commands without executing
}

// DefaultCommandExecutorConfig returns default configuration
func DefaultCommandExecutorConfig() *CommandExecutorConfig {
	return &CommandExecutorConfig{
		Timeout:     30 * time.Second,
		Concurrency: 10,
		DryRun:      false,
	}
}

// CommandExecutor handles command template substitution and async execution
type CommandExecutor struct {
	config *CommandExecutorConfig
	sem    chan struct{} // Semaphore for limiting concurrent executions
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor(config *CommandExecutorConfig) *CommandExecutor {
	if config == nil {
		config = DefaultCommandExecutorConfig()
	}

	// Ensure reasonable defaults
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}

	return &CommandExecutor{
		config: config,
		sem:    make(chan struct{}, config.Concurrency),
	}
}

// HasPcapCommand returns true if a PCAP command is configured
func (e *CommandExecutor) HasPcapCommand() bool {
	return e != nil && e.config.PcapCommand != ""
}

// HasVoipCommand returns true if a VoIP command is configured
func (e *CommandExecutor) HasVoipCommand() bool {
	return e != nil && e.config.VoipCommand != ""
}

// HasTunnelingCommand returns true if a tunneling command is configured
func (e *CommandExecutor) HasTunnelingCommand() bool {
	return e != nil && e.config.TunnelingCommand != ""
}

// ExecutePcapCommand executes the PCAP command asynchronously with the given file path
func (e *CommandExecutor) ExecutePcapCommand(filePath string) {
	if e == nil || e.config.PcapCommand == "" {
		return
	}

	// Log warning if filePath contains shell metacharacters
	if containsShellMetachars(filePath) {
		logger.Warn("PCAP file path contains shell metacharacters, escaping for safety",
			"file", filePath,
		)
	}

	// Substitute placeholder with shell-escaped value to prevent command injection
	cmd := strings.ReplaceAll(e.config.PcapCommand, "%pcap%", shellEscape(filePath))

	go e.executeAsync(cmd, "pcap", map[string]string{
		"file": filePath,
	})
}

// ExecuteVoipCommand executes the VoIP command asynchronously with call metadata
func (e *CommandExecutor) ExecuteVoipCommand(meta CallMetadata) {
	if e == nil || e.config.VoipCommand == "" {
		return
	}

	// Log warning if any metadata fields contain shell metacharacters
	// These values come from SIP packets and could be attacker-controlled
	for _, field := range []struct {
		name  string
		value string
	}{
		{"call_id", meta.CallID},
		{"caller", meta.Caller},
		{"called", meta.Called},
	} {
		if containsShellMetachars(field.value) {
			logger.Warn("VoIP metadata contains shell metacharacters, escaping for safety",
				"field", field.name,
				"call_id", meta.CallID,
			)
			break // Only log once per command
		}
	}

	// Substitute all placeholders with shell-escaped values to prevent command injection.
	// CallID, Caller, and Called come from SIP packets and could be attacker-controlled.
	// DirName is derived from CallID (already sanitized) and timestamps.
	// CallDate is generated internally but escaped for consistency.
	cmd := e.config.VoipCommand
	cmd = strings.ReplaceAll(cmd, "%callid%", shellEscape(meta.CallID))
	cmd = strings.ReplaceAll(cmd, "%dirname%", shellEscape(meta.DirName))
	cmd = strings.ReplaceAll(cmd, "%caller%", shellEscape(meta.Caller))
	cmd = strings.ReplaceAll(cmd, "%called%", shellEscape(meta.Called))
	cmd = strings.ReplaceAll(cmd, "%calldate%", shellEscape(meta.CallDate.Format(time.RFC3339)))

	go e.executeAsync(cmd, "voip", map[string]string{
		"call_id": meta.CallID,
		"dir":     meta.DirName,
	})
}

// ExecuteTunnelingCommand executes the tunneling command asynchronously with detection metadata
func (e *CommandExecutor) ExecuteTunnelingCommand(meta TunnelingMetadata) {
	if e == nil || e.config.TunnelingCommand == "" {
		return
	}
	command, fields := e.tunnelingCommand(meta)
	go e.executeAsync(command, "tunneling", fields)
}

// tunnelingCommand preserves the legacy substitutions for both command paths.
func (e *CommandExecutor) tunnelingCommand(meta TunnelingMetadata) (string, map[string]string) {
	// Log warning if domain contains shell metacharacters
	// Domain names come from DNS packets and could be attacker-controlled
	if containsShellMetachars(meta.Domain) {
		logger.Warn("Tunneling domain contains shell metacharacters, escaping for safety",
			"domain", meta.Domain,
		)
	}

	// Format score and entropy as floats with 2 decimal places
	scoreStr := fmt.Sprintf("%.2f", meta.Score)
	entropyStr := fmt.Sprintf("%.2f", meta.Entropy)

	// Format queries as integer
	queriesStr := fmt.Sprintf("%d", meta.Queries)

	// Join source IPs with commas
	srcIPsStr := strings.Join(meta.SrcIPs, ",")

	// Substitute all placeholders with shell-escaped values to prevent command injection.
	// Domain comes from DNS packets and could be attacker-controlled.
	// Other values are internally generated but escaped for consistency.
	// A single pass keeps placeholder-looking observation bytes opaque. Sequential
	// replacements would reinterpret an inserted %hunter% inside already quoted
	// domain data and could break its shell-escaping boundary.
	cmd := strings.NewReplacer(
		"%domain%", shellEscape(meta.Domain),
		"%score%", shellEscape(scoreStr),
		"%entropy%", shellEscape(entropyStr),
		"%queries%", shellEscape(queriesStr),
		"%srcips%", shellEscape(srcIPsStr),
		"%hunter%", shellEscape(meta.HunterID),
		"%timestamp%", shellEscape(meta.Timestamp.Format(time.RFC3339)),
	).Replace(e.config.TunnelingCommand)

	return cmd, map[string]string{
		"domain":  meta.Domain,
		"score":   scoreStr,
		"hunter":  meta.HunterID,
		"src_ips": srcIPsStr,
		"queries": queriesStr,
		"entropy": entropyStr,
	}
}

var ErrCommandConcurrencyLimit = errors.New("command executor concurrency limit reached")

// boundedCommandOutput retains a diagnostic prefix while draining the complete
// output stream. stdout and stderr may write concurrently.
type boundedCommandOutput struct {
	mu        sync.Mutex
	limit     int
	bytes     []byte
	truncated bool
}

func (w *boundedCommandOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	keep := min(len(p), w.limit-len(w.bytes))
	w.bytes = append(w.bytes, p[:keep]...)
	w.truncated = w.truncated || keep < len(p)
	return len(p), nil
}

// ExecuteTunnelingCommandContext executes one admitted notice action and waits
// for its completion. Unlike the legacy asynchronous helpers, the caller owns
// cancellation, bounded diagnostics and shutdown of this execution.
func (e *CommandExecutor) ExecuteTunnelingCommandContext(parent context.Context, meta TunnelingMetadata, maxOutputBytes int) error {
	if !e.HasTunnelingCommand() {
		return errors.New("tunneling command is not configured")
	}
	if parent == nil || maxOutputBytes <= 0 {
		return errors.New("tunneling execution requires a context and positive output limit")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	default:
		return ErrCommandConcurrencyLimit
	}
	command, _ := e.tunnelingCommand(meta)
	if e.config.DryRun {
		logger.Info("Notice command executor dry run", "type", "tunneling", "command", command)
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, e.config.Timeout)
	defer cancel()
	// #nosec G204 -- Admin-configured template; every observation substitution is shell-escaped.
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	configureNoticeCommandProcess(cmd)
	// Also bound waits for inherited output pipes on platforms where process
	// groups are unavailable. Descendant termination is a Unix capability.
	cmd.WaitDelay = 100 * time.Millisecond
	output := &boundedCommandOutput{limit: maxOutputBytes}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	if err != nil {
		err = errors.Join(err, ctx.Err())
		logger.Error("Notice tunneling command failed", "error", err, "output", string(output.bytes), "output_truncated", output.truncated)
		return fmt.Errorf("execute tunneling command: %w", err)
	}
	logger.Debug("Notice tunneling command completed", "output", string(output.bytes), "output_truncated", output.truncated)
	return nil
}

// executeAsync executes a command with timeout and concurrency control
func (e *CommandExecutor) executeAsync(cmdStr, cmdType string, logFields map[string]string) {
	// Acquire semaphore slot
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	default:
		logger.Warn("Command executor at concurrency limit, dropping command",
			"type", cmdType,
			"command", cmdStr,
		)
		return
	}

	// Build log fields
	fields := []any{
		"type", cmdType,
		"command", cmdStr,
	}
	for k, v := range logFields {
		fields = append(fields, k, v)
	}

	// Dry run mode - log without executing
	if e.config.DryRun {
		logger.Info("Command executor dry run", fields...)
		return
	}

	logger.Debug("Executing command", fields...)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Execute command via shell
	// #nosec G204 -- Command template from config, substituted values are shell-escaped
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Command timed out",
				"type", cmdType,
				"command", cmdStr,
				"timeout", e.config.Timeout,
			)
		} else {
			logger.Error("Command failed",
				"type", cmdType,
				"command", cmdStr,
				"error", err,
				"output", string(output),
			)
		}
		return
	}

	logger.Debug("Command completed successfully",
		"type", cmdType,
		"command", cmdStr,
		"output", string(output),
	)
}

// OnFileClose returns a callback function for PCAP file close events
func (e *CommandExecutor) OnFileClose() func(filePath string) {
	if e == nil || !e.HasPcapCommand() {
		return nil
	}
	return e.ExecutePcapCommand
}

// OnCallComplete returns a callback function for VoIP call complete events
func (e *CommandExecutor) OnCallComplete() func(meta CallMetadata) {
	if e == nil || !e.HasVoipCommand() {
		return nil
	}
	return e.ExecuteVoipCommand
}

// OnTunnelingDetected returns a callback function for DNS tunneling detection events
func (e *CommandExecutor) OnTunnelingDetected() func(meta TunnelingMetadata) {
	if e == nil || !e.HasTunnelingCommand() {
		return nil
	}
	return e.ExecuteTunnelingCommand
}
