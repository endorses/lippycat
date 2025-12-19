package processor

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// CallMetadata contains information about a completed VoIP call
type CallMetadata struct {
	CallID   string
	DirName  string
	Caller   string
	Called   string
	CallDate time.Time
}

// CommandExecutorConfig configures the command executor
type CommandExecutorConfig struct {
	PcapCommand string        // Template with %pcap% placeholder
	VoipCommand string        // Template with %callid%, %dirname%, %caller%, %called%, %calldate%
	Timeout     time.Duration // Command execution timeout (default: 30s)
	Concurrency int           // Max concurrent command executions (default: 10)
	DryRun      bool          // Log commands without executing
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

// ExecutePcapCommand executes the PCAP command asynchronously with the given file path
func (e *CommandExecutor) ExecutePcapCommand(filePath string) {
	if e == nil || e.config.PcapCommand == "" {
		return
	}

	// Substitute placeholder
	cmd := strings.ReplaceAll(e.config.PcapCommand, "%pcap%", filePath)

	go e.executeAsync(cmd, "pcap", map[string]string{
		"file": filePath,
	})
}

// ExecuteVoipCommand executes the VoIP command asynchronously with call metadata
func (e *CommandExecutor) ExecuteVoipCommand(meta CallMetadata) {
	if e == nil || e.config.VoipCommand == "" {
		return
	}

	// Substitute all placeholders
	cmd := e.config.VoipCommand
	cmd = strings.ReplaceAll(cmd, "%callid%", meta.CallID)
	cmd = strings.ReplaceAll(cmd, "%dirname%", meta.DirName)
	cmd = strings.ReplaceAll(cmd, "%caller%", meta.Caller)
	cmd = strings.ReplaceAll(cmd, "%called%", meta.Called)
	cmd = strings.ReplaceAll(cmd, "%calldate%", meta.CallDate.Format(time.RFC3339))

	go e.executeAsync(cmd, "voip", map[string]string{
		"call_id": meta.CallID,
		"dir":     meta.DirName,
	})
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
	// #nosec G204 -- Command comes from config file, not user input
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
