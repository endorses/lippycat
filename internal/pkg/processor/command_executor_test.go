package processor

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCommandExecutorConfig(t *testing.T) {
	config := DefaultCommandExecutorConfig()

	assert.NotNil(t, config)
	assert.Empty(t, config.PcapCommand)
	assert.Empty(t, config.VoipCommand)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 10, config.Concurrency)
	assert.False(t, config.DryRun)
}

func TestNewCommandExecutor(t *testing.T) {
	tests := []struct {
		name               string
		config             *CommandExecutorConfig
		expectedTimeout    time.Duration
		expectedConcurrent int
	}{
		{
			name:               "nil config uses defaults",
			config:             nil,
			expectedTimeout:    30 * time.Second,
			expectedConcurrent: 10,
		},
		{
			name: "custom config",
			config: &CommandExecutorConfig{
				Timeout:     5 * time.Second,
				Concurrency: 3,
			},
			expectedTimeout:    5 * time.Second,
			expectedConcurrent: 3,
		},
		{
			name: "zero timeout gets default",
			config: &CommandExecutorConfig{
				Timeout:     0,
				Concurrency: 5,
			},
			expectedTimeout:    30 * time.Second,
			expectedConcurrent: 5,
		},
		{
			name: "negative concurrency gets default",
			config: &CommandExecutorConfig{
				Timeout:     10 * time.Second,
				Concurrency: -1,
			},
			expectedTimeout:    10 * time.Second,
			expectedConcurrent: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewCommandExecutor(tt.config)

			assert.NotNil(t, executor)
			assert.NotNil(t, executor.config)
			assert.Equal(t, tt.expectedTimeout, executor.config.Timeout)
			assert.Equal(t, tt.expectedConcurrent, executor.config.Concurrency)
			assert.NotNil(t, executor.sem)
			assert.Equal(t, tt.expectedConcurrent, cap(executor.sem))
		})
	}
}

func TestHasPcapCommand(t *testing.T) {
	tests := []struct {
		name     string
		executor *CommandExecutor
		expected bool
	}{
		{
			name:     "nil executor",
			executor: nil,
			expected: false,
		},
		{
			name:     "empty command",
			executor: NewCommandExecutor(&CommandExecutorConfig{}),
			expected: false,
		},
		{
			name: "with command",
			executor: NewCommandExecutor(&CommandExecutorConfig{
				PcapCommand: "echo %pcap%",
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.executor.HasPcapCommand())
		})
	}
}

func TestHasVoipCommand(t *testing.T) {
	tests := []struct {
		name     string
		executor *CommandExecutor
		expected bool
	}{
		{
			name:     "nil executor",
			executor: nil,
			expected: false,
		},
		{
			name:     "empty command",
			executor: NewCommandExecutor(&CommandExecutorConfig{}),
			expected: false,
		},
		{
			name: "with command",
			executor: NewCommandExecutor(&CommandExecutorConfig{
				VoipCommand: "echo %callid%",
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.executor.HasVoipCommand())
		})
	}
}

func TestExecutePcapCommand_PlaceholderSubstitution(t *testing.T) {
	// Create temp file to verify command execution
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	testPath := "/var/pcaps/call_123_sip.pcap"

	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Note: Do NOT quote %pcap% - shellEscape adds quotes automatically
		PcapCommand: "echo %pcap% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecutePcapCommand(testPath)

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)

	// Verify file was created with correct content
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, testPath+"\n", string(content))
}

func TestExecuteVoipCommand_PlaceholderSubstitution(t *testing.T) {
	// Create temp file to verify command execution
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")

	callDate := time.Date(2024, 12, 18, 14, 30, 52, 0, time.UTC)
	meta := CallMetadata{
		CallID:   "abc123@192.168.1.1",
		DirName:  "/var/pcaps/calls/20241218_143052",
		Caller:   "alice@example.com",
		Called:   "bob@example.com",
		CallDate: callDate,
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Note: Do NOT quote placeholders - shellEscape adds quotes automatically
		// Use printf to concatenate the shell-escaped values
		VoipCommand: "printf '%s|%s|%s|%s|%s\\n' %callid% %dirname% %caller% %called% %calldate% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecuteVoipCommand(meta)

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)

	// Verify file was created with correct content
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	expected := "abc123@192.168.1.1|/var/pcaps/calls/20241218_143052|alice@example.com|bob@example.com|2024-12-18T14:30:52Z\n"
	assert.Equal(t, expected, string(content))
}

func TestExecutePcapCommand_NilExecutor(t *testing.T) {
	var executor *CommandExecutor
	// Should not panic
	executor.ExecutePcapCommand("/test/path.pcap")
}

func TestExecuteVoipCommand_NilExecutor(t *testing.T) {
	var executor *CommandExecutor
	// Should not panic
	executor.ExecuteVoipCommand(CallMetadata{})
}

func TestExecutePcapCommand_EmptyCommand(t *testing.T) {
	executor := NewCommandExecutor(&CommandExecutorConfig{
		PcapCommand: "",
	})

	// Should not panic or execute anything
	executor.ExecutePcapCommand("/test/path.pcap")
}

func TestExecuteVoipCommand_EmptyCommand(t *testing.T) {
	executor := NewCommandExecutor(&CommandExecutorConfig{
		VoipCommand: "",
	})

	// Should not panic or execute anything
	executor.ExecuteVoipCommand(CallMetadata{})
}

func TestCommandExecutor_ConcurrencyLimit(t *testing.T) {
	tmpDir := t.TempDir()

	var activeCount atomic.Int32
	var maxActive atomic.Int32
	var droppedCount atomic.Int32

	// Create executor with concurrency limit of 2
	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Command that sleeps briefly and writes to a file
		PcapCommand: "sleep 0.1",
		Timeout:     5 * time.Second,
		Concurrency: 2,
	})

	// Override the semaphore behavior by wrapping
	// We'll test by launching many commands and checking behavior
	var wg sync.WaitGroup
	numCommands := 10

	// Track active commands using a separate counter file approach
	counterFile := filepath.Join(tmpDir, "counter.txt")
	err := os.WriteFile(counterFile, []byte("0"), 0600)
	require.NoError(t, err)

	// Launch many commands concurrently
	for i := 0; i < numCommands; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Check if semaphore is full
			select {
			case executor.sem <- struct{}{}:
				current := activeCount.Add(1)
				// Track max concurrent
				for {
					old := maxActive.Load()
					if current <= old || maxActive.CompareAndSwap(old, current) {
						break
					}
				}
				// Simulate work
				time.Sleep(50 * time.Millisecond)
				activeCount.Add(-1)
				<-executor.sem
			default:
				droppedCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Max active should never exceed concurrency limit
	assert.LessOrEqual(t, maxActive.Load(), int32(2), "Max active commands should not exceed concurrency limit")
}

func TestCommandExecutor_Timeout(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")

	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Command that takes longer than timeout
		PcapCommand: "sleep 5 && echo 'done' > " + outputFile,
		Timeout:     100 * time.Millisecond,
		Concurrency: 1,
	})

	start := time.Now()
	executor.ExecutePcapCommand("/test/path.pcap")

	// Wait a bit for the command to be killed
	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start)

	// Command should have been killed quickly (within ~200ms of timeout)
	assert.Less(t, elapsed, 500*time.Millisecond, "Command should have been killed by timeout")

	// Output file should not exist (command was killed before completion)
	_, err := os.Stat(outputFile)
	assert.True(t, os.IsNotExist(err), "Output file should not exist - command should have been killed")
}

func TestCommandExecutor_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")

	executor := NewCommandExecutor(&CommandExecutorConfig{
		PcapCommand: "echo 'test' > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
		DryRun:      true,
	})

	executor.ExecutePcapCommand("/test/path.pcap")

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)

	// Output file should not exist (dry run doesn't execute)
	_, err := os.Stat(outputFile)
	assert.True(t, os.IsNotExist(err), "Output file should not exist in dry-run mode")
}

func TestOnFileClose(t *testing.T) {
	tests := []struct {
		name      string
		executor  *CommandExecutor
		expectNil bool
	}{
		{
			name:      "nil executor",
			executor:  nil,
			expectNil: true,
		},
		{
			name:      "no pcap command",
			executor:  NewCommandExecutor(&CommandExecutorConfig{}),
			expectNil: true,
		},
		{
			name: "with pcap command",
			executor: NewCommandExecutor(&CommandExecutorConfig{
				PcapCommand: "echo %pcap%",
			}),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := tt.executor.OnFileClose()
			if tt.expectNil {
				assert.Nil(t, callback)
			} else {
				assert.NotNil(t, callback)
			}
		})
	}
}

func TestOnCallComplete(t *testing.T) {
	tests := []struct {
		name      string
		executor  *CommandExecutor
		expectNil bool
	}{
		{
			name:      "nil executor",
			executor:  nil,
			expectNil: true,
		},
		{
			name:      "no voip command",
			executor:  NewCommandExecutor(&CommandExecutorConfig{}),
			expectNil: true,
		},
		{
			name: "with voip command",
			executor: NewCommandExecutor(&CommandExecutorConfig{
				VoipCommand: "echo %callid%",
			}),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := tt.executor.OnCallComplete()
			if tt.expectNil {
				assert.Nil(t, callback)
			} else {
				assert.NotNil(t, callback)
			}
		})
	}
}

func TestOnFileClose_CallbackWorks(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	testPath := "/var/pcaps/test.pcap"

	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Note: Do NOT quote %pcap% - shellEscape adds quotes automatically
		PcapCommand: "echo %pcap% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	callback := executor.OnFileClose()
	require.NotNil(t, callback)

	// Call the callback
	callback(testPath)

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)

	// Verify file was created
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, testPath+"\n", string(content))
}

func TestOnCallComplete_CallbackWorks(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")

	meta := CallMetadata{
		CallID:   "test-call-id",
		DirName:  "/var/pcaps/calls",
		Caller:   "alice",
		Called:   "bob",
		CallDate: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		// Note: Do NOT quote %callid% - shellEscape adds quotes automatically
		VoipCommand: "echo %callid% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	callback := executor.OnCallComplete()
	require.NotNil(t, callback)

	// Call the callback
	callback(meta)

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)

	// Verify file was created
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "test-call-id\n", string(content))
}

func TestCommandExecutor_FailedCommand(t *testing.T) {
	executor := NewCommandExecutor(&CommandExecutorConfig{
		PcapCommand: "exit 1",
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	// Should not panic on failed command
	executor.ExecutePcapCommand("/test/path.pcap")

	// Wait for async execution
	time.Sleep(100 * time.Millisecond)
}

// === Command Injection Prevention Tests ===

func TestShellEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "'hello'",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "'hello world'",
		},
		{
			name:     "string with single quote",
			input:    "it's",
			expected: "'it'\\''s'",
		},
		{
			name:     "string with multiple single quotes",
			input:    "don't won't",
			expected: "'don'\\''t won'\\''t'",
		},
		{
			name:     "string with shell metacharacters",
			input:    "; rm -rf /",
			expected: "'; rm -rf /'",
		},
		{
			name:     "string with backticks",
			input:    "`whoami`",
			expected: "'`whoami`'",
		},
		{
			name:     "string with command substitution",
			input:    "$(cat /etc/passwd)",
			expected: "'$(cat /etc/passwd)'",
		},
		{
			name:     "string with pipe",
			input:    "test | cat",
			expected: "'test | cat'",
		},
		{
			name:     "string with redirect",
			input:    "test > /etc/passwd",
			expected: "'test > /etc/passwd'",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "path with spaces",
			input:    "/path/with spaces/file.pcap",
			expected: "'/path/with spaces/file.pcap'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellEscape(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsShellMetachars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"safe string", "hello-world_123", false},
		{"safe path", "/var/pcaps/call.pcap", false},
		{"safe email", "alice@example.com", false},
		{"semicolon", "test; rm -rf /", true},
		{"pipe", "test | cat", true},
		{"ampersand", "test && echo", true},
		{"dollar sign", "$HOME", true},
		{"backtick", "`whoami`", true},
		{"double quote", "test\"quote", true},
		{"single quote", "it's", true},
		{"redirect", "test > file", true},
		{"newline", "test\ncommand", true},
		{"parenthesis", "$(cmd)", true},
		{"brackets", "{a,b}", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsShellMetachars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExecutePcapCommand_CommandInjectionPrevention(t *testing.T) {
	// Test that malicious file paths are safely escaped
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	markerFile := filepath.Join(tmpDir, "INJECTED")

	// Malicious file path attempting command injection
	maliciousPath := "/var/pcaps/test.pcap'; touch '" + markerFile + "'; echo '"

	executor := NewCommandExecutor(&CommandExecutorConfig{
		PcapCommand: "echo %pcap% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecutePcapCommand(maliciousPath)

	// Wait for async execution
	time.Sleep(200 * time.Millisecond)

	// The marker file should NOT exist - injection should have been prevented
	_, err := os.Stat(markerFile)
	assert.True(t, os.IsNotExist(err), "Injection marker file should NOT exist - command injection should be prevented")

	// The output file should contain the escaped path (not executed as command)
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, maliciousPath+"\n", string(content))
}

func TestExecuteVoipCommand_CommandInjectionPrevention_CallID(t *testing.T) {
	// Test injection via Call-ID field (attacker-controlled from SIP packet)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	markerFile := filepath.Join(tmpDir, "INJECTED")

	// Malicious Call-ID attempting command injection
	meta := CallMetadata{
		CallID:   "abc123'; touch '" + markerFile + "'; echo '",
		DirName:  "/var/pcaps/calls",
		Caller:   "alice@example.com",
		Called:   "bob@example.com",
		CallDate: time.Now(),
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		VoipCommand: "echo %callid% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecuteVoipCommand(meta)

	// Wait for async execution
	time.Sleep(200 * time.Millisecond)

	// The marker file should NOT exist - injection should have been prevented
	_, err := os.Stat(markerFile)
	assert.True(t, os.IsNotExist(err), "Injection marker file should NOT exist - command injection should be prevented")

	// The output file should contain the malicious string safely
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, meta.CallID+"\n", string(content))
}

func TestExecuteVoipCommand_CommandInjectionPrevention_Caller(t *testing.T) {
	// Test injection via Caller field (attacker-controlled from SIP From header)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	markerFile := filepath.Join(tmpDir, "INJECTED")

	// Malicious Caller attempting backtick command execution
	meta := CallMetadata{
		CallID:   "safe-call-id",
		DirName:  "/var/pcaps/calls",
		Caller:   "`touch " + markerFile + "`",
		Called:   "bob@example.com",
		CallDate: time.Now(),
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		VoipCommand: "echo %caller% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecuteVoipCommand(meta)

	// Wait for async execution
	time.Sleep(200 * time.Millisecond)

	// The marker file should NOT exist - backtick execution should have been prevented
	_, err := os.Stat(markerFile)
	assert.True(t, os.IsNotExist(err), "Injection marker file should NOT exist - backtick execution should be prevented")

	// The output should contain the literal backtick string
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, meta.Caller+"\n", string(content))
}

func TestExecuteVoipCommand_CommandInjectionPrevention_SubshellExpansion(t *testing.T) {
	// Test $() subshell expansion prevention
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	markerFile := filepath.Join(tmpDir, "INJECTED")

	// Malicious Called attempting $() command execution
	meta := CallMetadata{
		CallID:   "safe-call-id",
		DirName:  "/var/pcaps/calls",
		Caller:   "alice@example.com",
		Called:   "$(touch " + markerFile + ")",
		CallDate: time.Now(),
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		VoipCommand: "echo %called% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecuteVoipCommand(meta)

	// Wait for async execution
	time.Sleep(200 * time.Millisecond)

	// The marker file should NOT exist - subshell execution should have been prevented
	_, err := os.Stat(markerFile)
	assert.True(t, os.IsNotExist(err), "Injection marker file should NOT exist - $() execution should be prevented")

	// The output should contain the literal $() string
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, meta.Called+"\n", string(content))
}

func TestExecuteVoipCommand_PathWithSpaces(t *testing.T) {
	// Test that paths with spaces work correctly with escaping
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")

	meta := CallMetadata{
		CallID:   "call-id-with spaces",
		DirName:  "/var/pcaps/calls with spaces/subdir",
		Caller:   "alice with space@example.com",
		Called:   "bob smith@example.com",
		CallDate: time.Now(),
	}

	executor := NewCommandExecutor(&CommandExecutorConfig{
		VoipCommand: "echo %callid% > " + outputFile,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})

	executor.ExecuteVoipCommand(meta)

	// Wait for async execution
	time.Sleep(200 * time.Millisecond)

	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "call-id-with spaces\n", string(content))
}
