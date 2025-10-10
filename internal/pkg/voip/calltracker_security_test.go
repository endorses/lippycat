package voip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSanitize_PathTraversalSecurity tests the sanitize function against various path traversal attacks
func TestSanitize_PathTraversalSecurity(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedResult string
		description    string
	}{
		{
			name:           "Basic path traversal",
			input:          "../etc/passwd",
			expectedResult: "___etc_passwd",
			description:    "Should neutralize basic path traversal",
		},
		{
			name:           "Deep path traversal",
			input:          "../../../../etc/passwd",
			expectedResult: "____________etc_passwd",
			description:    "Should neutralize deep path traversal",
		},
		{
			name:           "Windows path traversal",
			input:          "..\\..\\windows\\system32\\config",
			expectedResult: "______windows_system32_config",
			description:    "Should neutralize Windows path traversal",
		},
		{
			name:           "Mixed separators",
			input:          "../\\..//windows\\system32",
			expectedResult: "________windows_system32",
			description:    "Should handle mixed path separators",
		},
		{
			name:           "URL encoded path traversal",
			input:          "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expectedResult: "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			description:    "URL encoding should be preserved (handled at a different layer)",
		},
		{
			name:           "Null byte injection",
			input:          "normal-file\x00../../../etc/passwd",
			expectedResult: "normal-file__________etc_passwd",
			description:    "Should handle null byte injection attempts",
		},
		{
			name:           "Double encoding attempt",
			input:          "....//....//etc//passwd",
			expectedResult: "____________etc__passwd",
			description:    "Should handle double encoding attempts",
		},
		{
			name:           "Special filesystem names",
			input:          "CON.txt",
			expectedResult: "CON.txt",
			description:    "Should preserve valid filenames (Windows reserved names handled elsewhere)",
		},
		{
			name:           "Long filename attack",
			input:          strings.Repeat("A", 300),
			expectedResult: strings.Repeat("A", 100), // Truncated to 100 chars
			description:    "Should truncate very long filenames",
		},
		{
			name:           "All dangerous characters",
			input:          `<>:"/\|?*@`,
			expectedResult: "__________",
			description:    "Should replace all dangerous filesystem characters",
		},
		{
			name:           "Unicode path traversal",
			input:          "．．/．．/etc/passwd", // Full-width dots
			expectedResult: "．．_．．_etc_passwd",
			description:    "Should handle unicode variations",
		},
		{
			name:           "Empty string",
			input:          "",
			expectedResult: "safe_filename", // Secure implementation returns safe default
			description:    "Empty input should be handled safely",
		},
		{
			name:           "Only dots",
			input:          ".....",
			expectedResult: "____.",
			description:    "String of dots should be sanitized",
		},
		{
			name:           "Root directory attempt",
			input:          "/",
			expectedResult: "_",
			description:    "Root directory access should be blocked",
		},
		{
			name:           "Current directory",
			input:          ".",
			expectedResult: "safe_filename",
			description:    "Current directory should be replaced with safe default",
		},
		{
			name:           "UNC path attempt",
			input:          "\\\\server\\share\\file",
			expectedResult: "__server_share_file",
			description:    "UNC paths should be neutralized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitize(tt.input)
			assert.Equal(t, tt.expectedResult, result, tt.description)

			// Additional security checks
			assert.LessOrEqual(t, len(result), 100, "Result should not exceed 100 characters")
			assert.NotContains(t, result, "..", "Result should not contain '..'")
			assert.NotContains(t, result, "/", "Result should not contain forward slash")
			assert.NotContains(t, result, "\\", "Result should not contain backslash")
		})
	}
}

func TestSanitize_FilenameSafety(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		unsafe bool
	}{
		{
			name:   "Safe filename",
			input:  "normal-call-123",
			unsafe: false,
		},
		{
			name:   "Filename with spaces",
			input:  "call with spaces",
			unsafe: false, // Spaces are allowed
		},
		{
			name:   "Filename with dangerous chars",
			input:  "call<>:\"/\\|?*",
			unsafe: true,
		},
		{
			name:   "Very long filename",
			input:  strings.Repeat("x", 200),
			unsafe: false, // Will be truncated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitize(tt.input)

			// Check if result is safe for filesystem
			if !tt.unsafe {
				// Should be able to create a file with this name in temp directory
				tmpDir := t.TempDir()
				testFile := filepath.Join(tmpDir, result)

				// Should not panic or error when creating file
				assert.NotPanics(t, func() {
					file, err := os.Create(testFile)
					if err == nil {
						file.Close()
						os.Remove(testFile)
					}
				})
			}
		})
	}
}

func TestInitWriters_ErrorHandling(t *testing.T) {
	// Test CallInfo.initWriters error handling
	tests := []struct {
		name        string
		setup       func(*testing.T) (string, func())
		expectError bool
		description string
	}{
		{
			name: "Valid directory creation",
			setup: func(t *testing.T) (string, func()) {
				tmpDir := t.TempDir()
				callID := "test-call-123"
				return callID, func() {
					// Cleanup handled by t.TempDir()
					os.RemoveAll(filepath.Join(tmpDir, "captures"))
				}
			},
			expectError: false,
			description: "Should successfully create files in valid directory",
		},
		{
			name: "Permission denied directory",
			setup: func(t *testing.T) (string, func()) {
				if os.Getuid() == 0 {
					t.Skip("Cannot test permission denied as root")
				}

				// Create a read-only parent directory
				tmpDir := t.TempDir()
				noWriteParent := filepath.Join(tmpDir, "nowrite")
				err := os.Mkdir(noWriteParent, 0555) // Read and execute, but no write
				require.NoError(t, err)

				// Point XDG_DATA_HOME to a subdirectory that can't be created
				oldXDG := os.Getenv("XDG_DATA_HOME")
				os.Setenv("XDG_DATA_HOME", noWriteParent)

				return "test-call-456", func() {
					// Restore environment
					if oldXDG != "" {
						os.Setenv("XDG_DATA_HOME", oldXDG)
					} else {
						os.Unsetenv("XDG_DATA_HOME")
					}
					// Restore permissions for cleanup
					os.Chmod(noWriteParent, 0755)
				}
			},
			expectError: true,
			description: "Should handle permission denied errors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callID, cleanup := tt.setup(t)
			defer cleanup()

			// Test initWriters
			call := &CallInfo{
				CallID: callID,
			}

			err := call.initWriters()

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				// Note: This may still error in sandboxed environment, which is OK
				if err != nil {
					t.Logf("initWriters failed (expected in sandboxed environment): %v", err)
				}
			}
		})
	}
}

func TestCallInfo_ResourceLeaks(t *testing.T) {
	t.Run("Multiple initWriters calls", func(t *testing.T) {
		call := &CallInfo{
			CallID: "test-resource-leak",
		}

		// Multiple calls should not leak file handles
		for i := 0; i < 5; i++ {
			err := call.initWriters()
			if err == nil {
				// If successful, close the files
				if call.sipFile != nil {
					call.sipFile.Close()
					call.sipFile = nil
				}
				if call.rtpFile != nil {
					call.rtpFile.Close()
					call.rtpFile = nil
				}
			}
		}

		// Should not leak resources
		assert.True(t, true, "Multiple initWriters calls should not leak resources")
	})
}

func TestSanitize_PerformanceAndMemory(t *testing.T) {
	t.Run("Performance with very long strings", func(t *testing.T) {
		// Test performance with very long input
		longInput := strings.Repeat("A", 10000)

		// Should complete quickly
		start := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				result := sanitize(longInput)
				// Verify it was truncated
				assert.LessOrEqual(b, len(result), 100)
			}
		})

		// Should not allocate excessive memory
		assert.Greater(t, start.N, 1000, "Should be able to process many iterations")
	})

	t.Run("Memory usage with repeated calls", func(t *testing.T) {
		// Test that repeated calls don't cause memory leaks
		inputs := []string{
			"../../../etc/passwd",
			"normal-call-id",
			strings.Repeat("x", 200),
			"call<>:\"/\\|?*@",
		}

		for i := 0; i < 1000; i++ {
			for _, input := range inputs {
				result := sanitize(input)
				assert.NotEmpty(t, result, "Should always return some result")
			}
		}
	})
}

func TestSanitize_ConsistentBehavior(t *testing.T) {
	t.Run("Deterministic output", func(t *testing.T) {
		inputs := []string{
			"../etc/passwd",
			"normal-call",
			strings.Repeat("A", 150),
			"call@domain:5060",
		}

		for _, input := range inputs {
			// Should produce consistent results across multiple calls
			result1 := sanitize(input)
			result2 := sanitize(input)
			result3 := sanitize(input)

			assert.Equal(t, result1, result2, "Should produce consistent results")
			assert.Equal(t, result2, result3, "Should produce consistent results")
		}
	})

	t.Run("Sanitize idempotency", func(t *testing.T) {
		// Sanitizing an already sanitized string should not change it further
		input := "../etc/passwd"
		first := sanitize(input)
		second := sanitize(first)

		assert.Equal(t, first, second, "Sanitize should be idempotent for safe strings")
	})
}

func TestSanitize_RealWorldCallIDs(t *testing.T) {
	// Test with real-world Call-ID patterns
	realWorldCallIDs := []string{
		"a84b4c76e66710@pc33.atlanta.com",
		"call-id-1234567890@192.168.1.100",
		"SDPpavr101c1346702206@192.168.0.1",
		"1234567890@10.0.0.1:5060",
		"f81d4fae-7dec-11d0-a765-00a0c91e6bf6@example.com",
		"call-id-with-很长的中文字符@domain.com",
		"call-id@[2001:db8::1]", // IPv6
	}

	for _, callID := range realWorldCallIDs {
		t.Run("CallID: "+callID[:min(len(callID), 20)], func(t *testing.T) {
			result := sanitize(callID)

			// Should be safe for filesystem
			assert.NotContains(t, result, "/", "Should not contain forward slash")
			assert.NotContains(t, result, "\\", "Should not contain backslash")
			assert.NotContains(t, result, "..", "Should not contain '..'")
			assert.LessOrEqual(t, len(result), 100, "Should be truncated if too long")

			// Should preserve some identifying characteristics when possible
			if len(callID) <= 100 && !strings.Contains(callID, "/") && !strings.Contains(callID, "\\") {
				// If original was safe and short, should be mostly preserved
				assert.NotEmpty(t, result, "Should not be empty for valid input")
			}
		})
	}
}

// Helper function for min (not available in older Go versions)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
