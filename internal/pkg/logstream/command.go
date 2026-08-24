package logstream

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandHook returns a post-rotate hook that runs command through /bin/sh.
// Each %log% placeholder is replaced with a shell-quoted rotated file path.
// The command is operator configuration; the generated path is always escaped.
func CommandHook(command string, timeout time.Duration) PostRotateFunc {
	return func(ctx context.Context, path string) error {
		if strings.TrimSpace(command) == "" {
			return nil
		}
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		commandCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		resolved := strings.ReplaceAll(command, "%log%", shellQuote(path))
		output, err := exec.CommandContext(commandCtx, "/bin/sh", "-c", resolved).CombinedOutput()
		if err != nil {
			return fmt.Errorf("execute post-rotate command: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
