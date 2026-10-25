//go:build unix && (processor || tap || all)

package processor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNoticeCommandCancellationStopsShellDescendant(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	child := "printf '%s' $$ > " + shellEscape(pidFile) + "; exec sleep 30"
	executor := NewCommandExecutor(&CommandExecutorConfig{TunnelingCommand: "sh -c " + shellEscape(child) + " & wait", Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- executor.ExecuteTunnelingCommandContext(ctx, TunnelingMetadata{}, 64) }()
	var pid string
	require.Eventually(t, func() bool {
		bytes, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid = string(bytes)
		number, err := strconv.Atoi(pid)
		return err == nil && number > 0
	}, 5*time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("command cancellation did not join its execution")
	}
	require.Eventually(t, func() bool {
		query, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		state, err := exec.CommandContext(query, "ps", "-o", "stat=", "-p", pid).Output()
		if err != nil {
			if exited, ok := err.(*exec.ExitError); ok && exited.ExitCode() == 1 {
				return true // No process remains.
			}
			return false
		}
		// Minimal container init processes may retain adopted zombies. Such a
		// descendant has terminated and cannot perform later external effects.
		return strings.HasPrefix(strings.TrimSpace(string(state)), "Z")
	}, 5*time.Second, time.Millisecond, "notice cancellation left a live shell descendant")
}
