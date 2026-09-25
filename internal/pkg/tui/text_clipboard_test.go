//go:build tui || all

package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyTextClipboardFallbacks(t *testing.T) {
	nativeErr, terminalErr := errors.New("native unavailable"), errors.New("terminal unavailable")
	for _, tc := range []struct {
		name          string
		terminalFirst bool
		nativeErr     error
		terminalErr   error
		wantCalls     []string
		wantErr       bool
	}{
		{name: "local native", wantCalls: []string{"native"}},
		{name: "local terminal fallback", nativeErr: nativeErr, wantCalls: []string{"native", "terminal"}},
		{name: "remote terminal", terminalFirst: true, wantCalls: []string{"terminal"}},
		{name: "remote native fallback", terminalFirst: true, terminalErr: terminalErr, wantCalls: []string{"terminal", "native"}},
		{name: "both fail", nativeErr: nativeErr, terminalErr: terminalErr, wantCalls: []string{"native", "terminal"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			backend := func(name string, result error) func(string) error {
				return func(text string) error {
					require.Equal(t, "INVITE 日本語\nsecond line", text)
					calls = append(calls, name)
					return result
				}
			}
			err := copyTextWithBackends("INVITE 日本語\nsecond line", tc.terminalFirst, backend("native", tc.nativeErr), backend("terminal", tc.terminalErr))
			require.Equal(t, tc.wantCalls, calls)
			if tc.wantErr {
				require.ErrorIs(t, err, nativeErr)
				require.ErrorIs(t, err, terminalErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
	// Empty selections must not clear either clipboard.
	require.NoError(t, copyTextWithBackends("", false, nil, nil))
}

func TestClipboardPrefersUserTerminalInRemoteSessions(t *testing.T) {
	for _, name := range []string{"SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT", "VSCODE_IPC_HOOK_CLI", "WSL_DISTRO_NAME", "WSL_INTEROP"} {
		t.Run(name, func(t *testing.T) {
			require.True(t, preferTerminalClipboard(clipboardTestEnv(map[string]string{name: "present"})))
		})
	}
	require.False(t, preferTerminalClipboard(clipboardTestEnv(map[string]string{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"})))
}

func TestNativeClipboardSessionBackends(t *testing.T) {
	for _, tc := range []struct {
		name string
		goos string
		env  map[string]string
		want []string
	}{
		{name: "wayland and X11 fallback", goos: "linux", env: map[string]string{"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, want: []string{"wl-copy", "xclip", "xsel"}},
		{name: "headless", goos: "linux"},
		{name: "macOS", goos: "darwin", want: []string{"pbcopy"}},
		{name: "Windows", goos: "windows", want: []string{"powershell.exe"}},
		{name: "WSL", goos: "linux", env: map[string]string{"WSL_INTEROP": "/run/WSL/1_interop"}, want: []string{"powershell.exe"}},
		{name: "Termux", goos: "android", env: map[string]string{"PREFIX": "/data/data/com.termux/files/usr"}, want: []string{"termux-clipboard-set"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var names []string
			for _, command := range nativeClipboardCommands(tc.goos, clipboardTestEnv(tc.env)) {
				names = append(names, command.name)
			}
			require.Equal(t, tc.want, names)
		})
	}
}

func TestNativeClipboardFailureAndCancellation(t *testing.T) {
	commands := []clipboardCommand{{name: "first"}, {name: "second"}}
	var calls []string
	require.NoError(t, runClipboardCommands(context.Background(), commands, "text", func(_ context.Context, command clipboardCommand, text string) error {
		require.Equal(t, "text", text)
		calls = append(calls, command.name)
		if command.name == "first" {
			return errors.New("not available")
		}
		return nil
	}))
	require.Equal(t, []string{"first", "second"}, calls)

	ctx, cancel := context.WithCancel(context.Background())
	calls = nil
	err := runClipboardCommands(ctx, commands, "text", func(ctx context.Context, command clipboardCommand, _ string) error {
		calls = append(calls, command.name)
		cancel()
		return ctx.Err()
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []string{"first"}, calls, "do not launch another helper after the timeout/cancellation")
	require.Error(t, runClipboardCommands(context.Background(), nil, "text", nil))
}

func TestClipboardOSC52Sequences(t *testing.T) {
	plain := "\x1b]52;c;aGVsbG8=\x07"
	require.Equal(t, plain, clipboardSequence("hello", clipboardTestEnv(nil)))
	tmux := clipboardSequence("hello", clipboardTestEnv(map[string]string{"TMUX": "/tmp/tmux/session", "TERM": "screen-256color"}))
	require.Equal(t, "\x1bPtmux;\x1b"+plain+"\x1b\\", tmux)
	screen := clipboardSequence("hello", clipboardTestEnv(map[string]string{"TERM": "screen-256color"}))
	require.Equal(t, "\x1bP"+plain+"\x1b\\", screen)
	// Selected escape sequences are data, never executable terminal controls.
	encoded := clipboardSequence("text\x1b[31m\n日本語", clipboardTestEnv(nil))
	require.False(t, strings.Contains(encoded, "\x1b[31m"))
}

func clipboardTestEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}
