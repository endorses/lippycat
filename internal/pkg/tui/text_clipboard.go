//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/aymanbagabas/go-osc52/v2"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const clipboardCommandTimeout = 2 * time.Second

type textCopiedMsg struct{ err error }

// copyTextCmd keeps clipboard helpers off the UI loop. In remote sessions the
// terminal owns the user's clipboard; a native helper would target the host.
func copyTextCmd(text string) tea.Cmd {
	return func() tea.Msg {
		return textCopiedMsg{err: copyTextWithBackends(text, preferTerminalClipboard(os.Getenv), writeNativeClipboard, writeTerminalClipboard)}
	}
}

func copyTextWithBackends(text string, terminalFirst bool, native, terminal func(string) error) error {
	if text == "" {
		return nil
	}
	first, second := native, terminal
	if terminalFirst {
		first, second = terminal, native
	}
	firstErr := first(text)
	if firstErr == nil {
		return nil
	}
	if secondErr := second(text); secondErr != nil {
		return fmt.Errorf("copy selected text: %w", errors.Join(firstErr, secondErr))
	}
	return nil
}

func preferTerminalClipboard(getenv func(string) string) bool {
	for _, name := range []string{"SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT", "VSCODE_IPC_HOOK_CLI", "WSL_DISTRO_NAME", "WSL_INTEROP"} {
		if getenv(name) != "" {
			return true
		}
	}
	return false
}

type clipboardCommand struct {
	name string
	args []string
}

func nativeClipboardCommands(goos string, getenv func(string) string) []clipboardCommand {
	// Read text from stdin, never interpolate selection text into a command.
	powershell := clipboardCommand{"powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new(); Set-Clipboard -Value ([Console]::In.ReadToEnd())"}}
	switch goos {
	case "darwin":
		return []clipboardCommand{{name: "pbcopy"}}
	case "windows":
		return []clipboardCommand{powershell}
	default:
		var commands []clipboardCommand
		if getenv("WAYLAND_DISPLAY") != "" {
			commands = append(commands, clipboardCommand{name: "wl-copy"})
		}
		if getenv("DISPLAY") != "" {
			commands = append(commands,
				clipboardCommand{"xclip", []string{"-in", "-selection", "clipboard"}},
				clipboardCommand{"xsel", []string{"--input", "--clipboard"}},
			)
		}
		if getenv("WSL_DISTRO_NAME") != "" || getenv("WSL_INTEROP") != "" {
			commands = append(commands, powershell)
		}
		if strings.Contains(getenv("PREFIX"), "com.termux") {
			commands = append(commands, clipboardCommand{name: "termux-clipboard-set"})
		}
		return commands
	}
}

func writeNativeClipboard(text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), clipboardCommandTimeout)
	defer cancel()
	return runClipboardCommands(ctx, nativeClipboardCommands(runtime.GOOS, os.Getenv), text, runClipboardCommand)
}

func runClipboardCommands(ctx context.Context, commands []clipboardCommand, text string, run func(context.Context, clipboardCommand, string) error) error {
	var failures []error
	for _, command := range commands {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		if err := run(ctx, command, text); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", command.name, err))
			continue
		}
		return nil
	}
	if len(failures) == 0 {
		return errors.New("no native clipboard available in this session")
	}
	return fmt.Errorf("native clipboard: %w", errors.Join(failures...))
}

func runClipboardCommand(ctx context.Context, command clipboardCommand, text string) error {
	cmd := exec.CommandContext(ctx, command.name, command.args...)
	cmd.Stdin = strings.NewReader(text)
	// A helper that forks must not leave the stdin copier waiting indefinitely.
	cmd.WaitDelay = 100 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return errors.Join(err, ctx.Err())
	}
	return nil
}

func clipboardSequence(text string, getenv func(string) string) string {
	sequence := osc52.New(text)
	if getenv("TMUX") != "" {
		sequence = sequence.Tmux()
	} else if strings.HasPrefix(getenv("TERM"), "screen") {
		sequence = sequence.Screen()
	}
	return sequence.String()
}

func writeTerminalClipboard(text string) error {
	sequence := clipboardSequence(text, os.Getenv)
	// Use the same file as Bubble Tea when stdout is a terminal. Writing the
	// complete sequence in one call prevents interleaving with render writes.
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if _, err := io.WriteString(os.Stdout, sequence); err != nil {
			return fmt.Errorf("write terminal clipboard: %w", err)
		}
		return nil
	}
	// Keep control sequences out of redirected stdout, while still supporting
	// a controlling terminal (including an SSH pseudo-terminal).
	path := "/dev/tty"
	if runtime.GOOS == "windows" {
		path = "CONOUT$"
	}
	terminal, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open terminal clipboard: %w", err)
	}
	_, writeErr := io.WriteString(terminal, sequence)
	closeErr := terminal.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("write terminal clipboard: %w", err)
	}
	return nil
}
