//go:build !unix && (processor || tap || all)

package processor

import "os/exec"

// CommandContext cancels the direct shell process. WaitDelay bounds inherited
// output-pipe waits, but descendant termination is unavailable on this platform.
func configureNoticeCommandProcess(_ *exec.Cmd) {}
