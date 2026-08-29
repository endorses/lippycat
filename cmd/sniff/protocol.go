//go:build cli || all

package sniff

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
)

// sniffRuntimeHooks binds flag-derived operations to a catalog protocol. It is
// topology wiring, not a second protocol specification.
type sniffRuntimeHooks struct {
	BuildBPF   func(baseFilter string) (string, error)
	StartLive  func(interfaces, filter string)
	StartFiles func(files []string, filter string)
}

func (s sniffRuntimeHooks) validate(protocol protocolcatalog.Spec) error {
	if protocol.Name == "" || protocol.Analyzer == "" {
		return fmt.Errorf("protocol name is required")
	}
	if s.BuildBPF == nil {
		return fmt.Errorf("%s protocol BPF builder is required", protocol.Name)
	}
	if s.StartLive == nil {
		return fmt.Errorf("%s protocol live ingress is required", protocol.Name)
	}
	if s.StartFiles == nil {
		return fmt.Errorf("%s protocol file ingress is required", protocol.Name)
	}
	return nil
}

func runProtocol(cmd *cobra.Command, args []string, protocol protocolcatalog.Spec, hooks sniffRuntimeHooks) {
	if err := hooks.validate(protocol); err != nil {
		logger.Error("Invalid sniff protocol specification", "protocol", protocol.Name, "error", err)
		return
	}
	effectiveFilter, err := hooks.BuildBPF(filter)
	if err != nil {
		logger.Error("Invalid protocol filter configuration", "protocol", protocol.Name, "error", err)
		return
	}

	files := collectReadFiles(readFile, args)
	withStructuredLogs(func() {
		if len(files) == 0 {
			hooks.StartLive(interfaces, effectiveFilter)
			return
		}
		hooks.StartFiles(files, effectiveFilter)
	})
}
