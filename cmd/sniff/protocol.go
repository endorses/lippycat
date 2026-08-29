//go:build cli || all

package sniff

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
)

// sniffRuntimeAdapter binds flag-derived operations to the single shared
// protocol definition. It is topology wiring, not another protocol spec.
type sniffRuntimeAdapter struct {
	protocol   protocolcatalog.Spec
	BuildBPF   func(baseFilter string) (string, error)
	StartLive  func(interfaces, filter string)
	StartFiles func(files []string, filter string)
}

func (s sniffRuntimeAdapter) validate() error {
	if s.protocol.Name == "" {
		return fmt.Errorf("protocol name is required")
	}
	if s.BuildBPF == nil {
		return fmt.Errorf("%s protocol BPF builder is required", s.protocol.Name)
	}
	if s.StartLive == nil {
		return fmt.Errorf("%s protocol live ingress is required", s.protocol.Name)
	}
	if s.StartFiles == nil {
		return fmt.Errorf("%s protocol file ingress is required", s.protocol.Name)
	}
	return nil
}

func runProtocol(cmd *cobra.Command, args []string, spec sniffRuntimeAdapter) {
	if err := spec.validate(); err != nil {
		logger.Error("Invalid sniff protocol specification", "protocol", spec.protocol.Name, "error", err)
		return
	}
	effectiveFilter, err := spec.BuildBPF(filter)
	if err != nil {
		logger.Error("Invalid protocol filter configuration", "protocol", spec.protocol.Name, "error", err)
		return
	}

	files := collectReadFiles(readFile, args)
	withStructuredLogs(func() {
		if len(files) == 0 {
			spec.StartLive(interfaces, effectiveFilter)
			return
		}
		spec.StartFiles(files, effectiveFilter)
	})
}
