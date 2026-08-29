//go:build cli || all

package sniff

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/cobra"
)

// ProtocolSpec describes the protocol-specific parts of a sniff runtime. Cobra
// and Viper remain in this composition-root package; protocol packages only
// provide filtering, analysis, and capture implementations.
type ProtocolSpec struct {
	Name       string
	BuildBPF   func(baseFilter string) (string, error)
	StartLive  func(interfaces, filter string)
	StartFiles func(files []string, filter string)
}

func (s ProtocolSpec) validate() error {
	if s.Name == "" {
		return fmt.Errorf("protocol name is required")
	}
	if s.BuildBPF == nil {
		return fmt.Errorf("%s protocol BPF builder is required", s.Name)
	}
	if s.StartLive == nil {
		return fmt.Errorf("%s protocol live ingress is required", s.Name)
	}
	if s.StartFiles == nil {
		return fmt.Errorf("%s protocol file ingress is required", s.Name)
	}
	return nil
}

func runProtocol(cmd *cobra.Command, args []string, spec ProtocolSpec) {
	if err := spec.validate(); err != nil {
		logger.Error("Invalid sniff protocol specification", "protocol", spec.Name, "error", err)
		return
	}
	effectiveFilter, err := spec.BuildBPF(filter)
	if err != nil {
		logger.Error("Invalid protocol filter configuration", "protocol", spec.Name, "error", err)
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
