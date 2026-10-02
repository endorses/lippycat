//go:build processor || tap || all

package processor

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/admissiontelemetry"
)

func (p *Processor) populateAdmissionStats(stats *management.ProcessorStats) {
	if p.packetSource != nil {
		stats.RtpEbpf = admissiontelemetry.ToProtoPointer(p.packetSource.Stats().MediaAdmission)
	}
}
