//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
	"google.golang.org/protobuf/proto"
)

// UpdateMediaAdmission keeps diagnostics only for nodes already present in the
// view. The private copy cannot be mutated by a remote callback after delivery.
func (n *NodesView) UpdateMediaAdmission(address string, status *management.MediaAdmissionStatus) {
	present := false
	for _, processor := range n.processors {
		if processor.Address == address {
			present = true
			break
		}
	}
	if !present {
		return
	}
	if n.mediaAdmission == nil {
		n.mediaAdmission = make(map[string]*management.MediaAdmissionStatus)
	}
	if status == nil {
		delete(n.mediaAdmission, address)
	} else {
		n.mediaAdmission[address] = proto.Clone(status).(*management.MediaAdmissionStatus)
	}
	n.updateViewportContent()
}

func (n *NodesView) renderMediaAdmission() string {
	var status *management.MediaAdmissionStatus
	if hunter := n.GetSelectedHunter(); hunter != nil {
		status = hunter.MediaAdmission
	} else {
		status = n.mediaAdmission[n.selectedProcessorAddr]
	}
	if status == nil || !status.Enabled {
		return ""
	}
	var text strings.Builder
	for _, scope := range status.Scopes {
		if scope == nil {
			continue
		}
		u := scope.GetUncertainty()
		lines := []string{
			fmt.Sprintf("RTP admission domain %d: %s; unknown calls %d; degraded %s", scope.Domain, scope.State, u.GetUnknownCalls(), time.Duration(scope.DegradedDurationNs).Round(time.Millisecond)),
			fmt.Sprintf("Reasons (overlap): headers %d, PRACK %d, partial SDP %d, delayed offer %d, forks %d, evidence loss %d", u.GetConflictingHeaders(), u.GetFaultyPrack(), u.GetPartialSdp(), u.GetDelayedOffer(), u.GetForkAmbiguity(), u.GetEvidenceLoss()),
			fmt.Sprintf("Duplicate header groups: identical %d, conflicting %d", u.GetIdenticalDuplicates(), u.GetConflictingDuplicates()),
		}
		for _, line := range lines {
			text.WriteString(nodesview.TruncateString(line, n.width))
			text.WriteByte('\n')
		}
	}
	return text.String()
}
