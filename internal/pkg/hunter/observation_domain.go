//go:build hunter || all

package hunter

import "github.com/endorses/lippycat/internal/pkg/pipeline"

func (h *Hunter) captureObservationDomain(iface string) (uint32, bool) {
	if h.config.MediaAdmission != nil {
		return uint32(h.config.MediaAdmission.Config.DomainForInterface(iface)), true
	}
	if domain, ok := h.config.VoIPInterfaceDomains[iface]; ok {
		return uint32(domain), true
	}
	return 0, h.config.VoIPMode
}

func (h *Hunter) captureSelectionAllowed(envelope *pipeline.PacketEnvelope) bool {
	if envelope != nil && len(envelope.CaptureSelectionProof) > 0 {
		return h.filterManager != nil && h.filterManager.CaptureSelectionProofAllowed(envelope)
	}
	return envelope != nil && h.filterManager != nil && h.filterManager.CaptureSelectionAllowed(envelope.MatchedFilterIDs)
}
