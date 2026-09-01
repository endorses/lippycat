package enrichment

import "testing"

func TestBuildInfoStringAcceptsNilMetadata(t *testing.T) {
	protocols := []string{"SSH", "ICMP", "DNS", "gRPC", "HTTP2", "SIP", "RTP", "unknown"}
	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			_ = buildInfoString(protocol, nil)
		})
	}
}
