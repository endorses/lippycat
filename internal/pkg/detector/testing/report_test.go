package testing

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

// TestFalsePositiveReport generates a comprehensive false positive report
func TestFalsePositiveReport(t *testing.T) {
	det := detector.NewDetector()

	// Register all signatures
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())
	det.RegisterSignature(application.NewTLSSignature())
	det.RegisterSignature(application.NewSSHSignature())
	det.RegisterSignature(application.NewWebSocketSignature())
	det.RegisterSignature(application.NewGRPCSignature())
	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(voip.NewRTPSignature())
	det.RegisterSignature(vpn.NewWireGuardSignature())
	det.RegisterSignature(vpn.NewOpenVPNSignature())
	det.RegisterSignature(vpn.NewL2TPSignature())
	det.RegisterSignature(vpn.NewIKEv2Signature())
	det.RegisterSignature(vpn.NewPPTPSignature())

	tester := NewFalsePositiveTester(det)
	results := tester.TestAllSignatures(10000)

	fmt.Println("\n=== FALSE POSITIVE RATE REPORT (10,000 random packets each) ===")

	zeroFP := []string{}
	nonZeroFP := []string{}

	for proto, result := range results {
		if result.FalsePositiveRate > 0 {
			nonZeroFP = append(nonZeroFP, fmt.Sprintf("⚠️  %s: %.4f%% (%d/%d)",
				proto, result.FalsePositiveRate, result.FalsePositives, result.TotalTests))
		} else {
			zeroFP = append(zeroFP, fmt.Sprintf("✅ %s: 0.0000%%", proto))
		}
	}

	fmt.Println("Protocols with 0% false positive rate:")
	for _, msg := range zeroFP {
		fmt.Println(msg)
	}

	fmt.Println("\nProtocols with non-zero false positive rate:")
	if len(nonZeroFP) == 0 {
		fmt.Println("None! All protocols have 0% false positive rate.")
	} else {
		for _, msg := range nonZeroFP {
			fmt.Println(msg)
		}
	}
	fmt.Println()
}
