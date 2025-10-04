package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

func TestRandomPacketGenerator(t *testing.T) {
	gen := NewRandomPacketGenerator()

	t.Run("GenerateRandomPayload", func(t *testing.T) {
		payload := gen.GenerateRandomPayload(1500)
		assert.Len(t, payload, 1500)
	})

	t.Run("GeneratePrintablePayload", func(t *testing.T) {
		payload := gen.GeneratePrintablePayload(100)
		assert.Len(t, payload, 100)

		// All bytes should be printable ASCII
		for _, b := range payload {
			assert.GreaterOrEqual(t, b, byte(32))
			assert.LessOrEqual(t, b, byte(126))
		}
	})

	t.Run("GenerateWithPattern", func(t *testing.T) {
		pattern := []byte{0xAA, 0x55}
		payload := gen.GenerateWithPattern(10, pattern)
		assert.Len(t, payload, 10)

		for i := 0; i < 10; i++ {
			assert.Equal(t, pattern[i%2], payload[i])
		}
	})

	t.Run("GenerateCommonPatterns", func(t *testing.T) {
		patterns := gen.GenerateCommonPatterns()
		assert.NotEmpty(t, patterns)
	})

	t.Run("GenerateVariableLengthPayloads", func(t *testing.T) {
		payloads := gen.GenerateVariableLengthPayloads()
		assert.NotEmpty(t, payloads)
	})

	t.Run("GenerateEdgeCases", func(t *testing.T) {
		edgeCases := gen.GenerateEdgeCases()
		assert.NotEmpty(t, edgeCases)
	})
}

func TestFalsePositiveTester_SingleSignature(t *testing.T) {
	det := detector.NewDetector()

	// Register a signature for testing
	sipSig := voip.NewSIPSignature()
	det.RegisterSignature(sipSig)

	tester := NewFalsePositiveTester(det)

	t.Run("TestSignature", func(t *testing.T) {
		result := tester.TestSignature(sipSig, 1000)

		require.NotNil(t, result)
		assert.Equal(t, sipSig.Name(), result.Protocol)
		assert.Equal(t, 1000, result.TotalTests)
		assert.GreaterOrEqual(t, result.FalsePositives, 0)
		assert.LessOrEqual(t, result.FalsePositives, 1000)

		// False positive rate should be very low for random data
		assert.Less(t, result.FalsePositiveRate, 1.0, "SIP signature should have <1% false positive rate")
	})

	t.Run("TestSignatureWithPatterns", func(t *testing.T) {
		result := tester.TestSignatureWithPatterns(sipSig)

		require.NotNil(t, result)
		assert.Equal(t, sipSig.Name(), result.Protocol)
		assert.Greater(t, result.TotalTests, 0)
	})
}

func TestFalsePositiveTester_MultipleSignatures(t *testing.T) {
	det := detector.NewDetector()

	// Register multiple signatures
	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(voip.NewRTPSignature())
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())
	det.RegisterSignature(application.NewTLSSignature())

	tester := NewFalsePositiveTester(det)

	t.Run("TestAllSignatures", func(t *testing.T) {
		results := tester.TestAllSignatures(500)

		assert.Len(t, results, 5)

		for protocol, result := range results {
			assert.Equal(t, 500, result.TotalTests, "Protocol: %s", protocol)
			assert.GreaterOrEqual(t, result.FalsePositives, 0)
			assert.LessOrEqual(t, result.FalsePositives, 500)
		}
	})

	t.Run("TestAllSignaturesParallel", func(t *testing.T) {
		results := tester.TestAllSignaturesParallel(500)

		assert.Len(t, results, 5)

		for protocol, result := range results {
			assert.Equal(t, 500, result.TotalTests, "Protocol: %s", protocol)
		}
	})
}

func TestFalsePositiveTester_VPNSignatures(t *testing.T) {
	det := detector.NewDetector()

	// Register VPN signatures (these are known to be strict)
	det.RegisterSignature(vpn.NewOpenVPNSignature())
	det.RegisterSignature(vpn.NewWireGuardSignature())
	det.RegisterSignature(vpn.NewL2TPSignature())
	det.RegisterSignature(vpn.NewIKEv2Signature())

	tester := NewFalsePositiveTester(det)

	results := tester.TestAllSignatures(1000)

	// VPN signatures should have very low false positive rates
	for protocol, result := range results {
		assert.Less(t, result.FalsePositiveRate, 0.5,
			"VPN protocol %s should have <0.5%% false positive rate, got %.4f%%",
			protocol, result.FalsePositiveRate)
	}
}

func TestFalsePositiveTester_ValidateThresholds(t *testing.T) {
	det := detector.NewDetector()

	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(application.NewDNSSignature())

	tester := NewFalsePositiveTester(det)
	_ = tester.TestAllSignatures(1000)

	t.Run("NoViolations", func(t *testing.T) {
		violations := tester.ValidateThresholds(5.0) // 5% threshold
		assert.Empty(t, violations, "Should have no violations with 5%% threshold")
	})

	t.Run("StrictThreshold", func(t *testing.T) {
		violations := tester.ValidateThresholds(0.0) // 0% threshold - very strict
		// Our detectors are good, so they might not violate even this strict threshold
		// This test just verifies the threshold validation works
		t.Logf("Violations with 0%% threshold: %v", violations)
	})
}

func TestFalsePositiveTester_Report(t *testing.T) {
	det := detector.NewDetector()

	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(application.NewDNSSignature())

	tester := NewFalsePositiveTester(det)
	_ = tester.TestAllSignatures(100)

	report := tester.GenerateReport()

	assert.Contains(t, report, "False Positive Testing Report")
	assert.Contains(t, report, "Summary")
	assert.Contains(t, report, "Per-Protocol Results")
	assert.Contains(t, report, "SIP")
	assert.Contains(t, report, "DNS")
}

func TestFalsePositiveTester_GetResults(t *testing.T) {
	det := detector.NewDetector()
	sipSig := voip.NewSIPSignature()
	det.RegisterSignature(sipSig)

	tester := NewFalsePositiveTester(det)
	_ = tester.TestSignature(sipSig, 100)

	results := tester.GetResults()
	assert.Len(t, results, 1)
	assert.Contains(t, results, sipSig.Name())
}

// Benchmark tests
func BenchmarkFalsePositiveTesting(b *testing.B) {
	det := detector.NewDetector()
	det.RegisterSignature(voip.NewSIPSignature())

	tester := NewFalsePositiveTester(det)
	sig := voip.NewSIPSignature()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tester.TestSignature(sig, 100)
	}
}

func BenchmarkRandomPayloadGeneration(b *testing.B) {
	gen := NewRandomPacketGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gen.GenerateRandomPayload(1500)
	}
}
