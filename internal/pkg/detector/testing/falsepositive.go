package testing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// FalsePositiveResult contains the results of false positive testing
type FalsePositiveResult struct {
	Protocol         string
	TotalTests       int
	FalsePositives   int
	FalsePositiveRate float64
	Duration         time.Duration
}

// FalsePositiveTester tests signatures against random data to measure false positive rates
type FalsePositiveTester struct {
	detector  *detector.Detector
	generator *RandomPacketGenerator
	mu        sync.Mutex
	results   map[string]*FalsePositiveResult
}

// NewFalsePositiveTester creates a new false positive tester
func NewFalsePositiveTester(det *detector.Detector) *FalsePositiveTester {
	return &FalsePositiveTester{
		detector:  det,
		generator: NewRandomPacketGenerator(),
		results:   make(map[string]*FalsePositiveResult),
	}
}

// TestSignature tests a single signature against random data
func (t *FalsePositiveTester) TestSignature(sig signatures.Signature, numTests int) *FalsePositiveResult {
	start := time.Now()

	result := &FalsePositiveResult{
		Protocol:   sig.Name(),
		TotalTests: numTests,
	}

	for i := 0; i < numTests; i++ {
		// Generate random payload
		payload := t.generator.GenerateRandomPayload(1500)

		// Create detection context
		ctx := t.createDetectionContext(payload)

		// Test detection
		detResult := sig.Detect(ctx)

		// Check for false positive
		if detResult != nil && detResult.Confidence > 0 {
			result.FalsePositives++
		}
	}

	result.Duration = time.Since(start)
	result.FalsePositiveRate = float64(result.FalsePositives) / float64(result.TotalTests) * 100

	t.mu.Lock()
	t.results[sig.Name()] = result
	t.mu.Unlock()

	return result
}

// TestSignatureWithPatterns tests a signature against common patterns
func (t *FalsePositiveTester) TestSignatureWithPatterns(sig signatures.Signature) *FalsePositiveResult {
	start := time.Now()

	patterns := t.generator.GenerateCommonPatterns()
	edgeCases := t.generator.GenerateEdgeCases()
	variableLengths := t.generator.GenerateVariableLengthPayloads()

	allPayloads := append(patterns, edgeCases...)
	allPayloads = append(allPayloads, variableLengths...)

	result := &FalsePositiveResult{
		Protocol:   sig.Name(),
		TotalTests: len(allPayloads),
	}

	for _, payload := range allPayloads {
		ctx := t.createDetectionContext(payload)
		detResult := sig.Detect(ctx)

		if detResult != nil && detResult.Confidence > 0 {
			result.FalsePositives++
		}
	}

	result.Duration = time.Since(start)
	result.FalsePositiveRate = float64(result.FalsePositives) / float64(result.TotalTests) * 100

	return result
}

// TestAllSignatures tests all registered signatures
func (t *FalsePositiveTester) TestAllSignatures(numTestsPerSignature int) map[string]*FalsePositiveResult {
	sigs := t.detector.GetSignatures()
	results := make(map[string]*FalsePositiveResult)

	for _, sig := range sigs {
		result := t.TestSignature(sig, numTestsPerSignature)
		results[sig.Name()] = result
	}

	return results
}

// TestAllSignaturesParallel tests all signatures in parallel
func (t *FalsePositiveTester) TestAllSignaturesParallel(numTestsPerSignature int) map[string]*FalsePositiveResult {
	sigs := t.detector.GetSignatures()

	var wg sync.WaitGroup
	resultsChan := make(chan *FalsePositiveResult, len(sigs))

	for _, sig := range sigs {
		wg.Add(1)
		go func(s signatures.Signature) {
			defer wg.Done()
			result := t.TestSignature(s, numTestsPerSignature)
			resultsChan <- result
		}(sig)
	}

	wg.Wait()
	close(resultsChan)

	results := make(map[string]*FalsePositiveResult)
	for result := range resultsChan {
		results[result.Protocol] = result
	}

	return results
}

// GetResults returns the accumulated test results
func (t *FalsePositiveTester) GetResults() map[string]*FalsePositiveResult {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Return a copy to avoid concurrent access issues
	resultsCopy := make(map[string]*FalsePositiveResult)
	for k, v := range t.results {
		resultsCopy[k] = v
	}
	return resultsCopy
}

// PrintResults prints the test results in a formatted table
func (t *FalsePositiveTester) PrintResults() {
	results := t.GetResults()

	fmt.Println("\n=== False Positive Test Results ===")
	fmt.Printf("%-20s %-15s %-15s %-15s %-15s\n", "Protocol", "Total Tests", "False Positives", "FP Rate (%)", "Duration")
	fmt.Println("-------------------------------------------------------------------------------------------")

	for protocol, result := range results {
		fmt.Printf("%-20s %-15d %-15d %-15.4f %-15s\n",
			protocol,
			result.TotalTests,
			result.FalsePositives,
			result.FalsePositiveRate,
			result.Duration,
		)
	}
}

// ValidateThresholds checks if false positive rates are within acceptable thresholds
func (t *FalsePositiveTester) ValidateThresholds(maxRate float64) []string {
	results := t.GetResults()
	violations := []string{}

	for protocol, result := range results {
		if result.FalsePositiveRate > maxRate {
			violations = append(violations, fmt.Sprintf(
				"%s: %.4f%% (threshold: %.4f%%)",
				protocol,
				result.FalsePositiveRate,
				maxRate,
			))
		}
	}

	return violations
}

// createDetectionContext creates a detection context from a payload
func (t *FalsePositiveTester) createDetectionContext(payload []byte) *signatures.DetectionContext {
	// Create a minimal packet - use UDP as the base layer type
	packet := gopacket.NewPacket(
		payload,
		layers.LayerTypeUDP,
		gopacket.NoCopy,
	)

	ctx := &signatures.DetectionContext{
		Packet:    packet,
		Payload:   payload,
		Transport: "UDP",
		SrcIP:     "192.0.2.1",
		DstIP:     "192.0.2.2",
		SrcPort:   12345,
		DstPort:   54321,
		FlowID:    "test-flow",
		Context:   context.Background(),
	}

	return ctx
}

// GenerateReport creates a detailed report of false positive testing
func (t *FalsePositiveTester) GenerateReport() string {
	results := t.GetResults()

	report := "# False Positive Testing Report\n\n"
	report += fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339))

	report += "## Summary\n\n"

	totalTests := 0
	totalFP := 0

	for _, result := range results {
		totalTests += result.TotalTests
		totalFP += result.FalsePositives
	}

	overallRate := 0.0
	if totalTests > 0 {
		overallRate = float64(totalFP) / float64(totalTests) * 100
	}

	report += fmt.Sprintf("- Total Protocols Tested: %d\n", len(results))
	report += fmt.Sprintf("- Total Tests Run: %d\n", totalTests)
	report += fmt.Sprintf("- Total False Positives: %d\n", totalFP)
	report += fmt.Sprintf("- Overall False Positive Rate: %.4f%%\n\n", overallRate)

	report += "## Per-Protocol Results\n\n"
	report += "| Protocol | Total Tests | False Positives | FP Rate (%) | Duration |\n"
	report += "|----------|-------------|-----------------|-------------|----------|\n"

	for protocol, result := range results {
		report += fmt.Sprintf("| %s | %d | %d | %.4f | %s |\n",
			protocol,
			result.TotalTests,
			result.FalsePositives,
			result.FalsePositiveRate,
			result.Duration,
		)
	}

	return report
}
