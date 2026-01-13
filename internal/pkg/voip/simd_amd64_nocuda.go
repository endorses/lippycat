//go:build amd64 && !cuda

package voip

// Assembly function declarations - implemented in simd_amd64.s
// These are only available when NOT building with CUDA (CGo + asm conflict)

// bytesEqualAVX2 is implemented in assembly
func bytesEqualAVX2(a, b []byte) bool

// bytesEqualSSE2 is implemented in assembly
func bytesEqualSSE2(a, b []byte) bool

// indexByteAVX2 is implemented in assembly
func indexByteAVX2(data []byte, c byte) int

// indexByteSSE2 is implemented in assembly
func indexByteSSE2(data []byte, c byte) int

// sipMethodMatchSSE42Asm uses SSE4.2 optimized matching for SIP method prefix detection.
// Uses first-byte dispatch and 64-bit word comparison for fast matching.
// Returns the method index (1-6) or 0 if no match, or -1 for SIP/2.0 response.
// Methods: 1=INVITE, 2=REGISTER, 3=BYE, 4=CANCEL, 5=ACK, 6=OPTIONS
func sipMethodMatchSSE42Asm(line []byte) int

// init overrides the dispatch function on amd64 to use assembly implementation
func init() {
	sipMethodMatchDispatchFn = sipMethodMatchSSE42Asm
}
