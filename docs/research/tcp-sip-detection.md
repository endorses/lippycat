# TCP SIP Detection: Analysis and Improvement Options

**Date:** 2026-01-24
**Status:** Complete - Full TCP Reassembly Implemented
**Related Issues:** TCP SIP packets incorrectly categorized, RTP-only calls in TUI

## Executive Summary

TCP SIP messages can be incorrectly categorized as "TCP" instead of "SIP" when individual TCP segments don't start with a SIP method. This affects:
- **Hunter filtering** (`lc hunt voip`): VoIP filters may not be applied to TCP SIP
- **TUI display** (`lc watch live`): Calls may appear as "RTP-only" when SIP signaling is missed

Local capture modes (`lc sniff voip`, `lc tap voip`) are **not affected** because they use TCP reassembly.

## Problem Description

### The Detection Gap

The protocol detector (`internal/pkg/detector/signatures/voip/sip.go`) identifies SIP by checking if the packet payload **starts with** a SIP method:

```go
// SIP detection checks if payload starts with method
if simd.BytesEqual(ctx.Payload[:len(methodBytes)], methodBytes) {
    return &DetectionResult{Protocol: "SIP", ...}
}
```

For TCP, `ctx.Payload` is the individual segment payload, not the reassembled stream. This works when:
- UDP SIP (each datagram is typically a complete message)
- TCP segments that happen to start with a SIP method

This **fails** when:
- TCP segments contain continuation of a SIP message (headers, body)
- SIP messages are fragmented across multiple segments
- Large SIP messages split mid-header

### Impact by Mode

| Mode | TCP SIP Handling | Affected? | Consequence |
|------|------------------|-----------|-------------|
| `sniff voip` | TCP reassembly | **No** | Full SIP parsing on reassembled streams |
| `tap voip` | TCP reassembly | **No** | Full SIP parsing on reassembled streams |
| `hunt voip` | TCP reassembly | **No** | Full SIP parsing on reassembled streams (implemented 2026-01-24) |
| `watch live` | Hybrid detection | **No** | Port-based + header-based + flow cache detection |

## Technical Analysis

### How `sniff voip` / `tap voip` Handle TCP SIP (Correct)

In `internal/pkg/voip/core.go:202-209`, packet routing is transport-based only:

```go
switch layer := packet.TransportLayer().(type) {
case *layers.TCP:
    handleTcpPackets(pkt, layer, assembler)  // ALL TCP goes to assembler
case *layers.UDP:
    handleUdpPackets(pkt, layer)
}
```

Key points:
- **No protocol detection gates processing** - all TCP packets go to the assembler
- SIP parsing happens on **reassembled streams** in `tcp_stream.go`
- Content-based detection (looking for "Call-ID:" header, SIP start lines)
- TCP fragmentation is handled transparently by gopacket's `tcpassembly`

### How `hunt voip` Handles TCP SIP (Problematic)

In `internal/pkg/hunter/application_filter.go:1218-1234`:

```go
func (af *ApplicationFilter) isVoIPPacket(packet gopacket.Packet) bool {
    result := af.detector.Detect(packet)  // Per-packet detection
    if result == nil {
        return false
    }
    switch result.Protocol {
    case "SIP", "RTP", "RTCP":
        return true
    default:
        return false
    }
}
```

And in `MatchPacket` (line 510-527):

```go
if hasVoIPFilters {
    if af.isVoIPPacket(packet) {  // Must pass detection
        // Apply VoIP filters...
    }
}
```

**Problem:** If a TCP segment doesn't start with a SIP method, `isVoIPPacket()` returns `false`, VoIP filters are not applied, and the packet may be dropped.

### How `watch live` Handles TCP SIP (Problematic)

In `internal/pkg/tui/bridge.go:740-747`:

```go
detectionResult := detector.GetDefault().Detect(pkt)  // Per-packet detection
if detectionResult != nil && detectionResult.Protocol != "unknown" {
    display.Protocol = detectionResult.Protocol
    display.Info = buildProtocolInfo(detectionResult, pkt, &display)
}
```

If detected as SIP, `buildProtocolInfo()` populates `VoIPData` and registers media ports:

```go
tracker.RegisterMediaPorts(display.VoIPData.CallID, rtpIP, mediaPorts)
```

**Problem:** If a TCP segment isn't detected as SIP:
- `VoIPData` won't be populated
- `RegisterMediaPorts()` won't be called
- RTP packets won't be correlated to the call
- Call appears as "RTP-only" with synthetic CallID like `rtp-12345678`

## Root Cause

The detector operates on **individual packet payloads**, not reassembled TCP streams. This is by design for performance (no state required), but creates a gap for TCP-based protocols.

## Improvement Options

### Option A: Full TCP Reassembly in Hunter (IMPLEMENTED)

Add `tcpassembly.Assembler` to hunter, identical to sniff/tap modes.

**Pros:**
- Most accurate - handles all fragmentation cases
- Consistent with sniff/tap voip
- Reuses existing `sipStreamFactory`, `SIPStream`, and `HunterForwardHandler`

**Cons:**
- Memory overhead (stream buffers per flow) - mitigated by periodic flushing
- Added latency (must wait for reassembly) - acceptable for accurate filtering

**Implementation:** This option was implemented on 2026-01-24:
- `VoIPPacketProcessor.SetAssembler()` wires the assembler
- TCP packets are buffered and fed to the assembler
- `HunterForwardHandler` receives reassembled SIP messages
- Background goroutine flushes old streams every 30 seconds

### Option B: Flow-based Protocol Memory

Once any packet in a TCP flow is detected as SIP, remember that flow and treat all subsequent packets as SIP.

**Pros:**
- Low overhead after initial detection
- Detector already has flow tracking (`FlowTracker`)

**Cons:**
- If first packet is fragmented, flow never gets marked as SIP
- Doesn't solve initial detection problem
- Requires flow state management

**Recommendation:** Useful as supplementary approach, not standalone solution.

### Option C: Port-based Hinting (Recommended for Operations)

For TCP on ports 5060/5061, assume traffic is likely SIP and:
- Forward through VoIP filters regardless of detection result
- Apply SIP parsing even if not "detected"

**Pros:**
- Simple, low overhead
- Works for standard SIP deployments
- BPF filter does the work in kernel space

**Cons:**
- Doesn't work for non-standard ports
- May process non-SIP traffic on those ports

**Recommendation:** This is the primary recommended approach via `--sip-port` flag.

### Option D: Enhanced Content Detection

Look for SIP indicators **anywhere** in payload, not just at start:
- `Call-ID:` or `i:` (compact form)
- `CSeq:`
- `Via: SIP/2.0` or `v: SIP/2.0`

**Pros:**
- Catches continuation packets
- Works for any port
- No state required

**Cons:**
- More CPU per packet
- Potential false positives (email with "From:" header)
- Still won't catch all fragments

**Recommendation:** Could be added to detector as fallback.

### Option E: Hybrid Approach

Combine B + C + D:
1. **Port-based fast path**: TCP on 5060/5061 → treat as potential SIP
2. **Enhanced detection**: Look for SIP headers anywhere in payload
3. **Flow memory**: Once detected, cache the flow as SIP

**Recommendation:** Best balance of accuracy and performance for TUI.

## Implemented Solution

### BPF Filter Optimization (Operational)

The recommended operational approach is to use `--sip-port` to generate optimized BPF filters:

```bash
# Recommended usage
sudo lc hunt voip -i eth0 --sip-port 5060

# Generated BPF filter:
# (port 5060) or (udp portrange 10000-32768)
```

This ensures:
- TCP on port 5060 is captured (for TCP SIP)
- UDP on port 5060 is captured (for UDP SIP)
- UDP in RTP range is captured (for RTP streams)

### Deprecated `--udp-only` Flag

The `--udp-only` flag has been deprecated in all VoIP commands because it completely misses TCP SIP traffic:

```
Flag --udp-only has been deprecated, this flag misses TCP SIP traffic; use --sip-port instead for proper BPF filtering
```

### Added Warning for Missing SIP Port Filter

When VoIP mode is used without `--sip-port`, a warning is displayed:

```
WARN: No --sip-port specified: capturing all TCP traffic for SIP detection
WARN: For better performance, use: --sip-port 5060 (or your SIP port)
```

## Implemented: `watch live` TUI Hybrid Detection

The TUI live mode now implements Option E (Hybrid) in `internal/pkg/tui/bridge.go`:

### Implementation Details

**Flow Cache:**
- `tcpSIPFlowCache`: Maps flow keys to entries with timestamps
- TTL-based eviction (5 minutes max age)
- Size-limited (10,000 max entries)
- Symmetric flow keys (same key for both directions)

**Detection Order:**
1. **Standard detection**: Use detector for SIP method prefix matching
2. **Flow cache lookup**: If flow already known as SIP, treat packet as SIP
3. **Port-based hinting**: TCP on port 5060/5061 → mark as SIP
4. **Header-based detection**: Look for SIP headers (Call-ID, Via, CSeq) anywhere in payload

**Key Functions Added:**
```go
// Flow key generation (symmetric)
func getTCPFlowKey(srcIP, dstIP, srcPort, dstPort string) string

// Flow cache operations
func isTCPSIPFlow(flowKey string) bool
func markTCPSIPFlow(flowKey string)
func updateTCPSIPFlowTimestamp(flowKey string)
func ClearTCPSIPFlowCache()

// Detection helpers
func isTCPOnSIPPort(srcPort, dstPort string) bool
func containsSIPHeaders(payload []byte) bool
func containsBytes(haystack, needle []byte) bool
```

**Applied to Both Conversion Paths:**
- `convertPacketFast()`: Lightweight path with hybrid detection
- `convertPacket()`: Full path with detector + hybrid fallback

### Test Coverage

Added tests in `bridge_test.go`:
- `TestTCPSIPFlowCache`: Cache operations
- `TestGetTCPFlowKey`: Symmetric key generation
- `TestIsTCPOnSIPPort`: Port-based detection
- `TestContainsSIPHeaders`: Header-based detection
- `TestConvertPacketFast_TCPSIPContinuation`: Port-based hinting
- `TestConvertPacketFast_TCPSIPFlowMemory`: Flow memory across packets

## Summary

| Component | Status | Solution |
|-----------|--------|----------|
| `sniff voip` | ✅ Working | Uses TCP reassembly |
| `tap voip` | ✅ Working | Uses TCP reassembly |
| `hunt voip` | ✅ **Implemented** | Full TCP reassembly (Option A) - same as sniff/tap |
| `watch live` | ✅ **Implemented** | Hybrid detection (Option E) |

### Hunter TCP Reassembly Implementation (2026-01-24)

The hunter node now uses the same TCP reassembly approach as sniff/tap modes:

1. **`cmd/hunt/voip.go`**: Creates `tcpassembly.StreamPool` and `Assembler`
2. **`internal/pkg/voip/voip_packet_processor.go`**: Feeds TCP packets to assembler
3. **Background flusher**: Periodically flushes old TCP streams (every 30s, 2min timeout)
4. **Reused components**: `sipStreamFactory`, `SIPStream`, `HunterForwardHandler`

This ensures TCP SIP messages are properly reassembled before filter matching, eliminating
the fragmentation issues that previously caused TCP SIP to be missed.

## References

- `internal/pkg/voip/core.go` - VoIP packet routing
- `internal/pkg/voip/tcp_stream.go` - TCP reassembly for SIP
- `internal/pkg/detector/signatures/voip/sip.go` - SIP detection logic
- `internal/pkg/hunter/application_filter.go` - Hunter VoIP filtering
- `internal/pkg/tui/bridge.go` - TUI packet conversion
- `internal/pkg/voip/filter.go` - BPF filter builder
