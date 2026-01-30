# TUI Layer Summary

**Date:** 2026-01-30
**Status:** Complete

## Overview

Add a compact protocol layer summary to the TUI details panel, showing the packet's layer stack (Ethernet → IPv4 → TCP → HTTP) with key fields from each layer. This fills the gap between basic packet info and protocol-specific analysis.

## Design

### Display Format

```
─── Layers ───────────────────────────────────────
Ethernet  40:61:86:9a:f1:f5 → 00:1a:8c:15:f9:80
IPv4      192.168.3.131 → 72.14.213.138  TTL=64
TCP       57011 → 80  [SYN,ACK] Seq=944 Ack=387
HTTP      GET /complete/search?client=chrome...
```

Covering the full available width of the details panel, taking into account box characters and padding.

### Layer Fields

| Layer | Key Fields |
|-------|------------|
| Ethernet | Src MAC → Dst MAC, EtherType (if not IP) |
| IPv4 | Src → Dst, TTL, ID (if fragmented) |
| IPv6 | Src → Dst, Hop Limit |
| TCP | SrcPort → DstPort, Flags, Seq, Ack |
| UDP | SrcPort → DstPort, Length |
| ICMP | Type, Code, ID/Seq (for echo) |
| Application | Protocol-specific one-liner (already in Info field) |

### Implementation Approach

Parse layers from `RawData` + `LinkType` in the details panel renderer using gopacket. No changes to `PacketDisplay` struct or capture pipeline required.

## Tasks

### Phase 1: Layer Parsing

- [x] Add `renderLayerSummary()` method to `detailspanel.go`
- [x] Parse Ethernet layer (MACs, EtherType for non-IP)
- [x] Parse IPv4/IPv6 layer (addresses, TTL/HopLimit)
- [x] Parse TCP layer (ports, flags, seq/ack)
- [x] Parse UDP layer (ports, length)
- [x] Parse ICMP layer (type, code)
- [x] Handle VLAN tags (802.1Q) if present

### Phase 2: Integration

- [x] Insert layer summary section after "Packet Details", before protocol-specific sections
- [x] Use section header style: `─── Layers ───`
- [x] Color-code by layer type (link=gray, network=blue, transport=cyan)
- [x] Truncate long MACs/IPs on narrow terminals

### Phase 3: Edge Cases

- [x] Handle missing RawData gracefully (skip section)
- [x] Handle unknown/unsupported link types
- [x] Handle truncated packets (show available layers only)

## File Changes

**Modified:**
- `internal/pkg/tui/components/detailspanel.go` - add `renderLayerSummary()`, call from `renderContent()`

**No changes required:**
- `internal/pkg/types/packet.go` - RawData and LinkType already available
- Capture pipeline - no API changes needed

## Notes

- gopacket is already a dependency (used for capture)
- Parsing in the renderer is acceptable since it only happens for the selected packet
- Keeps implementation self-contained in the TUI package
