# Intrusion Detection System (IDS) Analysis for lippycat

## Executive Summary

This document analyzes lippycat's potential as an intrusion detection platform, evaluating its current architecture, capabilities, and potential extensions for security monitoring and threat detection.

## Current Architecture Assessment

### Strengths for IDS Use Cases

1. **Distributed Capture Architecture**
   - Hunter nodes can be deployed across multiple network segments
   - Provides visibility into different security zones (DMZ, internal, external)
   - Scales horizontally by adding more hunters
   - Reduces single point of failure

2. **Centralized Analysis**
   - Processor node aggregates data from multiple sources
   - Enables correlation across network segments
   - Single point for rule management and threat intelligence updates
   - Facilitates detection of distributed attacks

3. **Real-Time Streaming**
   - Low-latency packet forwarding (100ms batch intervals)
   - Suitable for real-time threat detection and response
   - gRPC-based communication with flow control

4. **Built-in Protocol Detection**
   - Deep packet inspection for 20+ protocols
   - Centralized detection engine (`internal/pkg/detector`)
   - Protocol-specific metadata extraction (SIP, RTP, DNS, SSH, VPN, etc.)
   - Extensible signature-based detection

5. **Existing Filter Infrastructure**
   - Dynamic filter management (`internal/pkg/processor/processor.go:516-582`)
   - Push filters from processor to hunters
   - BPF filter support for efficient packet filtering
   - Hunter-specific filter targeting

6. **Evidence Collection**
   - Per-call PCAP writing (`internal/pkg/processor/pcap_writer.go`)
   - Full packet capture for forensic analysis
   - Async PCAP writing to avoid blocking detection pipeline

## IDS Use Cases

### 1. Botnet Detection (IP-Based Threat Intelligence)

**Scenario**: Match captured traffic against known botnet C2 IP addresses

**Implementation Approaches**:

#### Option A: Hunter-Side Filtering (Efficient)
- **How**: Hunters maintain local threat intel lists (botnet IPs, malicious domains)
- **Pros**: Reduces bandwidth, filters at edge, minimal processor overhead
- **Cons**: Limited correlation, no cross-segment visibility
- **Best for**: High-volume networks where bandwidth is constrained

```
Threat Intel Feed → Processor → Push IP filters to Hunters
Hunter: if (dst_ip in botnet_ips) → forward to Processor
Processor: Log, alert, take action
```

#### Option B: Processor-Side Correlation (Powerful)
- **How**: All traffic forwarded to processor, centralized threat matching
- **Pros**: Full correlation, behavioral analysis, multi-stage attack detection
- **Cons**: Higher bandwidth usage, processor becomes bottleneck
- **Best for**: Smaller deployments or critical segments requiring deep inspection

```
Hunters → Forward all traffic → Processor
Processor: Match against threat intel, correlate across hunters
Processor: Detect patterns, generate alerts
```

#### Option C: Hybrid Approach (Recommended)
- **How**: Hunter does coarse filtering, processor does deep analysis
- **Pros**: Balanced performance, comprehensive detection
- **Cons**: More complex architecture
- **Best for**: Production deployments requiring both efficiency and depth

```
Hunters: Quick IP/port/protocol filtering → Forward suspects
Processor: Deep inspection, correlation, behavioral analysis
Processor: Update hunter filters based on new threats (dynamic)
```

### 2. Port Scanning Detection

**Threat**: Attackers scan network for vulnerable services

**Detection Method**:
- Processor correlates SYN packets across multiple hunters
- Identifies patterns: many destinations, sequential ports, short timeframe
- Distinguishes from legitimate traffic (connection establishment rates)

**Current Capability**:
- Protocol detection includes TCP flag inspection
- Processor receives packets from all hunters
- Need: State tracking to correlate SYN packets over time

### 3. Data Exfiltration Detection

**Threat**: Sensitive data being sent to external adversary

**Detection Method**:
- Monitor outbound traffic volume to suspicious IPs/domains
- Identify unusual protocols on non-standard ports (DNS tunneling, HTTPS to unknown hosts)
- Track data transfer patterns (large uploads, periodic beaconing)

**Current Capability**:
- Protocol detection can identify tunneling attempts
- Packet metadata includes src/dst IPs, ports, protocols
- Need: Volume tracking, baseline behavior modeling

### 4. Command & Control (C2) Traffic Detection

**Threat**: Compromised hosts communicating with attacker infrastructure

**Detection Method**:
- Beaconing detection: Regular intervals, consistent packet sizes
- Protocol anomalies: HTTP with unusual user-agents, non-standard TLS
- Known C2 signatures: Cobalt Strike, Metasploit patterns

**Current Capability**:
- Protocol detector can identify malformed/suspicious protocols
- Timestamp tracking for temporal analysis
- Need: Behavioral pattern matching, C2 signature library

### 5. Lateral Movement Detection

**Threat**: Attacker pivoting through internal network after initial compromise

**Detection Method**:
- Monitor authentication attempts across segments (SMB, SSH, RDP)
- Detect unusual service access patterns
- Track privilege escalation attempts

**Current Capability**:
- Hunters deployed across segments see cross-zone traffic
- Protocol detection for auth protocols
- Need: User/host baseline behavior, anomaly detection

### 6. DDoS Detection

**Threat**: Distributed denial of service attacks

**Detection Method**:
- Aggregate packet rates from multiple hunters
- Identify traffic spikes to specific targets
- Protocol-specific floods (SYN flood, DNS amplification, NTP reflection)

**Current Capability**:
- Multiple hunters provide distributed visibility
- Packet batching includes counts
- Protocol detection identifies attack vectors
- Need: Rate threshold configuration, automatic mitigation triggers

### 7. VoIP-Specific Attacks (Given Current VoIP Plugin)

**Threats**:
- SIP scanning/enumeration
- Registration hijacking
- RTP injection/eavesdropping
- Toll fraud

**Detection Method**:
- Monitor SIP REGISTER floods
- Detect unauthorized call attempts
- Identify RTP streams without corresponding SIP signaling

**Current Capability**:
- Full SIP/RTP protocol parsing (`internal/pkg/voip`)
- Call tracking and state management
- SIP header extraction (From, To, Call-ID)
- Need: VoIP-specific attack signatures

## Architectural Gaps for IDS

### 1. Threat Intelligence Integration

**Current State**: No built-in threat intel support

**Needed**:
- IoC feed ingestion (STIX/TAXII, CSV, JSON)
- IP/domain/hash reputation lookups
- Automatic filter generation from threat feeds
- Periodic feed updates

**Recommendation**:
```
Add to processor:
- Threat intel manager service
- Feed parsers for common formats
- Redis/in-memory cache for fast lookups
- REST API to add/remove IoCs
```

### 2. Rule Engine

**Current State**: Filter system supports basic pattern matching

**Needed**:
- Complex detection rules (e.g., "if A and B within time T, then alert")
- Boolean logic combinations
- Stateful rule evaluation
- Custom rule language or adopt existing (Snort/Suricata syntax)

**Recommendation**:
```
Options:
A) Build custom rule engine in Go
B) Integrate existing: gopacket/afpacket with BPF extensions
C) Embed Suricata as library (if feasible)
D) Create plugin system for rule engines
```

### 3. Alert and Response System

**Current State**: No alerting mechanism

**Needed**:
- Alert generation and management
- Severity classification (critical, high, medium, low, info)
- Alert deduplication and aggregation
- Notification channels (syslog, webhook, email, Slack)
- Response actions (block IP, update firewall, kill connection)

**Recommendation**:
```
Add alert subsystem:
- Alert queue with priority handling
- Configurable output plugins (syslog, webhook, etc.)
- Alert correlation to reduce false positives
- SOAR integration hooks
```

### 4. State Tracking and Session Management

**Current State**: Stateless packet processing

**Needed**:
- Connection state tracking (TCP streams, UDP sessions)
- Session reassembly for application-layer analysis
- Stateful protocol analysis
- Time-windowed correlation

**Recommendation**:
```
Add to processor:
- Connection table (5-tuple tracking)
- Stream reassembly engine (use gopacket/reassembly)
- Session timeout management
- Memory-bounded state storage
```

### 5. Behavioral Analysis and Anomaly Detection

**Current State**: Signature-based detection only

**Needed**:
- Baseline behavior modeling
- Statistical anomaly detection
- Machine learning integration
- User/host profiling

**Recommendation**:
```
Phase 1: Basic statistics (packet rates, connection counts)
Phase 2: Time-series analysis (detect deviations)
Phase 3: ML integration (optional, via plugin)
```

## Design Philosophy: Full IDS vs. Building Blocks

### Option 1: Full-Featured IDS

**Approach**: Transform lippycat into a complete IDS solution

**Pros**:
- Unified security platform
- Integrated rule management
- Out-of-box threat detection
- Competitive with Snort/Suricata/Zeek

**Cons**:
- Scope creep (deviates from network analysis tool)
- Maintenance burden (security rules, signatures)
- Opinionated architecture
- Harder to customize

### Option 2: IDS Building Blocks (Recommended)

**Approach**: Provide flexible platform for building security solutions

**Pros**:
- Maintains focus on packet analysis and visibility
- Plugin architecture allows specialized IDS modules
- Users can integrate their own threat intel, rules, ML models
- Complements existing tools rather than replacing them

**Cons**:
- Not turnkey IDS solution
- Requires user expertise to build detections
- May need external tools for complete pipeline

### Recommendation: **Hybrid Approach**

**Core Platform** (lippycat):
- High-performance packet capture and analysis
- Protocol detection and metadata extraction
- Distributed architecture (hunters/processors)
- Filter and subscription system
- PCAP export for evidence

**IDS Extensions** (plugins/modules):
- Threat intel plugin (IoC matching)
- Rule engine plugin (Snort-like rules)
- Alert output plugin (syslog, webhook, SIEM)
- Behavioral analysis plugin (anomaly detection)
- Response action plugin (firewall integration)

**Benefits**:
- Core remains focused and maintainable
- Users choose which IDS features they need
- Extensible without bloat
- Can integrate with existing security stack

## Implementation Roadmap

### Phase 1: Foundation (Current State + Minimal IDS)
- ✅ Distributed capture (hunters/processors)
- ✅ Protocol detection
- ✅ Filter system
- ✅ PCAP export
- **Add**: Simple threat intel matching (IP blocklist/allowlist)
- **Add**: Basic alerting (stdout, syslog)

### Phase 2: Enhanced Detection
- **Add**: Stateful connection tracking
- **Add**: Rule engine (custom or integrated)
- **Add**: Alert management (deduplication, correlation)
- **Add**: Threat intel feed integration (auto-update)

### Phase 3: Advanced Analysis
- **Add**: Stream reassembly
- **Add**: Behavioral baseline and anomaly detection
- **Add**: Response actions (firewall updates, connection blocking)
- **Add**: Dashboard/visualization (Grafana integration)

### Phase 4: Enterprise Features
- **Add**: Multi-tenancy
- **Add**: Role-based access control
- **Add**: Audit logging
- **Add**: SIEM integration (Splunk, Elastic, etc.)

## Technical Recommendations

### 1. Threat Intel Module Design

```go
// internal/pkg/intel/manager.go
type ThreatIntel struct {
    ipBlocklist   map[string]ThreatInfo
    domainList    map[string]ThreatInfo
    hashList      map[string]ThreatInfo
    feeds         []FeedSource
    updateInterval time.Duration
}

type ThreatInfo struct {
    Type        string    // botnet, malware, c2
    Severity    int       // 1-10
    Source      string    // feed name
    LastUpdated time.Time
    Metadata    map[string]interface{}
}

func (ti *ThreatIntel) CheckIP(ip string) (match bool, info ThreatInfo)
func (ti *ThreatIntel) LoadFeed(source FeedSource) error
func (ti *ThreatIntel) AutoUpdate(ctx context.Context)
```

### 2. Rule Engine Interface

```go
// internal/pkg/rules/engine.go
type Rule struct {
    ID          string
    Name        string
    Severity    string
    Conditions  []Condition
    Actions     []Action
    Enabled     bool
}

type Condition interface {
    Evaluate(pkt *PacketContext) bool
}

type Action interface {
    Execute(alert Alert) error
}

// Example: if (src_ip in botnet_list AND dst_port=445 AND protocol=TCP)
```

### 3. Alert System

```go
// internal/pkg/alerts/manager.go
type Alert struct {
    ID          string
    Timestamp   time.Time
    RuleID      string
    Severity    string
    Source      string
    Destination string
    Protocol    string
    Description string
    Evidence    []byte // raw packet or PCAP
}

type AlertManager struct {
    queue       chan Alert
    outputs     []AlertOutput
    deduplicator *Deduplicator
}

type AlertOutput interface {
    Send(alert Alert) error
}
// Implementations: SyslogOutput, WebhookOutput, SlackOutput, etc.
```

### 4. State Tracking

```go
// internal/pkg/state/tracker.go
type ConnectionTracker struct {
    sessions map[FiveTuple]*Session
    timeout  time.Duration
}

type FiveTuple struct {
    SrcIP   string
    DstIP   string
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}

type Session struct {
    State       string // NEW, ESTABLISHED, CLOSED
    BytesSent   uint64
    BytesRecv   uint64
    PacketCount uint64
    StartTime   time.Time
    LastSeen    time.Time
}
```

## Integration Examples

### Example 1: Botnet Detection Pipeline

```
1. Threat Intel Manager loads botnet IP feed from AlienVault OTX
2. Processor generates filter: "match dst_ip in botnet_list"
3. Filter pushed to all hunters
4. Hunter captures packet to 192.0.2.100 (known botnet C2)
5. Hunter forwards packet to processor
6. Processor rule engine evaluates: MATCH
7. Alert generated: "Botnet C2 Communication Detected"
8. Alert sent to syslog and webhook (SOC notification)
9. Response action: Update firewall to block 192.0.2.100
10. Evidence: PCAP file written with full session capture
```

### Example 2: Port Scan Detection

```
1. Hunters forward all SYN packets to processor
2. Processor connection tracker maintains scan state:
   - Track: SrcIP → [DstIP:Port list, timestamp]
3. Rule: if (unique_dst_ports > 100 within 60s) → Alert
4. Detection: 192.168.1.50 scans 200 ports in 30s
5. Alert: "Port Scan Detected from 192.168.1.50"
6. Response: Rate-limit traffic from 192.168.1.50
```

### Example 3: VoIP Fraud Detection

```
1. SIP plugin detects REGISTER flood (100 attempts/sec)
2. Rule: if (SIP_REGISTER rate > threshold AND auth_failures > 10)
3. Alert: "SIP Registration Attack - Potential Toll Fraud"
4. Response: Block source IP at SBC (Session Border Controller)
5. Evidence: SIP message capture for forensics
```

## Security Considerations

### 1. Hunter Node Security
- Hunters have network visibility - secure deployment critical
- Run with minimal privileges (drop root after capture init)
- Encrypt gRPC traffic (TLS for hunter-processor communication)
- Authenticate hunters before accepting connections

### 2. Threat Intel Poisoning
- Validate feed sources (signature verification)
- Prevent malicious IoC injection
- Rate-limit feed updates
- Audit trail for all intel changes

### 3. Alert Fatigue
- Implement alert thresholds and rate limiting
- Deduplication to prevent storm
- Confidence scoring to reduce false positives
- Tunable sensitivity per environment

### 4. Privacy and Compliance
- PCAP data may contain sensitive information (PII, credentials)
- Implement data retention policies
- Support packet anonymization (IP masking, payload redaction)
- Access controls for captured data

## Performance Considerations

### Hunter Performance
- Filter at hunter to reduce bandwidth (push down filtering)
- Use BPF for kernel-level filtering (zero-copy where possible)
- Async packet forwarding to avoid blocking capture

### Processor Performance
- Stateful tracking requires memory - implement LRU eviction
- Parallel rule evaluation (goroutine pool)
- Alert queue with backpressure handling
- Horizontal scaling: Multiple processors with load balancing

### Network Performance
- Batch packets (already implemented: 64 packets/batch)
- Compress gRPC traffic (optional: gzip compression)
- Flow control to prevent overwhelm (already implemented)

## Comparison with Existing IDS Solutions

### Snort/Suricata
- **Pros**: Mature rule language, large signature database, community
- **Cons**: Single-node architecture, complex deployment
- **lippycat advantage**: Distributed capture, Go performance, simpler deployment

### Zeek (Bro)
- **Pros**: Scriptable, protocol analysis, connection logging
- **Cons**: Steep learning curve, resource intensive
- **lippycat advantage**: Plugin architecture, modern language, lighter footprint

### Elastic Security / Wazuh
- **Pros**: SIEM integration, dashboards, correlation
- **Cons**: Heavy (Elasticsearch cluster), complex setup
- **lippycat advantage**: Focused tool, can feed into SIEM, simpler architecture

### Positioning
lippycat should position as:
- **Lightweight**: Easy deployment, minimal dependencies
- **Distributed**: Native multi-segment monitoring
- **Extensible**: Plugin architecture for custom detections
- **Complementary**: Integrates with existing security stack (feeds SIEM, updates firewalls)

## Conclusion

lippycat has a strong architectural foundation for IDS capabilities:
- Distributed capture provides network-wide visibility
- Protocol detection enables deep inspection
- Existing filter system can be extended for threat matching
- Real-time streaming supports immediate threat response

**Recommended Approach**:
Evolve lippycat as an **IDS building block platform** rather than monolithic IDS. Provide:
1. Core: High-performance distributed packet analysis
2. Plugins: Threat intel, rules, alerts, response actions
3. Integrations: SIEM, SOAR, threat feeds, firewalls

This maintains focus while enabling users to build custom IDS solutions tailored to their environments.

**Next Steps**:
1. Implement basic threat intel matching (IP blocklist/allowlist)
2. Add simple alerting (syslog output)
3. Create plugin interface for extensibility
4. Build example IDS plugins (botnet detection, port scan detection)
5. Document IDS deployment patterns and best practices
