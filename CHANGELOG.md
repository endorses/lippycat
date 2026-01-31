# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-01-31

### Added
- **TUI statistics dashboard**: Complete statistics tab with interactive dashboard
  - Protocol distribution bar charts with colored bars
  - CPU/RAM sparklines for TUI process monitoring
  - Active calls sparkline for VoIP monitoring
  - Top talkers navigation with h/l and arrow keys
  - Fleet health stats for remote mode
  - Bridge performance statistics
  - Responsive layouts for different terminal sizes
  - Clickable view and time window selectors
- **VoIP call filtering**: Generic filtering system for call list
  - Call filter syntax with state and numeric comparison filters
  - Filter syntax documentation in help tab
  - Persistent filter history
- **RTP-only call support**: Display calls detected from RTP before SIP arrives
  - RTP-only call state with distinct styling
  - Auto-merge with SIP when signaling arrives
  - LRU eviction for CallStore, CallTracker, and CallAggregator
- **Capture pause coordination**: PauseSignal type for synchronized pause/resume
  - Source-level pause support in PacketBuffer
  - Call updates pause when capture is paused
- **Protocol detection improvements**:
  - QUIC protocol detector
  - Heuristic RTP detection for edge cases
  - TCP SIP injection support
  - Protocol layer summary in details panel
- **TUI usability improvements**:
  - Node address history in Add Node modal
  - Toast supersession for auto-dismissing obsolete messages
  - Top-of-list auto-scroll for call view
  - Dev console for debugging
- **Hunter TCP reassembly**: Full TCP reassembly for VoIP hunter mode
- **TCP SIP timeout flags**: Configurable timeouts for TCP SIP handling

### Changed
- **Default gRPC port**: Changed from 50051 to 55555
- **Default filter policy**: Changed `--no-filter-policy` default to `deny` for hunt and tap commands
- **Statistics tab redesign**: Simplified to Overview and Distributed views

### Fixed
- **IPv4 defragmentation**: Fixed handling of fragmented SIP messages
- **TCP SIP handling**: Multiple improvements to TCP stream handling
  - Replaced tcpreader with buffered stream to prevent capture freeze
  - Added TCP stream read timeout for persistent connections
  - Hybrid TCP SIP detection for continuation packets
  - TCP reassembly for SIP detection instead of heuristics
- **TUI stability fixes**:
  - Prevent crash when interacting during startup
  - Reset terminal SGR attributes before starting TUI
  - Return focus to packet list when hiding details panel
  - Help tab section selector clicks when scrolled
  - Settings input field mouse and escape behavior
- **VoIP fixes**:
  - Extract phone suffix from SIP user part only, not full URI
  - Add discard flag to stop buffering non-SIP streams immediately
  - Update call From/To when SIP arrives after RTP
  - Inherit From/To from tracker for RTP-created calls
- **TUI layout fixes**:
  - Consistent bar style for bridge queue indicator
  - Truncate long codec names in VoIP statistics
  - Correct sparkline padding calculation
  - Card width and height calculations for dashboard layout
  - CPU sparkline positioning in TUI PROCESS card
  - Allow CPU usage display to exceed 100% on multi-core systems
- **Filtering fixes**:
  - Reapply packet filters when paused instead of clearing
  - Reapply packet filters in offline mode
  - Auto-scroll state matching cursor position after filter
  - Re-sort filtered calls when StartTime changes
- **Call list fixes**:
  - Eliminate race condition with sorted insert
  - Track selected call by ID for correct auto-scroll on removal
  - Scroll up when filtered call list shrinks
  - Make offline VoIP call tracking deterministic
- **Protocol detection**: Prevent OpenVPN false positives on TLS traffic
- **Remote capture**: Use packet timestamp for call EndTime instead of time.Now()
- **HTTP info**: Extract HTTP info from payload when metadata unavailable
- **Invalid UTF-8 handling**: Handle invalid UTF-8 and rate calculation after reconnection

### Performance
- **Statistics caching**: Cache statistics computations to eliminate CPU spikes
- **Call view optimization**: Multi-phase performance improvements
  - Double-buffer pattern to reduce allocations
  - Index map for selected call lookup
  - SIP packet priority queue for sampling

## [0.8.3] - 2026-01-21

### Added
- **DNS fallback parsing**: Added fallback parsing when gopacket doesn't auto-decode DNS layers, improving DNS packet detection reliability
- **Processor automatic reconnection**: Processors now automatically reconnect to upstream connections when disconnected

### Fixed
- **Processor data races**: Added per-processor mutex to fix data races in downstream manager when multiple hunters connect/disconnect
- **TUI TAP virtual hunters**: Fixed TAP virtual hunters not showing in graph view after reconnection
- **TUI TAP node reconnection**: Fixed TAP node reconnection and stats updates in graph view

## [0.8.2] - 2026-01-20

### Added
- **TUI calls view auto-scroll**: Automatically follows new calls when scrolled to bottom
- **TUI calls view navigation**: Added GotoTop, GotoBottom methods for keyboard navigation

### Fixed
- **TUI UI freeze at high packet rates**: Fixed two issues causing UI freeze when using filters like `has:voip` at 300-400 Mbit/s traffic rates. GetNewFilteredPackets now uses monotonically increasing counter instead of buffer length, and MetadataFilter for `has:voip` also matches by Protocol name (SIP/RTP)
- **TUI VoIP call tracking**: Fixed LocalCallAggregator not being initialized on startup for live and offline capture modes, causing "No active VoIP calls" despite SIP/RTP packets being captured
- **TUI mouse click handling**: Fixed mouse clicks selecting incorrect rows in calls view; moved to central mouse_handler.go for consistent coordinate calculation
- **TUI node column display**: Show interface name instead of "offline" in Node column for local capture modes

## [0.8.1] - 2026-01-20

### Added
- **TUI filter documentation**: Comprehensive filter syntax help in the TUI help tab covering BPF, port, IP, and protocol filters

### Fixed
- **TUI TAP node display**: Correct TAP node visualization and selection behavior in the graph view
- **Signal handler panic**: Prevent panic on early cleanup when service fails to start
- **CI test stability**: Use dynamic port allocation in integration tests to prevent port conflicts
- **Makefile version parsing**: Strip 'v' prefix from git tags when extracting version

## [0.8.0] - 2026-01-19

### Breaking Changes
- **`watch file` command**: Removed `-r`/`--read-file` flag in favor of positional arguments
  - Old: `lc watch file -r capture.pcap`
  - New: `lc watch file capture.pcap`
  - Now supports multiple files: `lc watch file sip.pcap rtp.pcap`
- **CLI flag normalization**: Standardized flag naming with short flags
  - `--sipuser` → `--sip-user` (`-u`) for sniff voip, tap voip commands
  - `--upstream` → `--processor` (`-P`) for tap, process commands
  - `--hunter-id` → `--id` (`-I`) for hunt command
  - `--processor-id` → `--id` (`-I`) for process command
  - `--tap-id` → `--id` (`-I`) for tap command
  - Old flag names are deprecated and will show warning messages, but continue to work

### Added
- **Multi-file PCAP support**: Analyze multiple PCAP files simultaneously in TUI
  - Space-separated files in offline settings dialog
  - Header displays "Files:" when multiple files loaded
  - Merged packet display across all files
- **Node CPU/RAM statistics**: Real-time system metrics for hunters and tap nodes
  - New sysmetrics package for CPU/RAM collection
  - CPU/RAM columns in TUI nodes display
  - CPU/RAM fields in CLI JSON output
  - Metrics forwarded via gRPC proto
- **Tap command enhancements**:
  - GPU acceleration support (`--gpu-backend`)
  - LI support in LI builds (`--li-*` flags)
  - TLS keylog support (`--sslkeylogfile`)
  - Production mTLS enforcement
  - `--voip-command` and `--stats` flags
  - Own-traffic BPF exclusion to prevent capture loops
- **TUI responsive layout**: Adaptive layout for different terminal sizes
  - Responsive header with proportional column widths
  - Responsive footer with progressive disclosure
  - Responsive tabs with progressive disclosure
  - Terminal resize re-renders content properly
- **TUI performance optimizations**:
  - High-traffic capture optimization for smooth 50ms updates
  - Memory optimization with ring buffer
  - Non-blocking bridge to prevent packet freeze
  - Bridge diagnostics in statistics view
- **Protocol mode display**: Hunter/tap nodes show protocol badges in TUI
  - Protocol-specific filter validation
  - Protocol mode detection for badge display
- **VRRP support**: VRRP info extraction in packet list
- **Build-tagged CLI flags**: GPU flags for sniff/hunt, LI flags for process
- **JSON output for `list interfaces`**: Structured output for scripting
- **New short flags**: Added short flags for commonly used options
  - `-T` for `--tls` across all commands
  - `-V` for `--virtual-interface` in sniff, tap, process commands
  - `-P` for `--processor` in hunt, tap, process commands
  - `-I` for `--id` in hunt, tap, process commands
  - `-u` for `--sip-user` in sniff voip, tap voip commands
  - `-n` for `--nodes-file` in watch remote command

### Changed
- Renamed `docs/plan` directory to `docs/plans`

### Fixed
- **Hunter metrics forwarding**: Store and forward CPU/RAM metrics in processor
- **Non-amd64 SIMD**: Added fallback implementation for non-amd64 architectures
- **Config consistency**: Use consistent `tui.*` viper config prefix
- **CI failures**: Fixed lint ineffassign and data race issues
- **TAP virtual hunter**: Show correct capture stats and filter count
- **Watch TLS config**: Support TLS config from config file
- **Viper bindings**: Added viper binding for insecure flag in hunt, process, tap
- **Interface filtering**: Unified filtering between CLI and TUI
- **TUI resize**: Re-render content on terminal resize
- **TUI filter input**: Make filter input span full terminal width
- **TUI protocol mode**: Show protocol mode in tree view

## [0.7.3] - 2026-01-13

### Added
- **DNS tunneling detection with command hooks**: Execute custom commands when DNS tunneling is detected
  - `--tunneling-command` flag with placeholder substitution (%domain%, %score%, %entropy%, etc.)
  - `--tunneling-threshold` for configurable detection sensitivity
  - `--tunneling-debounce` for per-domain alert rate limiting
  - Cross-hunter aggregation of tunneling indicators at processor level
  - Alert tracking with source IP aggregation
- **Virtual hunter for TAP nodes**: TAP nodes now display local capture statistics in TUI
  - Appears as "{processor-id}-local" in the hunter list
  - Shows real-time capture stats (packets captured, forwarded, dropped)
  - Displays VoIP mode when VoIP processor is configured
- **`--no-filter-policy` flag**: Added for hunt and tap commands to disable filter policy enforcement
- **DNS metadata in TUI**: DNS query/response metadata now displayed in packet details

### Fixed
- **Config file handling**: Fixed viper.IsSet() returning empty slice for unset config keys
  - CLI flag defaults are now preserved when config file doesn't explicitly set a value
  - Affected commands: tap, hunt, process

## [0.7.2] - 2026-01-11

### Added
- **Secure-by-default TLS for watch modes**: `watch live`, `watch file`, and `watch remote` now use TLS by default
  - Use `--insecure` flag to disable TLS when needed
- **Tap node badge in TUI**: Tap nodes now display with `[TAP]` badge in nodes tab for easy identification

### Changed
- **TLS credential logging**: Changed TLS credential setup logs from INFO to DEBUG level to reduce log noise

### Fixed
- **Tap mode filter management**: Filter changes via `lc set/rm filter` now properly restart capture
  - BPF filters are recompiled and capture is restarted when filters change
  - Application-level filters (SIP user, phone number, call ID, codec) are updated at runtime
- **TUI filter display**: Filters now correctly appear in TUI filter management view
- **TUI connection status**: Fixed Reachable flag not being set on connection success/failure
  - Only shows "Unreachable" status for actually failed connections
- **Watch TLS auto-enable**: TLS is now automatically enabled when certificate flags are provided
- **Topology reachability**: Current processor node now correctly shows as reachable in topology
- **Build tags**: Added missing build tags to TUI and hunter files

## [0.7.1] - 2026-01-10

### Breaking Changes
- **Secure-by-default TLS**: TLS is now enabled by default for all gRPC connections
  - Removed `--tls` flag from hunt, process, and tap commands
  - Use `--insecure` flag to disable TLS when needed (e.g., local development)
  - Production environments (`LIPPYCAT_PRODUCTION=true`) reject insecure connections

### Added
- **TTY-aware JSON output**: CLI commands with JSON output now detect terminal vs pipe
  - Pretty-printed JSON when output is a terminal
  - Compact JSON when piped to other commands

### Changed
- **`show config` command**: Refactored to display all Viper settings
  - JSON-only output format for easier parsing
  - Shows complete configuration state including defaults

## [0.7.0] - 2026-01-10

### Added
- **TLS Decryption Support (Phase 7)**: Real-time TLS traffic decryption using SSLKEYLOGFILE
  - SSLKEYLOGFILE parser with file watcher for dynamic key updates
  - TLS 1.2 key derivation (PRF with SHA-256/SHA-384)
  - TLS 1.3 key derivation (HKDF-based)
  - Cipher suite support: AES-128/256-GCM, AES-128/256-CBC, ChaCha20-Poly1305
  - Session tracking with automatic key matching via Client Random
  - Key forwarding from hunters to processors via gRPC
  - TUI decryption display in packet details panel
  - `--sslkeylogfile` flag for sniff/hunt/tap commands
  - Documentation: [TLS_DECRYPTION.md](docs/TLS_DECRYPTION.md)
- **X1 Rate Limiting**: Per-IP rate limiting for X1 HTTPS server
  - Configurable rate limit (default: 10 req/s) and burst (default: 20)
  - X-Forwarded-For header support for proxy deployments
  - XML parsing timeout protection (default: 5s)

### Changed
- X1 handler functions return flexible types for proper error responses
- Improved test coverage for remotecapture, downstream, and subscriber packages

### Fixed
- **Security**: Command injection vulnerability in CommandExecutor
  - Shell escaping for all user-controlled values (Call-ID, file paths, etc.)
  - Metacharacter detection with warning logs
- **Security**: TOCTOU race condition in CallIDDetector eliminated
  - Mutex-protected state instead of atomic operations
  - Comprehensive race detector stress tests
- **Memory Leak**: Subscriber channel not closed on Remove
  - New `safeChannel` wrapper with synchronized Close/TrySend
  - Prevents goroutine leaks from blocked channel readers
- **Memory Leak**: writtenKeys map unbounded growth in TLS keylog writer
  - Periodic cleanup goroutine (5-minute interval)
  - LRU eviction when MaxEntries reached
- **ETSI Compliance**: X1 error responses now include error details
  - Proper `<errorResponse>` with `<errorCode>` and `<errorDescription>`
- **Context Propagation**: LI delivery client passes context to GetConnection
  - Enables proper cancellation during connection establishment
- **Build**: Processor package build constraints for test compatibility
  - All processor files tagged with `//go:build processor || tap || all`

## [0.6.1] - 2026-01-08

### Added
- **IMAP/POP3 Protocol Support (Phase 5)**: Complete email protocol suite
  - IMAP command parser (SELECT, FETCH, SEARCH, LOGIN, etc.)
  - POP3 command parser (USER, PASS, RETR, LIST, etc.)
  - Multi-protocol factory for port-based protocol detection
  - `--protocol` flag for smtp/imap/pop3/all selection
  - `--imap-port` and `--pop3-port` flags for custom port configuration
  - `--mailbox` flag for IMAP mailbox name filtering (glob patterns)
  - `--command` flag for IMAP/POP3 command filtering (FETCH, RETR, etc.)
  - Extended `EmailMetadata` with IMAP/POP3-specific fields
  - TCP stream handlers for IMAP and POP3 protocols

## [0.6.0] - 2026-01-07

### Added
- **DNS Protocol Support (Phase 1)**: Complete DNS analysis with sniff/hunt/tap commands
  - Query/response correlation with RTT calculation
  - DNS tunneling detection via entropy analysis
  - TUI DNS queries view with `v` key toggle
  - `--domain` and `--domains-file` flags for content filtering
  - Distributed filtering via `FILTER_DNS_DOMAIN` type
- **Email/SMTP Protocol Support (Phase 2)**: SMTP envelope and body analysis
  - MAIL FROM, RCPT TO, Subject header extraction
  - STARTTLS detection and Message-ID correlation
  - TUI Email sessions view with details panel
  - Content filtering: `--sender`, `--recipient`, `--address`, `--subject` flags
  - Body content filtering with `--keywords-file` and `--capture-body`
  - Hunter-side TCP reassembly for distributed body keyword matching
- **TLS/JA3 Fingerprinting (Phase 3)**: TLS handshake analysis
  - ClientHello/ServerHello parsing with SNI extraction
  - JA3, JA3S, and JA4 fingerprint calculation
  - TUI TLS details view in packet details panel
  - Content filtering: `--sni`, `--ja3`, `--ja3s`, `--ja4` flags with file variants
  - Distributed filtering via `FILTER_TLS_SNI`, `FILTER_TLS_JA3`, `FILTER_TLS_JA3S`, `FILTER_TLS_JA4`
- **HTTP Protocol Support (Phase 4)**: HTTP/1.x request/response analysis
  - Request/response correlation with RTT measurement
  - TCP stream reassembly for complete message reconstruction
  - TUI HTTP view with auto-scroll and chronological ordering
  - Content filtering: `--host`, `--path`, `--method`, `--status`, `--user-agent`, `--content-type`
  - Body content filtering with `--keywords-file` and `--capture-body`
  - Distributed filtering via `FILTER_HTTP_HOST`, `FILTER_HTTP_URL`
- **Filter Distribution Infrastructure (Phase 0)**: Protocol-agnostic filter framework
  - New filter types in proto for all supported protocols
  - Hunter filter matchers in `internal/pkg/hunter/filter/`
  - TUI filter manager supports all new filter types
  - Glob pattern matching with O(1) exact match optimization
- **TUI Help Tab**: Interactive help with search functionality
  - Async content loading with glamour markdown rendering
  - Section tabs for navigation (Overview, Capture, Nodes, etc.)
  - Search highlighting with `/` key and persistent results
- **Tap Mode VoIP Integration**: Local capture with processor capabilities
  - VoIP processor integration for standalone capture
  - Per-call PCAP writing in tap mode
- **VoIP Improvements**
  - B2BUA phone suffix correlation for call leg matching
  - RTP tracking via IP:PORT endpoints instead of port-only
  - Phone number normalization for filter patterns
  - Improved call completion monitor for RTP handling

### Changed
- Config file path logged as debug instead of stderr
- README updated with multi-protocol support and architecture diagram

### Fixed
- Prevent nil pointer crash when hunter disconnects abruptly
- Defer PCAP header write until first packet (fixes empty file issues)
- Apply loaded filters to LocalTarget at startup in tap mode
- Propagate actual link type through packet pipeline
- Include unflushed packets in stats reporting
- Use actual capture timestamp instead of current time in processor

## [0.5.2] - 2025-12-29

### Changed
- **tap command flags**: Reorganized flags between `tap` and `tap voip` for clearer separation
  - VoIP-specific flags (`--per-call-pcap*`, `--voip-command`) now only available in `tap voip`
  - All shared flags (TLS, management, virtual interface) now persistent and inherited by `tap voip`
- **sipuser flag**: Removed `-u` short flag to avoid conflict with `--upstream -u`

### Fixed
- **Flag conflict**: Resolved `-u` short flag collision between `--sipuser` and `--upstream`

## [0.5.1] - 2025-12-29

### Fixed
- **Memory leak**: Optimized sync.Pool usage to prevent buffer retention
- **TUI overflow**: Use int64 for statistics counters to prevent overflow on high-traffic captures
- **TLS security**: Added explicit cipher suite configuration for secure defaults
- **Error handling**: Added error logging for critical Close operations throughout codebase
- **VIF injection**: Upgraded errors to warnings with counter for better observability

### Changed
- **Constants extraction**: Refactored magic numbers to documented constants for maintainability
- **TUI state management**: Replaced global capture state with synchronized struct for thread safety
- **VoIP logging**: Added logging for TCP stream cleanup drops for debugging

### Documentation
- Clarified CUDA build tag pattern in CLAUDE.md to prevent misinterpretation

### Testing
- Improved test coverage for hunter/connection and SIP parsing modules

## [0.5.0] - 2025-12-28

### Added
- **ETSI Lawful Interception (LI) support** (`internal/pkg/li/`): Complete implementation of ETSI TS 103 221-1/2 interfaces
  - **X1 Interface** (ADMF ↔ NE): XML/HTTPS administration interface for task management
    - X1 Server for receiving task activation/deactivation/modification from ADMF
    - X1 Client for sending notifications and status updates to ADMF
    - Full XSD schema types from ETSI TS 103 221-1 and TS 103 280
  - **X2 Interface** (IRI delivery): Binary TLV encoding for SIP signaling events
    - SIP INVITE/ACK/BYE/CANCEL/REGISTER message encoding
    - Party information, correlation IDs, and timestamp attributes
  - **X3 Interface** (CC delivery): Binary TLV encoding for RTP content
    - RTP payload encoding with sequence numbers and timestamps
    - SSRC and payload type attributes per ETSI TS 103 221-2
  - **LI Manager**: Central coordinator for task lifecycle, filter mapping, and packet routing
  - **Task Registry**: ETSI X1 lifecycle state machine (pending → active → removed)
  - **Filter Manager**: Maps LI task XIDs to lippycat filter IDs for packet correlation
  - **Delivery Client**: Async delivery with connection pooling, batching, and backpressure
  - **Destination Manager**: Connection pool with health monitoring and automatic reconnection
- **PhoneNumberMatcher** (`internal/pkg/phonematcher/`): LI-optimized phone number matching
  - Bloom filter pre-check for fast negative lookups
  - Suffix-based matching for E.164 number normalization
  - Support for national/international format variations
- **SIPURI filter type** (`internal/pkg/hunter/`): Full SIP URI matching for LI targets
  - GPU-accelerated Aho-Corasick matching for SIPURI patterns
  - Named automaton support for per-filter pattern groups
- **IP filter optimizations**: O(1) hash map for exact IPs, O(prefix) radix trie for CIDRs
- **LI build targets**: `make build-li`, `make processor-li`, `make tap-li`, `make tap-li-cuda`
- **Comprehensive LI documentation**: Integration guide, certificate management, architecture docs

### Changed
- Hunter application filter extended with per-packet filter ID tracking for LI correlation
- Processor packet pipeline includes LI Manager integration for matched packet delivery
- GPU backends (CUDA, OpenCL, SIMD) support named automata for LI filter groups

### Security
- **BREAKING**: Migrated RSA signature scheme from PKCS#1 v1.5 to PSS in proxy authorization tokens
  - RSA-PSS provides provable security under the random oracle model
  - Uses SHA-256 hash and salt length equal to hash length
  - **Note**: Tokens signed with previous versions will not verify; rolling restarts required during upgrade

## [0.4.0] - 2025-12-21

### Added
- **Standalone tap capture mode** (`lc tap`): Single-machine capture with processor capabilities
  - `lc tap` - General packet capture with TUI serving
  - `lc tap voip` - VoIP-specific capture with per-call PCAP writing
  - Local packet source using gopacket for direct interface capture
  - Local filter target for protocol-specific packet filtering
  - Optional upstream forwarding to central processor nodes
  - TUI clients can connect for remote monitoring
  - Supports all processor features: per-call PCAP, command hooks, TLS/mTLS
- **PacketSource/FilterTarget interfaces** (`internal/pkg/processor/source/`, `internal/pkg/processor/filtering/`): Abstraction layer for packet ingestion and filtering
  - `PacketSource` interface for unified packet ingestion (local capture, gRPC hunters)
  - `FilterTarget` interface for protocol-specific packet filtering
  - `LocalSource`: Direct interface capture using gopacket
  - `GRPCSource`: Receives packets from distributed hunter nodes
  - `LocalTarget`: Local packet filtering with VoIP call tracking
  - `HunterTarget`: Forwards filtered packets to processor nodes

## [0.3.3] - 2025-12-20

### Added
- **Aho-Corasick pattern matching engine** (`internal/pkg/ahocorasick/`): High-performance multi-pattern string matching
  - Core Aho-Corasick automaton with failure links and output links
  - `MultiModeAC`: Separate automata per pattern type (literal, prefix, suffix, contains)
  - `BufferedMatcher`: Lock-free concurrent reads with atomic automaton swapping
  - `DenseAC`: SIMD-friendly state layout for cache-efficient traversal
  - AMD64-optimized matching with prefetch hints
  - Algorithm selection via `--pattern-algorithm` flag: `auto`, `ahocorasick`, `linear`
- **Wildcard pattern matching**: Support for `*` wildcards in SIP user patterns
  - `*suffix` - match users ending with suffix
  - `prefix*` - match users starting with prefix
  - `*contains*` - match users containing substring
  - Configurable via `--sipuser` flag (e.g., `--sipuser 'alice*,*bob,*test*'`)
- **GPU backend integration**: AC-based pattern matching in GPU acceleration path
  - SIMD backend uses DenseAC for vectorized matching
  - CUDA backend integration for GPU-accelerated filtering
  - Automatic algorithm selection based on pattern count thresholds

### Changed
- Hunter application filter migrated from linear search to Aho-Corasick matching
- SIP user filtering now uses unified pattern matching infrastructure
- GPU acceleration path uses AC-based matching for improved throughput

## [0.3.2] - 2025-12-19

### Added
- **Filter management CLI commands**: Remote filter management on processor nodes
  - `lc list filters`: List all filters on a processor
  - `lc show filter <id>`: Show details of a single filter by ID
  - `lc set filter`: Create or update filters (inline or batch from file)
  - `lc rm filter <id>`: Delete filters (single or batch from file)
  - JSON output for scripting/automation
  - Config file support for `remote.processor` and `remote.tls.*` settings
  - TLS/mTLS connection support
  - Auto-generated UUIDs for new filters
  - Batch operations via `--file` flag
  - Proper exit codes (0=success, 1=general, 2=connection, 3=validation, 4=not found)
- **Shared filter types package**: `internal/pkg/filtering` with types, parser, validation, and conversion utilities
- **Filter client package**: `internal/pkg/filterclient` with gRPC client for filter operations

### Security
- **Go 1.24.11**: Updated Go version for security fixes in CI

## [0.3.1] - 2025-12-19

### Added
- **PCAP command hooks for processor node**: Execute custom commands when PCAP files are written
  - `--pcap-command`: Run command when any PCAP file is completed (supports `%pcap%` placeholder)
  - `--voip-command`: Run command when VoIP call PCAP is completed (supports `%pcap%`, `%callid%`, `%dirname%` placeholders)
  - Call completion monitor tracks call state and triggers hooks after configurable idle timeout
  - Async command execution with configurable timeout and concurrent execution limits
  - Comprehensive integration tests for command hook workflows

## [0.3.0] - 2025-12-19

### Breaking Changes
- **CLI restructured to verb-object pattern**: Commands reorganized for consistency and discoverability
  - `lc tui` → `lc watch` (defaults to live mode)
  - `lc tui --remote` → `lc watch remote`
  - `lc interfaces` → `lc list interfaces`
  - `lc debug <subcommand>` → `lc show <subcommand>`
- **TUI package relocated**: `cmd/tui/` moved to `internal/pkg/tui/` (internal implementation detail)

### Added
- **New command structure**: `lc [verb] [object]` pattern for improved discoverability
  - `lc watch` - Interactive TUI monitoring (live, file, remote modes)
  - `lc list` - Resource listing (interfaces, future: hunters, calls)
  - `lc show` - Diagnostics display (health, metrics, alerts, buffers, streams, config, summary)
- **Multi-level processor hierarchy**: Complete support for hierarchical processor deployments
  - Real-time topology subscriptions with streaming updates
  - Recursive routing for deep processor chains
  - Authorization token verification for cross-processor operations
  - Chain error context propagation
  - Audit logging for multi-level management operations
  - Network partition handling with automatic recovery
  - Graceful shutdown coordination across hierarchy
  - Cycle detection and hierarchy depth limits
  - Topology cache with configurable TTL
  - Retry logic for proxied operations with exponential backoff
- **Virtual interface feature**: Replay PCAP files through virtual network interfaces
  - TUN/TAP device support for packet injection
  - Network namespace isolation for security
  - Privilege dropping after interface creation
  - Packet timing replay for realistic traffic simulation
  - Integration with `lc sniff` and `lc process` commands
- **BPF filter optimization**: VoIPFilterBuilder for efficient kernel-level packet filtering
  - `--udp-only` flag for UDP-only VoIP capture (reduces CPU on TCP-heavy networks)
  - `--sip-port` flag for custom SIP port filtering
- **Per-call PCAP writing**: Separate SIP and RTP files per VoIP call
- **Auto-rotating PCAP writing**: Time/size-based rotation for non-VoIP traffic
- **gRPC connection pooling**: Improved performance for processor-to-processor communication
- **API key authentication**: Secure distributed deployments with `--api-key` flag
- **Protocol analyzer framework**: Compile-time protocol module registration system
- **TUI enhancements**:
  - Hierarchical processor tree view with upstream tracking
  - Hierarchy depth indicators and latency estimates
  - SSH packet coloring (solarized magenta)
  - Solarized colors for VPN, ARP, and ICMPv6 protocols
  - Filter box styling with solarized violet
  - Date display in all timestamps
  - Adaptive packet display throttling for improved responsiveness
  - Chain error handling with unreachable status display
  - Hierarchical hunter subscription management
- **Hunter improvements**:
  - Automatic BPF filter for processor communication port exclusion

### Changed
- **Processor refactoring**: Split monolithic processor.go into focused modules
  - Core infrastructure, upstream handling, enrichment, and manager packages
  - Improved separation of concerns and testability
- **RemoteCapture client refactoring**: Extracted conversion, subscriptions, and streaming logic
- **Constants consolidation**: Magic numbers moved to dedicated constants package
- **TUI navigation**: Eliminated code duplication across components
- **Error handling policy**: Comprehensive guidelines established in CONTRIBUTING.md

### Fixed
- **Race conditions**: Fixed PCAP writer and shutdown race conditions in VoIP package
- **Deep copy safety**: Proper deep copies in GetCalls() to prevent concurrent modification
- **gRPC pool stability**: Added nil checks to prevent panics in pool operations
- **Processor routing**: Fixed multi-level processor routing with upstream processor ID
- **Topology events**: Proper publishing on processor registration
- **Flow context**: Fixed concurrent map write crash in detector package
- **TUI filters**: Remove filters by insertion order, not selectivity order
- **TUI tree view**: Correct navigation with hierarchical processor ordering
- **ARP display**: Full ARP info display for remote capture
- **Settings input**: Limited field widths to reasonable size
- **Config loading**: Restore TLS settings from config file when flags not provided

### Security
- **PCAP file permissions**: Changed from 0644 to 0600
- **Silent error suppression**: Eliminated in Close() operations

### Performance
- **Zero-copy optimizations**: sync.Pool usage in virtual interface package
- **Adaptive throttling**: TUI packet display responsiveness improvements

### Testing
- **Test coverage improvements**:
  - processor: 31.4% → 62.6% (+31.2%)
  - capture: 30.3% → 60.4% (+30.1%)
  - remotecapture: 12.2% → 23.0% (+10.8%)
- **Load tests**: High packet rates (10K pps), concurrent hunters (100), subscribers (100)
- **Integration tests**: Multi-level topology, remotecapture client, CI-ready test suite
- **Protocol analyzer tests**: Comprehensive test suite for module framework

## [0.2.9] - 2025-10-21

### Added
- **SIP call correlation engine**: Track and correlate SIP messages across multiple transactions with Call-ID, tag, and Via branch tracking
- **Correlated call details panel in TUI**: View all related SIP messages for a call with dialog state awareness
- **VoIP call aggregation in live capture mode**: Real-time call state tracking in TUI
- **PCAP file writing**: Add `--write-file` flag to sniff command for saving captured traffic
- **Capability-based filter distribution**: Hunters advertise capabilities (VoIP, generic) for intelligent filter routing
- **Hunter mode badges in TUI**: Visual indicators showing hunter capabilities in nodes view and subscription selector
- **Hot-reload for application filters**: Update BPF filters without restarting packet capture
- **Hot-swap for hunter subscriptions**: Switch monitored hunters without TUI reconnection
- **Nuclear-proof resilience features**: Enhanced reconnection logic, keepalive tuning, and automatic retry mechanisms
- **Context-aware tab-specific keybindings**: Dynamic footer shows relevant shortcuts based on active tab and state
- **Color-coded tabs with active indicators**: Improved visual navigation in TUI
- **File dialog enhancements**: Wraparound navigation, page keys, responsive height
- **SIP tag tracking**: Enhanced filtering and correlation capabilities

### Changed
- Refactored VoIPFilter to ApplicationFilter for protocol-agnostic filtering
- Improved TUI styling with Solarized colors and better readability
- Optimized TUI styles and consolidated keybind hints
- Modernized codebase using Go 1.24 builtins (max, slices.Delete)
- Updated dependencies for improved resilience
- Reorganized documentation structure

### Fixed
- **Streaming save**: Write both buffered and new packets correctly in TUI
- **TCP stream handling**: Flush and close TCP streams in offline mode for proper SIP file writing
- **Content-based SIP detection**: Per-call file output with accurate protocol detection
- **Offline mode detection**: Use RunOffline for PCAP file processing
- **Structured logging**: Send logs to stderr instead of stdout
- **Hunter packet statistics**: Properly track packet counts in processor
- **Processor deadlock**: Resolve heartbeat monitoring race condition
- **Filter hot-reload**: Improve behavior during processor restart
- **VoIP hunter mode**: Drop non-VoIP traffic appropriately
- **Build tags**: Fix VoIP writer stub inclusion in tests
- **Hunter shutdown**: Improve cleanup, reconnection, and type safety
- **Version bump script**: Fix sed regex escaping for asterisks and special characters

## [0.2.8] - 2025-10-16

### Added
- **Enhanced TUI call view navigation**
  - Added mouse click support for call selection
  - Added keyboard shortcuts: home/end (g/G), page up/down for navigation
  - Improved call sorting by timestamp and call ID

### Changed
- **TUI calls view improvements**
  - Extract clean SIP URIs (remove display names and tag parameters)
  - Improved column width allocation for better readability
  - From/To columns now 15-40 chars (was 10-20)
  - CallID column dynamically expands to use available space
  - Consistent layout calculations with packet list component

### Fixed
- **Test suite stability**
  - Fixed `TestCallAggregator_CallDuration` by adding packet timestamps
  - Updated `TestJanitorLoopCleanup` for ring-buffer-based cleanup
- **Security hardening**
  - Changed debug log file permissions from 0644 to 0600
  - Added error handling for file close operations
  - Added validation for safe RTP integer conversions
  - Reduced gosec security issues from 21 to 8 (remaining are in generated code)

## [0.2.7] - 2025-10-16

### Added
- **Interfaces command** for hunter build variant
  - Hunter nodes can now list available network interfaces

### Changed
- **Major architecture refactoring** for improved maintainability
  - Hunter package: Extracted connection management, packet forwarding, filtering, stats, and capture to sub-packages
  - Processor package: Extracted core infrastructure, upstream, enrichment, and managers to dedicated packages
  - Improved separation of concerns and testability
- **TUI improvements**
  - Changed remote capture indicator from "REMOTE" to "STREAMING" for clarity
  - Improved settings interface selection UX
  - Added space after info toast icon for better visual spacing

### Fixed
- **Hunter stability fixes**
  - Eliminated double-buffering causing packet drops
  - Removed duplicate stream receiver causing deadlock
- **Processor reliability**
  - Send DELETE filter messages to hunters when filter scope narrows
  - Resolved deadlock in hunter heartbeat processing
  - Fixed deadlock in hunter.Manager
- **Test improvements**
  - Eliminated shared state in mode factory test
  - Added build tag to connection TLS tests

### Performance
- **TUI rendering optimization**
  - Optimized packet list and details panel rendering for better responsiveness

## [0.2.6] - 2025-10-12

### Added
- **FileDialog modal component** for file/directory operations
  - Unified file picker for PCAP save and nodes YAML selection
  - Vim-style navigation with real-time filtering
  - Inline folder creation and details toggle
  - Four input modes: Navigation, Filename, Filter, CreateFolder
- **Toast notification system**
  - Non-blocking queue-based notifications
  - Four types: Success, Error, Info, Warning
  - Auto-dismiss with configurable durations
  - Click-to-dismiss functionality

### Documentation
- Added TUI architecture documentation to CLAUDE.md
  - FileDialog and Toast design principles
  - Version management instructions

## [0.2.5] - 2025-10-12

### Added
- **Dynamic filter management** with hunter target selection
  - Multi-select modal for choosing which hunters a filter applies to
  - Press 's' on Targets field to open hunter selector
  - Keyboard shortcuts: Space (toggle), 'a' (all), 'n' (none)
  - Filters can target all hunters or specific subset

### Changed
- **Improved filter form consistency**
  - Enter key always saves the form (consistent behavior)
  - Separate 's' key for opening hunter selector
  - Clear hints and footer instructions

### Fixed
- **Makefile test targets** now include `-tags all` flag
  - Required for project's build tag architecture
  - Tests now pass reliably with `make test`
- **TCP security tests** no longer flaky with `-count=3`
  - Reset global metrics state for clean test isolation

## [0.2.4] - 2025-10-11

### Added
- **Hunter subscription management** in TUI
  - Press 's' to select specific hunters to subscribe to
  - Press 'd' to unsubscribe from hunters or remove processors
  - Multi-select interface with visual feedback
  - Selective packet filtering at processor level
- **TLS/mTLS support** for distributed mode
  - Encrypted gRPC connections between all nodes
  - Mutual authentication with client certificates
  - Per-node TLS configuration in nodes.yaml
  - Self-signed certificate generation for testing
- **ListAvailableHunters management API**
  - Query processor for connected hunters
  - Used by TUI hunter selector modal

### Fixed
- **Packet subscription and protobuf serialization** issues
  - Fixed Proto3 empty list serialization with `has_hunter_filter` field
  - Fixed concurrent protobuf serialization race condition with `proto.Clone()`
  - Unsubscribe from hunters now works correctly
- **Hunter reconnection resilience**
  - Hunter reconnects within ~100ms when processor restarts
  - Added cleanup timeout to prevent deadlock
  - Fixed packet buffer preservation on reconnection
  - Reduced connection monitoring interval from 10s to 100ms

### Changed
- **Flow control improvements**
  - Removed subscriber backpressure from affecting hunters
  - TUI client drops no longer pause hunter packet capture
  - Per-subscriber buffering for slow clients
- **TUI visual improvements**
  - Fixed hunter selector modal styling
  - Prevented cursor drift in scrolling
  - Added vim-style navigation (j/k)
  - Hover-based mouse scrolling

### Documentation
- Improved TLS certificate generation documentation with SAN requirements

### Removed
- Obsolete subscriber backpressure tests

## [0.2.3]

### Added
- VoIP/SIP analysis (UDP and TCP)
- Distributed capture architecture with build-tagged specialized binaries
- SIMD optimizations and optional GPU acceleration
- TUI and CLI interfaces
- Protocol detection with signature-based matching
