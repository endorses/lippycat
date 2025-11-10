# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Load tests for processor package**: Performance tests for high packet rates (10K pps), many concurrent hunters (100), and many subscribers (100)
- **Benchmarks for processor package**: Throughput benchmarks for packet processing with various hunter configurations

### Improved
- **Test coverage improvements**:
  - processor: 31.4% → 62.6% (+31.2%)
  - capture: 30.3% → 60.4% (+30.1%)
  - remotecapture: 12.2% → 23.0% (+10.8%) in unit tests (integration tests in test/ provide full coverage)
- Comprehensive test coverage for capture package converter and snifferstarter modules
- Integration tests for remotecapture client in CI pipeline

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
