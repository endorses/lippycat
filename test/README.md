# lippycat Integration Tests

This directory contains comprehensive end-to-end integration tests for the lippycat distributed packet capture system.

## Overview

The integration tests validate critical functionality across the hunter-processor distributed architecture, including failure scenarios, high-volume packet processing, and protocol detection accuracy.

## Test Categories

### 1. Hunter-Processor Integration Tests (`integration_test.go`)

Tests for distributed packet capture and processing between hunter and processor nodes.

#### Test Cases

- **TestIntegration_HunterProcessorBasicFlow**: Validates basic packet flow from hunter to processor
  - Hunter registration
  - Packet batch streaming
  - Stream acknowledgments
  - Stats tracking

- **TestIntegration_HunterCrashRecovery**: Tests hunter crash and reconnection
  - Simulates abrupt hunter disconnection
  - Validates processor handles disconnection gracefully
  - Tests successful reconnection and continued operation

- **TestIntegration_ProcessorRestartWithConnectedHunters**: Tests processor restart scenario
  - Multiple hunters connected
  - Processor shutdown and restart
  - Hunter reconnection after processor restart
  - Packet flow restoration

- **TestIntegration_NetworkPartition**: Tests network partition handling
  - Simulates network partition via connection close
  - Validates disconnection detection
  - Tests recovery after partition heals

- **TestIntegration_HighVolume**: Stress test with high packet rates
  - Sends 10,000 packets at ~10k packets/second
  - Validates throughput (target: >5k packets/sec)
  - Verifies packet loss is <20%

- **TestIntegration_MultipleHuntersSimultaneous**: Tests concurrent hunter operations
  - 5 hunters sending simultaneously
  - Each hunter sends 1,000 packets
  - Validates processor handles concurrent streams
  - Verifies packet deduplication and ordering

- **TestIntegration_JumboFrames**: Tests large packet handling
  - Creates 9000-byte jumbo frame packets
  - Validates gRPC message size limits
  - Ensures no truncation or corruption

### 2. Protocol Detection Integration Tests (`protocol_detection_integration_test.go`)

Tests for protocol detection accuracy, false positive rates, and edge cases.

#### Test Cases

- **TestIntegration_ProtocolDetectionFalsePositiveRate**: Measures false positive rate
  - Tests with 1,000 random data packets
  - Validates false positive rate <5%
  - Ensures detector doesn't over-classify random data

- **TestIntegration_MultiProtocolFlows**: Tests multi-protocol scenarios
  - VPN over HTTP
  - SIP with embedded RTP
  - TLS encrypted database
  - DNS over HTTPS
  - Mixed protocols in sequence

- **TestIntegration_MalformedPackets**: Tests detector resilience
  - Truncated IP headers
  - Invalid SIP methods
  - Malformed HTTP headers
  - Truncated TLS handshakes
  - Invalid RTP versions
  - Oversized DNS queries
  - Zero-length payloads
  - Corrupted checksums
  - Validates no panics on malformed input

- **TestIntegration_ProtocolDetectionAccuracy**: Tests detection accuracy
  - SIP INVITE (target: 0.8 confidence)
  - HTTP GET (target: 0.9 confidence)
  - TLS ClientHello (target: 0.9 confidence)
  - DNS Query (target: 0.8 confidence)
  - SSH Banner (target: 0.9 confidence)

## Running the Tests

### Run All Integration Tests

```bash
go test -v ./test/... -run TestIntegration
```

### Run Specific Test Category

```bash
# Hunter-processor tests only
go test -v ./test/ -run TestIntegration_Hunter

# Protocol detection tests only
go test -v ./test/ -run TestIntegration_Protocol
```

### Skip Integration Tests (Short Mode)

```bash
go test -short ./test/...
```

All integration tests check `testing.Short()` and skip when running in short mode.

### Run with Timeout

```bash
# Default timeout is sufficient for most tests
go test -v ./test/... -run TestIntegration -timeout 5m
```

## Test Requirements

### Prerequisites

- Go 1.21 or later
- Network access (for gRPC tests)
- Available ports: 50051-50057 (used by test processors)

### Dependencies

All dependencies are standard lippycat dependencies:
- `github.com/stretchr/testify` - assertions
- `google.golang.org/grpc` - gRPC client/server
- `github.com/google/gopacket` - packet manipulation

## Architecture

### Test Helpers

**startTestProcessor(ctx, addr)**: Creates and starts a test processor instance
- Minimal configuration for testing
- Background goroutine execution
- Returns processor instance for stats/control

**connectHunter(ctx, addr, hunterID)**: Connects a simulated hunter to processor
- Registers hunter with processor
- Creates bidirectional gRPC stream
- Returns connection and stream for packet sending

**createTestBatch(hunterID, sequence, numPackets)**: Creates synthetic packet batches
- Generates realistic packet structures
- Includes metadata and stats
- Configurable size and content

**createSyntheticPacket(index)**: Creates individual test packets
- Ethernet/IP/UDP/payload structure
- Unique identifiers per packet
- Valid checksums and headers

### Mock Infrastructure

**MockPacketSource**: Simulates packet capture source
- In-memory packet queue
- Controllable packet generation
- Used for isolated testing

## Test Coverage Goals

Integration tests are designed to complement unit tests by validating:

1. **End-to-end flows**: Full request/response cycles
2. **Failure scenarios**: Crashes, timeouts, partitions
3. **Performance**: Throughput and resource usage
4. **Concurrency**: Multi-node coordination
5. **Edge cases**: Malformed input, extreme loads

## Current Test Coverage

### CODE_REVIEW.md Recommendation 20

These integration tests implement recommendation 20 from the code review:

> **20. Write integration tests** - E2E VALIDATION - 1 week
> - Hunter failure scenarios
> - High volume tests (10,000 packets/second sustained)
> - Protocol detection accuracy tests
> - Multi-hunter coordination tests

**Status**: ✅ IMPLEMENTED

### Test Statistics

- **Hunter/Processor Tests**: 7 test cases
- **Protocol Detection Tests**: 4 test cases
- **TLS Integration Tests**: 6 test cases (NEW)
- **Filter Distribution Tests**: 5 test cases (NEW)
- **Performance Benchmarks**: 5 benchmarks (NEW)
- **Total Assertions**: 100+
- **Failure Scenarios**: 10+ (crashes, partitions, restarts, TLS failures, filter distribution failures)
- **Docker Compose Services**: 7 (processors, hunters, generator, client)

## Known Limitations

1. **Network Tests**: Require available localhost ports (50051-50057)
2. **Timing**: Tests use `time.Sleep` for synchronization (brittle on slow systems)
3. **RTP Detection**: Synthetic RTP packets may not match detector expectations (test disabled)
4. **Real Traffic**: Tests use synthetic packets, not real network captures

## New Features (2025-10-10)

### ✅ TLS Integration Tests (`tls_integration_test.go`)
Comprehensive TLS security testing:
- **Mutual TLS Authentication**: Full mTLS with client certificates
- **TLS 1.3 Enforcement**: Validates TLS version requirements
- **Certificate Validation**: Tests invalid/self-signed cert rejection
- **Server Name Verification**: SNI validation testing
- **Production Mode Enforcement**: Tests security guards

**Run TLS tests:**
```bash
go test -v ./test/ -run TestIntegration_TLS
```

### ✅ Filter Distribution Tests (`filter_distribution_integration_test.go`)
Dynamic filter management testing:
- **Single Hunter**: Filter push to individual hunter
- **Multiple Hunters**: Broadcast filters to hunter groups
- **Update/Remove**: Filter lifecycle management
- **Circuit Breaker**: Failed hunter handling
- **Priority Ordering**: Filter priority enforcement

**Run filter tests:**
```bash
go test -v ./test/ -run TestIntegration_FilterDistribution
```

### ✅ Docker Compose Environment (`docker-compose.yml`)
Isolated multi-node testing infrastructure:
- **Multiple Processors**: Primary + upstream hierarchical setup
- **Multiple Hunters**: 3 hunter nodes with TLS
- **Packet Generator**: Synthetic traffic generation
- **TUI/CLI Client**: Interactive testing interface
- **Network Isolation**: Dedicated test network

**Quick start:**
```bash
cd test
./testcerts/generate_test_certs.sh
docker-compose up --build
```

See [DOCKER_TESTING.md](DOCKER_TESTING.md) for detailed Docker Compose usage.

### ✅ Performance Benchmarks (`benchmark_test.go`)
Comprehensive performance testing:
- **Packet Throughput**: Measures packets/sec and MB/sec
- **End-to-End Latency**: Measures µs per packet
- **Filter Distribution**: Measures distribution speed
- **Concurrent Hunters**: Tests scalability
- **Protocol Detection**: Detection performance

**Run benchmarks:**
```bash
go test -v ./test/ -bench=. -benchmem -benchtime=10s
```

### ✅ CI/CD Integration (`.github/workflows/integration-tests.yml`)
Automated testing pipeline:
- **Unit Tests**: With race detection and coverage
- **Integration Tests**: All TestIntegration_* tests
- **Docker Integration**: Multi-node Docker testing
- **Benchmarks**: Performance regression detection
- **Security Scan**: gosec + govulncheck
- **Lint**: golangci-lint + gofmt checks

### ✅ Test Certificate Generation (`testcerts/`)
Automated TLS certificate generation:
- **CA Certificate**: Test certificate authority
- **Server Certificates**: Processor + upstream
- **Client Certificates**: Hunter + TUI client
- **10-Year Validity**: Long-lived test certs

**Generate certificates:**
```bash
cd test/testcerts
./generate_test_certs.sh
```

## Future Enhancements

1. **PCAP Replay**: Use real PCAP files for more realistic testing (partially implemented via Docker generator)
2. **Chaos Engineering**: Add deliberate failures (network delays, packet loss)
3. **Load Testing**: Extend high-volume tests to longer durations
4. **Metrics Validation**: Prometheus/OpenTelemetry metrics testing

## Debugging

### Verbose Logging

```bash
# Enable debug logging for test runs
LIPPYCAT_LOG_LEVEL=debug go test -v ./test/...
```

### Isolate Failing Test

```bash
# Run single test with full output
go test -v ./test/ -run TestIntegration_HunterCrashRecovery
```

### Port Conflicts

If tests fail with "address already in use":

```bash
# Find process using port
lsof -i :50051

# Kill process or wait for it to release
kill -9 <PID>
```

## Contributing

When adding integration tests:

1. **Use `testing.Short()`**: Skip in short mode
2. **Clean Up Resources**: Defer connection/processor cleanup
3. **Use Unique Ports**: Avoid conflicts between tests
4. **Document Scenarios**: Clear test names and comments
5. **Validate Stats**: Check processor stats after operations
6. **Add Timeout**: Set reasonable test timeouts

## Related Documentation

- [Code Review](../CODE_REVIEW.md) - Original integration test requirements
- [Architecture](../CLAUDE.md) - System architecture overview
- [Docker Testing](DOCKER_TESTING.md) - Docker Compose multi-node testing guide
- [Test Certificates](testcerts/README.md) - TLS certificate generation
- [Unit Tests](../internal/pkg/*/README.md) - Package-specific unit tests
- [Security](../docs/SECURITY.md) - Production TLS setup

## Test Coverage Matrix

| Test Category | Test Files | Coverage |
|---------------|-----------|----------|
| Hunter/Processor Integration | `integration_test.go` | Basic flow, crash recovery, network partition, high volume, multiple hunters, jumbo frames |
| Protocol Detection | `protocol_detection_integration_test.go` | False positives, multi-protocol, malformed packets, accuracy |
| TLS Security | `tls_integration_test.go` | mTLS, TLS 1.3, cert validation, SNI, production mode |
| Filter Distribution | `filter_distribution_integration_test.go` | Single/multi-hunter, update/remove, circuit breaker, priority |
| Performance | `benchmark_test.go` | Throughput, latency, filter distribution, concurrent hunters |
| Docker Multi-Node | `docker-compose.yml` | Hierarchical processors, TLS-enabled, packet generation |

## Quick Reference Commands

```bash
# Run all integration tests
go test -v ./test/... -run TestIntegration

# Run specific category
go test -v ./test/ -run TestIntegration_TLS
go test -v ./test/ -run TestIntegration_FilterDistribution

# Run with race detector
go test -v -race ./test/... -run TestIntegration

# Run benchmarks
go test -v ./test/ -bench=. -benchmem -benchtime=10s

# Docker Compose quick start
cd test
./testcerts/generate_test_certs.sh
docker-compose up --build

# Docker Compose cleanup
cd test
docker-compose down -v
```
