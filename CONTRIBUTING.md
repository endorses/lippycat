# Contributing to lippycat

Thank you for your interest in contributing to lippycat! This document provides guidelines and best practices for contributing to the project.

## Table of Contents

- [Code Style](#code-style)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Messages](#commit-messages)

## Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` to format all Go code before committing
- Run `golangci-lint` to check for common issues
- Keep functions focused and under 50 lines when possible
- Add comments for exported functions and types (godoc format)

## Error Handling

### General Principles

1. **Never silently ignore errors** - All errors should be handled appropriately
2. **Provide context** - Wrap errors with additional context using `fmt.Errorf(..., %w, err)`
3. **Use structured logging** - Include relevant context fields when logging errors
4. **Fail fast** - Return errors early rather than continuing with invalid state
5. **Consistent patterns** - Follow established patterns for similar error scenarios
6. **Observable failures** - Ensure all errors are either returned, logged, or both

### Error Handling Decision Tree

Use this decision tree to determine how to handle errors:

```
┌─────────────────────────────┐
│  Error Occurred?            │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Can you return error?       │◄─── Is this a function that returns error?
└──────┬──────────────────┬───┘
       │YES               │NO
       ▼                  ▼
┌──────────────────┐   ┌────────────────────────┐
│ Is this cleanup  │   │ Shutdown/destructor?   │
│ during error     │   └──────┬─────────────────┘
│ handling?        │          │YES
└──┬──────────┬────┘          │
   │YES       │NO             ▼
   ▼          ▼          ┌────────────────────┐
┌──────┐  ┌──────┐      │ LOG error with     │
│ LOG  │  │RETURN│      │ structured context │
│ then │  │error │      │ (can't return)     │
│RETURN│  │with  │      └────────────────────┘
│primary│  │context│
│error │  │      │
└──────┘  └──────┘

Special Cases:
├─ Test code cleanup:        Can use _ (blank identifier)
├─ Background goroutines:    LOG + increment error metric
├─ User input validation:    RETURN with clear, actionable message
└─ Critical path (I/O, net): RETURN immediately with context
```

### When to Log vs. Return Errors

| Scenario | Action | Example |
|----------|--------|---------|
| **Function returns `error`** | Return error with context | `return fmt.Errorf("failed to open: %w", err)` |
| **Cleanup during error handling** | Log error, return primary error | See "Error Path Cleanup" pattern below |
| **Shutdown/Close methods** | Log error (cannot return) | See "Shutdown/Cleanup Paths" pattern below |
| **Background goroutines** | Log error + increment metric | `logger.Error("background task failed", "error", err)` |
| **User input validation** | Return error with clear message | `return fmt.Errorf("invalid port %d: must be 1-65535", port)` |
| **Critical path (I/O, network)** | Return error immediately | `return fmt.Errorf("failed to write PCAP: %w", err)` |
| **Test cleanup** | Can use `_` (blank identifier) | `defer func() { _ = f.Close() }()` |

### Close() Error Handling

When closing resources (files, connections, etc.), follow these patterns:

#### 1. Error Path Cleanup (Defer in Error Handling)

When closing resources in error handling paths where you're already returning an error, **log the close error** but don't override the primary error:

```go
file, err := os.Create(filename)
if err != nil {
    return fmt.Errorf("failed to create file: %w", err)
}

// If something fails later...
if err := doSomething(); err != nil {
    // Log close error but return the primary error
    if closeErr := file.Close(); closeErr != nil {
        logger.Error("Failed to close file during error cleanup",
            "error", closeErr,
            "file", filename)
    }
    return fmt.Errorf("operation failed: %w", err)
}
```

#### 2. Shutdown/Cleanup Paths (No Return Value)

In shutdown/cleanup methods where you can't return an error (e.g., `Shutdown()`, `Close()`), **always log close errors**:

```go
func (m *Manager) Shutdown() {
    if m.conn != nil {
        if err := m.conn.Close(); err != nil {
            logger.Error("Failed to close connection during shutdown",
                "error", err,
                "processor", m.config.ProcessorAddr)
        }
    }
}
```

#### 3. Normal Path (Success Case)

In the normal success path, **return close errors** to the caller:

```go
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }
    defer func() {
        if err := file.Close(); err != nil {
            logger.Error("Failed to close file", "error", err, "file", filename)
        }
    }()

    // Process file...
    return nil
}
```

Or better, handle it explicitly:

```go
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }

    // Process file...

    if err := file.Close(); err != nil {
        return fmt.Errorf("failed to close file: %w", err)
    }
    return nil
}
```

#### 4. Test Cleanup

In test code, you may use blank identifier for cleanup, but consider logging in production-like tests:

```go
func TestSomething(t *testing.T) {
    file, err := os.Create("test.txt")
    require.NoError(t, err)
    defer func() {
        _ = file.Close() // Acceptable in tests
        _ = os.Remove("test.txt")
    }()

    // Test code...
}
```

### Structured Logging Patterns

Use structured logging with relevant context fields. The logger uses key-value pairs for structured data.

#### Basic Pattern

```go
// Good: Structured logging with context
logger.Error("Failed to close file during error cleanup",
    "error", err,
    "file", filepath,
    "operation", "rotation")

// Bad: Unstructured logging (printf-style)
logger.Error("close failed: %v", err)
```

#### Common Context Fields

Include relevant context fields based on the operation:

| Operation Type | Recommended Fields | Example |
|----------------|-------------------|---------|
| File operations | `"file"`, `"operation"`, `"error"` | `logger.Error("write failed", "error", err, "file", path, "operation", "pcap_write")` |
| Network operations | `"address"`, `"port"`, `"protocol"`, `"error"` | `logger.Error("connection failed", "error", err, "address", addr, "port", port)` |
| VoIP operations | `"call_id"`, `"operation"`, `"error"` | `logger.Error("SIP parse failed", "error", err, "call_id", callID)` |
| gRPC operations | `"method"`, `"peer"`, `"error"` | `logger.Error("RPC failed", "error", err, "method", "RegisterHunter", "peer", peer)` |
| Resource operations | `"resource"`, `"operation"`, `"count"`, `"error"` | `logger.Error("allocation failed", "error", err, "resource", "buffer", "count", n)` |

#### Logging Levels

Choose appropriate log levels:

```go
// DEBUG: Detailed diagnostic information
logger.Debug("Processing packet",
    "call_id", callID,
    "packet_type", pktType,
    "size", len(data))

// INFO: Normal operation milestones
logger.Info("Hunter connected",
    "hunter_id", hunterID,
    "address", addr)

// WARN: Potentially problematic situations (recoverable)
logger.Warn("Queue utilization high",
    "utilization", util,
    "threshold", threshold)

// ERROR: Error events (may allow continued operation)
logger.Error("Failed to write packet",
    "error", err,
    "file", filename,
    "call_id", callID)
```

#### Advanced Patterns

**Multiple related fields:**
```go
logger.Error("Failed to create PCAP writer",
    "error", err,
    "file", outputFile,
    "call_id", callID,
    "sip_from", fromUser,
    "sip_to", toUser,
    "timestamp", time.Now().Unix())
```

**Conditional logging (avoid log spam):**
```go
// Only log errors that aren't context.Canceled (expected during shutdown)
if err != nil && !errors.Is(err, context.Canceled) {
    logger.Error("Stream interrupted",
        "error", err,
        "processor", processorAddr)
}
```

**Performance-sensitive paths (use defer for consistency):**
```go
func processPackets(packets []Packet) error {
    start := time.Now()
    defer func() {
        logger.Debug("Batch processed",
            "count", len(packets),
            "duration_ms", time.Since(start).Milliseconds())
    }()

    // Process packets...
    return nil
}
```

### Error Wrapping

Always wrap errors with context using `%w` to preserve the error chain for `errors.Is()` and `errors.As()`.

#### Basic Wrapping

```go
// Good: Wrapped error with context
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to process packet: %w", err)
}

// Bad: Error string concatenation (loses error chain)
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to process packet: %v", err)
}

// Bad: Bare error without context
if err := doSomething(); err != nil {
    return err
}
```

#### Multi-Level Context Wrapping

Add context at each layer:

```go
// Layer 1: Low-level I/O
func writePacket(w io.Writer, pkt Packet) error {
    if _, err := w.Write(pkt.Data); err != nil {
        return fmt.Errorf("failed to write packet data: %w", err)
    }
    return nil
}

// Layer 2: PCAP writer
func (pw *PCAPWriter) WritePacket(pkt Packet) error {
    if err := writePacket(pw.writer, pkt); err != nil {
        return fmt.Errorf("failed to write PCAP packet (call_id=%s): %w", pw.callID, err)
    }
    return nil
}

// Layer 3: Call tracker
func (ct *CallTracker) RecordPacket(callID string, pkt Packet) error {
    writer := ct.getWriter(callID)
    if err := writer.WritePacket(pkt); err != nil {
        return fmt.Errorf("failed to record packet for call %s: %w", callID, err)
    }
    return nil
}
```

#### Error Chain Inspection

Use `errors.Is()` and `errors.As()` to check wrapped errors:

```go
import "errors"

// Check for specific error types
if err := processFile(filename); err != nil {
    if errors.Is(err, os.ErrNotExist) {
        logger.Info("File does not exist, creating new", "file", filename)
        // Handle missing file
    } else if errors.Is(err, os.ErrPermission) {
        logger.Error("Permission denied", "error", err, "file", filename)
        return fmt.Errorf("cannot access file: %w", err)
    } else {
        logger.Error("Unexpected error", "error", err, "file", filename)
        return err
    }
}

// Extract specific error types
var pathErr *os.PathError
if errors.As(err, &pathErr) {
    logger.Error("Path error",
        "error", err,
        "operation", pathErr.Op,
        "path", pathErr.Path)
}
```

#### Context-Rich Error Messages

Include relevant details in error messages:

```go
// Good: Context-rich error with relevant details
if port < 1 || port > 65535 {
    return fmt.Errorf("invalid port %d: must be in range 1-65535", port)
}

if err := conn.Dial(address); err != nil {
    return fmt.Errorf("failed to connect to processor at %s: %w", address, err)
}

// Bad: Generic error without context
if port < 1 || port > 65535 {
    return fmt.Errorf("invalid port")
}

if err := conn.Dial(address); err != nil {
    return fmt.Errorf("connection failed: %w", err)
}
```

### Error Categories

Categorize errors to determine appropriate handling:

#### 1. Critical Path Errors

**Definition:** Errors that prevent the primary operation from completing successfully.

**Handling:** Return to caller with full context.

**Examples:**
```go
// File I/O errors
file, err := os.Open(filename)
if err != nil {
    return fmt.Errorf("failed to open PCAP file %s: %w", filename, err)
}

// Network errors
conn, err := grpc.Dial(address, opts...)
if err != nil {
    return fmt.Errorf("failed to connect to processor at %s: %w", address, err)
}

// Resource allocation failures
buffer := make([]byte, size)
if len(buffer) != size {
    return fmt.Errorf("failed to allocate buffer of size %d: insufficient memory", size)
}
```

#### 2. Cleanup Errors

**Definition:** Errors that occur during resource cleanup (defer, shutdown paths).

**Handling:** Log with structured context, don't override primary error.

**Examples:**
```go
// File close during error cleanup
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }

    // Process file...
    if err := doSomething(); err != nil {
        // Log close error but return primary error
        if closeErr := file.Close(); closeErr != nil {
            logger.Error("Failed to close file during error cleanup",
                "error", closeErr,
                "file", filename)
        }
        return fmt.Errorf("processing failed: %w", err)
    }

    // Normal close path
    if err := file.Close(); err != nil {
        return fmt.Errorf("failed to close file: %w", err)
    }
    return nil
}

// Connection close during shutdown
func (m *Manager) Shutdown() {
    if m.conn != nil {
        if err := m.conn.Close(); err != nil {
            logger.Error("Failed to close connection during shutdown",
                "error", err,
                "address", m.address)
        }
    }
}
```

#### 3. Background Errors

**Definition:** Errors in background goroutines or non-critical operations.

**Handling:** Log and optionally increment error metrics.

**Examples:**
```go
// Background goroutine error
go func() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := m.cleanup(); err != nil {
                logger.Error("Background cleanup failed",
                    "error", err,
                    "operation", "janitor")
                // Optionally increment metric
                metrics.IncrementCounter("cleanup_errors_total")
            }
        case <-ctx.Done():
            return
        }
    }
}()

// Non-critical monitoring error (expected during shutdown)
if err := stream.Send(update); err != nil {
    if !errors.Is(err, context.Canceled) {
        logger.Error("Failed to send topology update",
            "error", err,
            "subscriber", subscriberID)
    }
}
```

#### 4. User Input Errors

**Definition:** Errors caused by invalid user input or configuration.

**Handling:** Return with clear, actionable message for the user.

**Examples:**
```go
// Invalid configuration
if cfg.Port < 1 || cfg.Port > 65535 {
    return fmt.Errorf("invalid port %d: must be in range 1-65535", cfg.Port)
}

if cfg.MaxConnections < 1 {
    return fmt.Errorf("invalid max_connections %d: must be at least 1", cfg.MaxConnections)
}

// Invalid CLI arguments
if len(args) == 0 {
    return fmt.Errorf("interface name required: use --interface <name> or see 'lc interfaces' for available interfaces")
}

// API validation errors
if hunterID == "" {
    return status.Errorf(codes.InvalidArgument, "hunter_id is required")
}

if req.BatchSize > MaxBatchSize {
    return status.Errorf(codes.InvalidArgument,
        "batch_size %d exceeds maximum %d", req.BatchSize, MaxBatchSize)
}
```

#### 5. Expected Errors (Non-Errors)

**Definition:** Conditions that are expected during normal operation and don't require error logging.

**Handling:** Handle silently or log at DEBUG level.

**Examples:**
```go
// Context cancellation during shutdown (expected)
if errors.Is(err, context.Canceled) {
    logger.Debug("Operation cancelled", "operation", "stream")
    return nil
}

// EOF during file read (expected)
if errors.Is(err, io.EOF) {
    logger.Debug("Reached end of file", "file", filename)
    return nil
}

// Empty result set (not an error)
calls := ct.GetActiveCalls()
if len(calls) == 0 {
    logger.Debug("No active calls")
    return nil
}
```

## Testing

### Unit Tests

- Write unit tests for all new functionality
- Use table-driven tests where appropriate
- Mock external dependencies (network, file system) when testing logic
- Aim for > 70% coverage on critical packages

### Integration Tests

- Add integration tests for multi-component features
- Test error paths and edge cases
- Use real PCAP files from `testdata/pcaps/` for VoIP tests

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests with race detector
go test -race ./...

# Run benchmarks
make bench
```

## Pull Request Process

1. **Create a feature branch** from `main`
2. **Write tests** for new functionality
3. **Update documentation** (README.md, CLAUDE.md, etc.)
4. **Run all tests** and ensure they pass
5. **Format code** with `gofmt` and `golangci-lint`
6. **Create pull request** with clear description
7. **Address review feedback** promptly

## Commit Messages

Follow the conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Build/tooling changes

Example:

```
fix(voip): resolve race condition in call tracker shutdown

- Add proper locking around file close operations
- Log close errors during shutdown paths
- Add test case for concurrent shutdown scenarios

Fixes #123
```

## Architecture Guidelines

### Build Tags

When adding new commands, use appropriate build tags:

```go
//go:build all || tui
```

See CLAUDE.md for details on the build tag architecture.

### Logger Usage

Always use the structured logger:

```go
import "github.com/yourusername/lippycat/internal/pkg/logger"

logger.Info("Operation successful", "count", count)
logger.Error("Operation failed", "error", err, "context", value)
logger.Debug("Debug info", "detail", detail)
```

### Concurrency

- Use mutexes for shared state
- Prefer channels for goroutine communication
- Always clean up goroutines (use context cancellation)
- Test concurrent code with `-race` detector

## Questions?

If you have questions about contributing, please:

1. Check existing documentation (README.md, CLAUDE.md files)
2. Search existing issues on GitHub
3. Open a new issue for discussion

Thank you for contributing to lippycat!
