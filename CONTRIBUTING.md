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

### Error Logging Patterns

Use structured logging with relevant context:

```go
// Good: Structured logging with context
logger.Error("Failed to close file during error cleanup",
    "error", err,
    "file", filepath,
    "operation", "rotation")

// Bad: Unstructured logging
logger.Error("close failed: %v", err)
```

### Error Wrapping

Always wrap errors with context using `%w`:

```go
// Good: Wrapped error with context
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to process packet: %w", err)
}

// Bad: Error string concatenation
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to process packet: %v", err) // Loses error chain
}
```

### Error Categories

1. **Critical Path Errors**: Return to caller with full context
   - File I/O errors
   - Network errors
   - Resource allocation failures

2. **Cleanup Errors**: Log with structured context, don't fail operation
   - File close errors during cleanup
   - Connection close errors during shutdown
   - Resource deallocation errors

3. **Background Errors**: Log and increment metrics
   - Goroutine errors
   - Background task failures
   - Non-critical monitoring errors

4. **User Input Errors**: Return with clear, actionable message
   - Invalid configuration
   - Invalid CLI arguments
   - API validation errors

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
