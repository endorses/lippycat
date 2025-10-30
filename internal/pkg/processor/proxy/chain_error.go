package proxy

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ChainError represents an error that occurred in a multi-processor chain.
// It captures the full context of where and how the error occurred, including
// the processor path through the hierarchy and which processor failed.
//
// Example:
//
//	ChainError{
//	    ProcessorPath:     []string{"processor-a", "processor-b", "processor-c"},
//	    FailedProcessorID: "processor-c",
//	    ChainDepth:        2,
//	    UnderlyingError:   fmt.Errorf("connection refused"),
//	}
//
// Produces error message:
//
//	"chain error at processor-c (depth=2, path=processor-a -> processor-b -> processor-c): connection refused"
type ChainError struct {
	// ProcessorPath is the ordered list of processors in the chain from root to target.
	// Example: ["processor-a", "processor-b", "processor-c"]
	ProcessorPath []string

	// FailedProcessorID is the ID of the processor where the error occurred.
	// This may be the target processor or an intermediate hop.
	FailedProcessorID string

	// ChainDepth is the depth of the processor hierarchy at the point of failure.
	// 0 for root processor, 1 for direct downstream, 2+ for deeper levels.
	ChainDepth int

	// UnderlyingError is the actual error that occurred (connection failure, timeout, etc.)
	UnderlyingError error

	// Operation is the operation that was being performed (optional, for context)
	Operation string
}

// Error implements the error interface.
// Returns a formatted error message with full chain context.
func (e *ChainError) Error() string {
	var b strings.Builder

	// Start with operation if provided
	if e.Operation != "" {
		b.WriteString(e.Operation)
		b.WriteString(": ")
	}

	// Add chain context
	b.WriteString("chain error at ")
	b.WriteString(e.FailedProcessorID)

	// Add depth
	b.WriteString(" (depth=")
	b.WriteString(fmt.Sprintf("%d", e.ChainDepth))

	// Add processor path if available
	if len(e.ProcessorPath) > 0 {
		b.WriteString(", path=")
		b.WriteString(strings.Join(e.ProcessorPath, " -> "))
	}

	b.WriteString("): ")

	// Add underlying error
	if e.UnderlyingError != nil {
		b.WriteString(e.UnderlyingError.Error())
	} else {
		b.WriteString("unknown error")
	}

	return b.String()
}

// Unwrap returns the underlying error for error chain unwrapping.
// This allows errors.Is() and errors.As() to work with ChainError.
func (e *ChainError) Unwrap() error {
	return e.UnderlyingError
}

// GRPCStatus converts the ChainError to a gRPC status error.
// This preserves the chain context in the error message while mapping
// to appropriate gRPC error codes based on the underlying error.
//
// The status message includes the full processor path for debugging.
func (e *ChainError) GRPCStatus() *status.Status {
	// Determine gRPC code based on underlying error
	var code codes.Code
	if e.UnderlyingError != nil {
		// Try to extract gRPC status from underlying error
		if st, ok := status.FromError(e.UnderlyingError); ok {
			code = st.Code()
		} else {
			// Default to Internal for unknown errors
			code = codes.Internal
		}
	} else {
		code = codes.Internal
	}

	// Create status with chain context in message
	return status.New(code, e.Error())
}

// NewChainError creates a new ChainError with the given parameters.
//
// Parameters:
//   - processorPath: Ordered list of processors from root to target
//   - failedProcessorID: ID of the processor where the error occurred
//   - chainDepth: Hierarchy depth at the point of failure
//   - underlyingError: The actual error that occurred
//
// Example:
//
//	err := NewChainError(
//	    []string{"processor-a", "processor-b", "processor-c"},
//	    "processor-c",
//	    2,
//	    fmt.Errorf("connection refused"),
//	)
func NewChainError(processorPath []string, failedProcessorID string, chainDepth int, underlyingError error) *ChainError {
	return &ChainError{
		ProcessorPath:     processorPath,
		FailedProcessorID: failedProcessorID,
		ChainDepth:        chainDepth,
		UnderlyingError:   underlyingError,
	}
}

// NewChainErrorWithOperation creates a ChainError with an operation context.
// This is useful for providing additional context about what operation failed.
//
// Example:
//
//	err := NewChainErrorWithOperation(
//	    "UpdateFilter",
//	    []string{"processor-a", "processor-b"},
//	    "processor-b",
//	    1,
//	    fmt.Errorf("hunter not found"),
//	)
func NewChainErrorWithOperation(operation string, processorPath []string, failedProcessorID string, chainDepth int, underlyingError error) *ChainError {
	return &ChainError{
		Operation:         operation,
		ProcessorPath:     processorPath,
		FailedProcessorID: failedProcessorID,
		ChainDepth:        chainDepth,
		UnderlyingError:   underlyingError,
	}
}

// AppendProcessorToPath creates a new ChainError with an additional processor
// appended to the path. This is useful when forwarding errors up the chain.
//
// Example:
//
//	// Processor B receives error from Processor C
//	originalErr := &ChainError{
//	    ProcessorPath: []string{"processor-a", "processor-b", "processor-c"},
//	    FailedProcessorID: "processor-c",
//	    ...
//	}
//	// Processor B forwards to Processor A with updated path
//	updatedErr := originalErr.AppendProcessorToPath("processor-b")
func (e *ChainError) AppendProcessorToPath(processorID string) *ChainError {
	newPath := make([]string, len(e.ProcessorPath)+1)
	copy(newPath, e.ProcessorPath)
	newPath[len(newPath)-1] = processorID

	return &ChainError{
		Operation:         e.Operation,
		ProcessorPath:     newPath,
		FailedProcessorID: e.FailedProcessorID,
		ChainDepth:        e.ChainDepth,
		UnderlyingError:   e.UnderlyingError,
	}
}

// IsChainError checks if an error is a ChainError or wraps a ChainError.
// This is a convenience function that uses errors.As() to check the error chain.
//
// Example:
//
//	if chainErr, ok := IsChainError(err); ok {
//	    fmt.Printf("Failed at processor: %s\n", chainErr.FailedProcessorID)
//	    fmt.Printf("Chain depth: %d\n", chainErr.ChainDepth)
//	}
func IsChainError(err error) (*ChainError, bool) {
	var chainErr *ChainError
	// Walk the error chain looking for a ChainError
	for err != nil {
		if ce, ok := err.(*ChainError); ok {
			return ce, true
		}
		// Try to unwrap
		type unwrapper interface {
			Unwrap() error
		}
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
		} else {
			break
		}
	}
	return chainErr, false
}
