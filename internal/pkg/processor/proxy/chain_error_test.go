package proxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestChainError_Error(t *testing.T) {
	tests := []struct {
		name     string
		chainErr *ChainError
		want     string
	}{
		{
			name: "basic chain error",
			chainErr: &ChainError{
				ProcessorPath:     []string{"processor-a", "processor-b", "processor-c"},
				FailedProcessorID: "processor-c",
				ChainDepth:        2,
				UnderlyingError:   fmt.Errorf("connection refused"),
			},
			want: "chain error at processor-c (depth=2, path=processor-a -> processor-b -> processor-c): connection refused",
		},
		{
			name: "chain error with operation",
			chainErr: &ChainError{
				Operation:         "UpdateFilter",
				ProcessorPath:     []string{"processor-a", "processor-b"},
				FailedProcessorID: "processor-b",
				ChainDepth:        1,
				UnderlyingError:   fmt.Errorf("hunter not found"),
			},
			want: "UpdateFilter: chain error at processor-b (depth=1, path=processor-a -> processor-b): hunter not found",
		},
		{
			name: "chain error with empty path",
			chainErr: &ChainError{
				ProcessorPath:     []string{},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   fmt.Errorf("timeout"),
			},
			want: "chain error at processor-a (depth=0): timeout",
		},
		{
			name: "chain error with nil underlying error",
			chainErr: &ChainError{
				ProcessorPath:     []string{"processor-a"},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   nil,
			},
			want: "chain error at processor-a (depth=0, path=processor-a): unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.chainErr.Error()
			if got != tt.want {
				t.Errorf("ChainError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChainError_Unwrap(t *testing.T) {
	underlyingErr := fmt.Errorf("connection refused")
	chainErr := &ChainError{
		ProcessorPath:     []string{"processor-a"},
		FailedProcessorID: "processor-a",
		ChainDepth:        0,
		UnderlyingError:   underlyingErr,
	}

	unwrapped := chainErr.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ChainError.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}

	// Test that errors.Is works with unwrapped error
	if !errors.Is(chainErr, underlyingErr) {
		t.Error("errors.Is should work with ChainError")
	}
}

func TestChainError_GRPCStatus(t *testing.T) {
	tests := []struct {
		name     string
		chainErr *ChainError
		wantCode codes.Code
	}{
		{
			name: "chain error with gRPC status underlying error",
			chainErr: &ChainError{
				ProcessorPath:     []string{"processor-a", "processor-b"},
				FailedProcessorID: "processor-b",
				ChainDepth:        1,
				UnderlyingError:   status.Errorf(codes.NotFound, "processor not found"),
			},
			wantCode: codes.NotFound,
		},
		{
			name: "chain error with regular error",
			chainErr: &ChainError{
				ProcessorPath:     []string{"processor-a"},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   fmt.Errorf("connection refused"),
			},
			wantCode: codes.Internal,
		},
		{
			name: "chain error with nil underlying error",
			chainErr: &ChainError{
				ProcessorPath:     []string{"processor-a"},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   nil,
			},
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := tt.chainErr.GRPCStatus()
			if st.Code() != tt.wantCode {
				t.Errorf("ChainError.GRPCStatus().Code() = %v, want %v", st.Code(), tt.wantCode)
			}

			// Verify that the status message contains the chain context
			msg := st.Message()
			if !strings.Contains(msg, tt.chainErr.FailedProcessorID) {
				t.Errorf("GRPCStatus message should contain failed processor ID %s, got: %s",
					tt.chainErr.FailedProcessorID, msg)
			}
		})
	}
}

func TestNewChainError(t *testing.T) {
	processorPath := []string{"processor-a", "processor-b"}
	failedProcessorID := "processor-b"
	chainDepth := 1
	underlyingErr := fmt.Errorf("connection refused")

	chainErr := NewChainError(processorPath, failedProcessorID, chainDepth, underlyingErr)

	if chainErr.FailedProcessorID != failedProcessorID {
		t.Errorf("FailedProcessorID = %v, want %v", chainErr.FailedProcessorID, failedProcessorID)
	}

	if chainErr.ChainDepth != chainDepth {
		t.Errorf("ChainDepth = %v, want %v", chainErr.ChainDepth, chainDepth)
	}

	if chainErr.UnderlyingError != underlyingErr {
		t.Errorf("UnderlyingError = %v, want %v", chainErr.UnderlyingError, underlyingErr)
	}

	if len(chainErr.ProcessorPath) != len(processorPath) {
		t.Errorf("ProcessorPath length = %v, want %v", len(chainErr.ProcessorPath), len(processorPath))
	}
}

func TestNewChainErrorWithOperation(t *testing.T) {
	operation := "UpdateFilter"
	processorPath := []string{"processor-a", "processor-b"}
	failedProcessorID := "processor-b"
	chainDepth := 1
	underlyingErr := fmt.Errorf("hunter not found")

	chainErr := NewChainErrorWithOperation(operation, processorPath, failedProcessorID, chainDepth, underlyingErr)

	if chainErr.Operation != operation {
		t.Errorf("Operation = %v, want %v", chainErr.Operation, operation)
	}

	if chainErr.FailedProcessorID != failedProcessorID {
		t.Errorf("FailedProcessorID = %v, want %v", chainErr.FailedProcessorID, failedProcessorID)
	}

	// Verify operation is included in error message
	errMsg := chainErr.Error()
	if !strings.Contains(errMsg, operation) {
		t.Errorf("Error message should contain operation %s, got: %s", operation, errMsg)
	}
}

func TestChainError_AppendProcessorToPath(t *testing.T) {
	originalErr := &ChainError{
		Operation:         "UpdateFilter",
		ProcessorPath:     []string{"processor-a", "processor-b", "processor-c"},
		FailedProcessorID: "processor-c",
		ChainDepth:        2,
		UnderlyingError:   fmt.Errorf("connection refused"),
	}

	// Append a processor to the path
	updatedErr := originalErr.AppendProcessorToPath("processor-b")

	// Verify new error has updated path
	expectedPath := []string{"processor-a", "processor-b", "processor-c", "processor-b"}
	if len(updatedErr.ProcessorPath) != len(expectedPath) {
		t.Errorf("ProcessorPath length = %v, want %v", len(updatedErr.ProcessorPath), len(expectedPath))
	}

	for i, proc := range expectedPath {
		if updatedErr.ProcessorPath[i] != proc {
			t.Errorf("ProcessorPath[%d] = %v, want %v", i, updatedErr.ProcessorPath[i], proc)
		}
	}

	// Verify other fields are preserved
	if updatedErr.FailedProcessorID != originalErr.FailedProcessorID {
		t.Errorf("FailedProcessorID changed, got %v, want %v", updatedErr.FailedProcessorID, originalErr.FailedProcessorID)
	}

	if updatedErr.ChainDepth != originalErr.ChainDepth {
		t.Errorf("ChainDepth changed, got %v, want %v", updatedErr.ChainDepth, originalErr.ChainDepth)
	}

	if updatedErr.Operation != originalErr.Operation {
		t.Errorf("Operation changed, got %v, want %v", updatedErr.Operation, originalErr.Operation)
	}

	// Verify original error is unchanged
	if len(originalErr.ProcessorPath) != 3 {
		t.Error("Original error was modified")
	}
}

func TestIsChainError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantFound bool
	}{
		{
			name: "direct ChainError",
			err: &ChainError{
				ProcessorPath:     []string{"processor-a"},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   fmt.Errorf("connection refused"),
			},
			wantFound: true,
		},
		{
			name: "wrapped ChainError",
			err: fmt.Errorf("wrapper: %w", &ChainError{
				ProcessorPath:     []string{"processor-a"},
				FailedProcessorID: "processor-a",
				ChainDepth:        0,
				UnderlyingError:   fmt.Errorf("connection refused"),
			}),
			wantFound: true,
		},
		{
			name:      "regular error",
			err:       fmt.Errorf("connection refused"),
			wantFound: false,
		},
		{
			name:      "nil error",
			err:       nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainErr, found := IsChainError(tt.err)
			if found != tt.wantFound {
				t.Errorf("IsChainError() found = %v, want %v", found, tt.wantFound)
			}

			if found && chainErr == nil {
				t.Error("IsChainError() found=true but chainErr is nil")
			}

			if !found && chainErr != nil {
				t.Error("IsChainError() found=false but chainErr is not nil")
			}
		})
	}
}

func TestChainError_Integration(t *testing.T) {
	// Simulate a multi-hop chain error scenario
	// Processor C fails with connection error
	originalErr := fmt.Errorf("connection refused")

	// Processor B wraps it in a ChainError
	processorBErr := NewChainErrorWithOperation(
		"UpdateFilter",
		[]string{"processor-a", "processor-b"},
		"processor-c",
		2,
		originalErr,
	)

	// Verify the error chain
	if !errors.Is(processorBErr, originalErr) {
		t.Error("ChainError should preserve error chain for errors.Is()")
	}

	// Verify gRPC status conversion
	st := processorBErr.GRPCStatus()
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal code for regular error, got %v", st.Code())
	}

	msg := st.Message()
	expectedSubstrings := []string{
		"UpdateFilter",
		"processor-c",
		"depth=2",
		"processor-a -> processor-b",
		"connection refused",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(msg, substr) {
			t.Errorf("Status message missing expected substring %q, got: %s", substr, msg)
		}
	}
}
