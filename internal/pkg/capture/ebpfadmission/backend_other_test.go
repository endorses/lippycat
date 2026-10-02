//go:build !linux

package ebpfadmission

import (
	"context"
	"errors"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func TestUnsupportedPlatformBackend(t *testing.T) {
	backend, err := NewBackend(Options{})
	if backend != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported initialization: backend=%v error=%v", backend, err)
	}
	backend = &Backend{}
	ctx := context.Background()
	for _, err := range []error{backend.PutEndpoint(ctx, mediaadmission.EndpointKey{}), backend.DeleteEndpoint(ctx, mediaadmission.EndpointKey{}), backend.SetControl(ctx, 0, mediaadmission.Control{}), backend.ReplaceSelectors(ctx, 0, nil, true)} {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported mutation: %v", err)
		}
	}
	if _, err := backend.ListEndpoints(ctx, 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported enumeration: %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}
