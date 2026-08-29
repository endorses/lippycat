//go:build hunter || all

package hunt

import (
	"context"
	"errors"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/stretchr/testify/require"
)

func TestRunHunterRuntimeUsesProtocolHooksAndCleansUp(t *testing.T) {
	wantErr := errors.New("start failed")
	setupCalled := false
	cleanupCalled := false

	err := runHunterRuntime(hunter.Config{ProcessorAddr: "processor:55555", HunterID: "test"}, protocolcatalog.Spec{Name: "test", Analyzer: "test"}, hunterRuntimeHooks{
		setup: func(context.Context, *hunter.Hunter) (func(), error) {
			setupCalled = true
			return func() { cleanupCalled = true }, nil
		},
		start: func(context.Context, *hunter.Hunter) error { return wantErr },
	})

	require.ErrorIs(t, err, wantErr)
	require.True(t, setupCalled)
	require.True(t, cleanupCalled)
}

func TestRunHunterRuntimeWrapsSetupFailure(t *testing.T) {
	wantErr := errors.New("setup failed")
	err := runHunterRuntime(hunter.Config{ProcessorAddr: "processor:55555", HunterID: "test"}, protocolcatalog.MustLookup("dns"), hunterRuntimeHooks{
		setup: func(context.Context, *hunter.Hunter) (func(), error) {
			return nil, wantErr
		},
	})

	require.ErrorIs(t, err, wantErr)
	require.ErrorContains(t, err, "failed to initialize dns hunter")
}
