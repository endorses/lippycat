//go:build !linux

package admissionintegration

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedPlatformSession(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	session, err := NewSession(context.Background(), cfg)
	require.NoError(t, err)
	require.Nil(t, session.Controller)
	require.Nil(t, session.Metadata)
	require.Nil(t, session.Installer())
	require.False(t, session.Status().Enabled)
	require.NoError(t, session.Close())
	cfg.Enabled = true
	session, err = NewSession(context.Background(), cfg)
	require.Nil(t, session)
	require.ErrorContains(t, err, "requires Linux")
}
