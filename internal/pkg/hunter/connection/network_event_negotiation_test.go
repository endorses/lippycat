//go:build hunter || all

package connection

import (
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNetworkRequiredVersusSupportedKinds(t *testing.T) {
	old := &management.RegistrationResponse{AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: []int32{1, 2, 3, 4, 5, 6, 7}}
	require.NoError(t, validateAcceptedEventProfile(old))
	require.ErrorContains(t, validateAcceptedEventProfile(old, eventsv1.EventKind_EVENT_KIND_NTP), "kind 9")
	old.AcceptedEventKinds = append(old.AcceptedEventKinds, 9)
	require.NoError(t, validateAcceptedEventProfile(old, eventsv1.EventKind_EVENT_KIND_NTP))
}
