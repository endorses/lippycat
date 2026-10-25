package eventquery

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestECHQueriesDistinguishUnknownFromObservedAbsence(t *testing.T) {
	unknown := events.NewTLSEvent(events.Envelope{})
	absent := unknown
	absent.ClientHelloCount = 1
	offered := absent
	offered.ECHOfferedCount = 1
	for query, matches := range map[string][]bool{
		"ech_offered:true":       {false, false, true},
		"ech_offered:false":      {false, true, false},
		"client_hello_count:>=1": {false, true, true},
	} {
		predicate, err := Compile(query)
		require.NoError(t, err)
		for i, event := range []events.Event{unknown, absent, offered} {
			require.Equal(t, matches[i], predicate(event), query)
		}
	}
	require.NotContains(t, Summary(unknown), "ECH")
	require.Contains(t, Summary(absent), "ECH offered=0/1")
	require.Contains(t, Summary(offered), "ECH offered=1/1")
}
