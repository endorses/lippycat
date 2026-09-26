//go:build li

package li

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTaskAuthorizationCutoff(t *testing.T) {
	end := time.Unix(1700000000, 0).UTC()
	for _, tc := range []struct {
		name     string
		implicit bool
		end      time.Time
		want     time.Time
	}{
		{name: "implicit expiry", implicit: true, end: end, want: end},
		{name: "explicit deactivation", end: end},
		{name: "unbounded implicit", implicit: true},
		{name: "unbounded explicit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, TaskAuthorizationCutoff(&InterceptTask{EndTime: tc.end, ImplicitDeactivationAllowed: tc.implicit}))
		})
	}
}
