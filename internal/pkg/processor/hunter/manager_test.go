package hunter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagerRegisterZeroMaxHuntersIsUnlimited(t *testing.T) {
	manager := NewManager("test-processor", 0, nil)

	for i := 0; i < 256; i++ {
		hunterID := fmt.Sprintf("hunter-%d", i)
		_, _, err := manager.Register(hunterID, "test-host", []string{"eth0"}, nil)
		require.NoError(t, err)
	}

	require.Len(t, manager.GetAll(""), 256)
}
