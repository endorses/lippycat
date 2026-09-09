package radius

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateNAI(t *testing.T) {
	for _, value := range []string{"alice", "alice.smith", "alice@example.test", "@example.test", "é@Exämple.test", "!#$%&'*+-/=?^_`{|}~", strings.Repeat("a", 253)} {
		require.NoError(t, ValidateNAI(value), "%q", value)
	}
	for _, value := range []string{"", "alice@", "@", "alice@realm", "a@@example.test", ".alice", "alice.", "alice..smith", "alice smith", "alice@-realm.test", "alice@realm-.test", "alice@realm_test.test", "a@realm.test.", "e\u0301@example.test", "\xff", strings.Repeat("a", 254)} {
		require.Error(t, ValidateNAI(value), "%q", value)
	}
}
