package voip

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	username   string
	newSipUser *SipUser
}

var (
	sipUser1 = SipUser{ExpirationDate: time.Date(0o001, 0o1, 0o1, 0o1, 0o1, 0o1, 0o00000001, time.UTC)}
	sipUser2 = SipUser{ExpirationDate: time.Date(2035, 0o1, 0o1, 0o1, 0o1, 0o1, 0o00000001, time.UTC)}
)

func TestAddSipUser(t *testing.T) {
	t.Run("user add checking", func(t *testing.T) {
		tests := []testCase{
			{username: "testuser1", newSipUser: &sipUser1},
			{username: "testuser2", newSipUser: &sipUser2},
		}
		for _, test := range tests {
			AddSipUser(test.username, test.newSipUser)
			assert.Equal(t, test.newSipUser.ExpirationDate, SipUserMap[test.username].ExpirationDate)
		}
	})
}

func TestAddMultipleSipUsers(t *testing.T) {
	t.Run("multi user add", func(t *testing.T) {
		test := make(map[string]*SipUser)
		test["sipUser1"] = &sipUser1
		test["sipUser2"] = &sipUser2
		AddMultipleSipUsers(test)
		assert.Equal(t, test["sipUser1"], SipUserMap["sipUser1"])
	})
}
