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
	test     = make(map[string]*SipUser)
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
		test["testuser3"] = &sipUser1
		test["testuser4"] = &sipUser2
		AddMultipleSipUsers(test)
		assert.Equal(t, test["sipUser3"], SipUserMap["sipUser3"])
		assert.Equal(t, test["sipUser4"], SipUserMap["sipUser4"])
	})
}

func TestDeleteSipUser(t *testing.T) {
	t.Run("delete sip user", func(t *testing.T) {
		SipUserMap["testuser5"] = &sipUser2
		DeleteSipUser("sipUser3")
		assert.Equal(t, (*SipUser)(nil), test["testuser5"])
	})
}

func TestDeleteMultipleSipUsers(t *testing.T) {
	t.Run("delete multiple sip users", func(t *testing.T) {
		SipUserMap["testuser6"] = &sipUser2
		SipUserMap["testuser7"] = &sipUser2
		DeleteMultipleSipUsers([]string{"testuser6", "testuser7"})
		assert.Equal(t, (*SipUser)(nil), test["testuser6"])
		assert.Equal(t, (*SipUser)(nil), test["testuser7"])
	})
}
