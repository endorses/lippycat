package sipusers

import (
	"strings"
	"sync"
	"time"
)

type SipUser struct {
	ExpirationDate time.Time
}

var (
	sipUserMap = make(map[string]*SipUser)
	muSu       sync.Mutex
)

func AddSipUser(username string, newSipUser *SipUser) {
	muSu.Lock()
	defer muSu.Unlock()
	_, exists := sipUserMap[username]
	if !exists {
		su := &SipUser{ExpirationDate: newSipUser.ExpirationDate}
		sipUserMap[username] = su
	}
}

func AddMultipleSipUsers(sipUsers map[string]*SipUser) {
	for username, sipUser := range sipUsers {
		AddSipUser(username, sipUser)
	}
}

func DeleteSipUser(username string) {
	muSu.Lock()
	defer muSu.Unlock()
	if _, ok := sipUserMap[username]; ok {
		delete(sipUserMap, username)
	}
}

func DeleteMultipleSipUsers(usernames []string) {
	muSu.Lock()
	defer muSu.Unlock()
	for _, username := range usernames {
		delete(sipUserMap, username)
	}
}

func IsSurveiled(sipHeader string) bool {
	muSu.Lock()
	defer muSu.Unlock()

	// Normalize SIP header to lowercase for case-insensitive matching
	normalizedHeader := strings.ToLower(sipHeader)

	for username := range sipUserMap {
		normalizedUsername := strings.ToLower(username)

		// Use case-insensitive matching for SIP headers
		if strings.Contains(normalizedHeader, normalizedUsername) {
			return true
		}
	}
	return false
}
