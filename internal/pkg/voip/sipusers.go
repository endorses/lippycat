package voip

import (
	"sync"
	"time"
)

type SipUser struct {
	ExpirationDate time.Time
}

var (
	SipUserMap = make(map[string]*SipUser)
	muSu       sync.Mutex
)

func AddSipUser(username string, newSipUser *SipUser) {
	muSu.Lock()
	defer muSu.Unlock()
	su, exists := SipUserMap[username]
	if !exists {
		su = &SipUser{ExpirationDate: newSipUser.ExpirationDate}
		SipUserMap[username] = su
	}
}

func AddMultipleSipUsers(sipUsers map[string]*SipUser) {
	muSu.Lock()
	defer muSu.Unlock()
	for username, sipUser := range sipUsers {
		AddSipUser(username, sipUser)
	}
}

func DeleteSipUser(username string) {
	muSu.Lock()
	defer muSu.Unlock()
	delete(SipUserMap, username)
}

func DeleteMultipleSipUsers(usernames []string) {
	muSu.Lock()
	defer muSu.Unlock()
	for _, username := range usernames {
		delete(SipUserMap, username)
	}
}
