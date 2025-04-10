package voip

import "sync"

type SipUserList struct {
	usernames []string
}

var (
	SipUsers SipUserList
	mu2      sync.Mutex
)

func (s *SipUserList) AddSipUser(username string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = append(s.usernames, username)
}

func (s *SipUserList) AddMultipleSipUsers(usernames []string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = append(s.usernames, usernames...)
}

func (s *SipUserList) DeleteSipUser(username string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = remove(s.usernames, username)
}

func (s *SipUserList) DeleteMultipleSipUsers(usernames []string) {
	mu2.Lock()
	defer mu2.Unlock()
	for _, username := range usernames {
		s.usernames = remove(s.usernames, username)
	}
}

func remove(slice []string, value string) []string {
	newSlice := []string{}
	for _, item := range slice {
		if item != value {
			newSlice = append(newSlice, item)
		}
	}
	return newSlice
}
