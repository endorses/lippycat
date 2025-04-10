package voip

import "sync"

type SIPUserList struct {
	usernames []string
}

var (
	SIPUsers SIPUserList
	mu2      sync.Mutex
)

func (s *SIPUserList) AddSIPUser(username string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = append(s.usernames, username)
}

func (s *SIPUserList) AddMultipleSIPUsers(usernames []string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = append(s.usernames, usernames...)
}

func (s *SIPUserList) DeleteSIPUser(username string) {
	mu2.Lock()
	defer mu2.Unlock()
	s.usernames = remove(s.usernames, username)
}

func (s *SIPUserList) DeleteMultipleSIPUsers(usernames []string) {
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
