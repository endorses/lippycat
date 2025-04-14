package voip

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
)

type CallInfo struct {
	CallID      string
	State       string
	Created     time.Time
	LastUpdated time.Time
	LinkType    layers.LinkType
	SIPWriter   *pcapgo.Writer
	RTPWriter   *pcapgo.Writer
	sipFile     *os.File
	rtpFile     *os.File
}

var (
	callMap = make(map[string]*CallInfo)
	mu      sync.Mutex
)

func init() {
	go janitorLoop()
}

func (c *CallInfo) SetCallInfoState(newState string) {
	mu.Lock()
	defer mu.Unlock()

	c.State = newState
	c.LastUpdated = time.Now()
}

func getCall(callID string) (*CallInfo, error) {
	mu.Lock()
	defer mu.Unlock()

	result, exists := callMap[callID]
	fmt.Println("result call, exist:", result, exists)
	if !exists {
		return nil, errors.New("the CallID does not exist")
	}

	return result, nil
}

func GetOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	mu.Lock()
	defer mu.Unlock()

	call, exists := callMap[callID]
	if !exists {
		call = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    linkType,
		}
		if viper.GetViper().GetBool("writeVoip") {
			call.initWriters()
		}
		callMap[callID] = call
	}
	return call
}

func (c *CallInfo) initWriters() {
	os.MkdirAll("captures", 0o755)

	sipPath := filepath.Join("captures", fmt.Sprintf("sip_%s.pcap", sanitize(c.CallID)))
	rtpPath := filepath.Join("captures", fmt.Sprintf("rtp_%s.pcap", sanitize(c.CallID)))

	c.sipFile, _ = os.Create(sipPath)
	c.rtpFile, _ = os.Create(rtpPath)

	c.SIPWriter = pcapgo.NewWriter(c.sipFile)
	c.RTPWriter = pcapgo.NewWriter(c.rtpFile)

	c.SIPWriter.WriteFileHeader(65535, c.LinkType)
	c.RTPWriter.WriteFileHeader(65535, c.LinkType)
}

func sanitize(id string) string {
	return strings.ReplaceAll(id, "@", "_")
}

func janitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		cleanupOldCalls()
	}
}

func cleanupOldCalls() {
	mu.Lock()
	defer mu.Unlock()

	expireAfter := 90 * time.Second
	now := time.Now()

	for id, call := range callMap {
		if now.Sub(call.LastUpdated) > expireAfter {
			// fmt.Printf("Cleaning up expired call: %s\n", id)
			if call.sipFile != nil {
				call.sipFile.Close()
			}
			if call.rtpFile != nil {
				call.rtpFile.Close()
			}
			delete(callMap, id)
		}
	}
}
