package detector

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/link"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/network"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

var (
	// defaultDetector is the global detector instance
	defaultDetector *Detector
	once            sync.Once
	defaultMu       sync.RWMutex
)

// InitDefault initializes the default detector with all signatures
func InitDefault() *Detector {
	once.Do(func() {
		defaultMu.Lock()
		defer defaultMu.Unlock()
		defaultDetector = New()

		// Register VoIP signatures
		defaultDetector.RegisterSignature(voip.NewSIPSignature()) // Priority 150
		defaultDetector.RegisterSignature(voip.NewRTPSignature()) // Priority 140

		// Register VPN/Tunneling signatures
		defaultDetector.RegisterSignature(vpn.NewOpenVPNSignature())   // Priority 100
		defaultDetector.RegisterSignature(vpn.NewWireGuardSignature()) // Priority 100
		defaultDetector.RegisterSignature(vpn.NewL2TPSignature())      // Priority 100
		defaultDetector.RegisterSignature(vpn.NewPPTPSignature())      // Priority 100
		defaultDetector.RegisterSignature(vpn.NewIKEv2Signature())     // Priority 100

		// Register application signatures (in priority order)
		defaultDetector.RegisterSignature(application.NewGRPCSignature())       // Priority 130
		defaultDetector.RegisterSignature(application.NewDNSSignature())        // Priority 120
		defaultDetector.RegisterSignature(application.NewQUICSignature())       // Priority 115
		defaultDetector.RegisterSignature(application.NewDHCPSignature())       // Priority 110
		defaultDetector.RegisterSignature(application.NewNTPSignature())        // Priority 105
		defaultDetector.RegisterSignature(application.NewSSHSignature())        // Priority 100
		defaultDetector.RegisterSignature(application.NewSNMPSignature())       // Priority 100
		defaultDetector.RegisterSignature(application.NewPOP3Signature())       // Priority 95
		defaultDetector.RegisterSignature(application.NewIMAPSignature())       // Priority 95
		defaultDetector.RegisterSignature(application.NewFTPSignature())        // Priority 95
		defaultDetector.RegisterSignature(application.NewSMTPSignature())       // Priority 95
		defaultDetector.RegisterSignature(application.NewWebSocketSignature())  // Priority 90
		defaultDetector.RegisterSignature(application.NewMySQLSignature())      // Priority 90
		defaultDetector.RegisterSignature(application.NewPostgreSQLSignature()) // Priority 90
		defaultDetector.RegisterSignature(application.NewMongoDBSignature())    // Priority 90
		defaultDetector.RegisterSignature(application.NewRedisSignature())      // Priority 90
		defaultDetector.RegisterSignature(application.NewTLSSignature())        // Priority 110
		defaultDetector.RegisterSignature(application.NewTelnetSignature())     // Priority 85
		defaultDetector.RegisterSignature(application.NewHTTPSignature())       // Priority 80

		// Register network-layer signatures
		defaultDetector.RegisterSignature(network.NewICMPSignature()) // Priority 90

		// Register link-layer signatures
		defaultDetector.RegisterSignature(link.NewARPSignature()) // Priority 95
	})

	return GetDefaultIfInitialized()
}

// GetDefault returns the default detector instance
func GetDefault() *Detector {
	if d := GetDefaultIfInitialized(); d != nil {
		return d
	}
	return InitDefault()
}

// GetDefaultIfInitialized returns the existing default detector, or nil if
// detection has never initialized it. Observability callers must use this
// accessor to avoid creating detector state and cleanup goroutines. The lock
// synchronizes reads with initialization and prevents partial publication.
func GetDefaultIfInitialized() *Detector {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultDetector
}
