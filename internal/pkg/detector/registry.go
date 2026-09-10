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
		defaultDetector = registerDefaultSignatures(New())
	})

	return GetDefaultIfInitialized()
}

// NewWithDefaultSignatures creates an independently owned detector with the
// same signatures as the shared default and hard cache/flow caps of 100,000
// entries each. It does not read global configuration. Call Shutdown when done.
func NewWithDefaultSignatures() *Detector {
	return registerDefaultSignatures(NewWithLimits(100000, 100000))
}

func registerDefaultSignatures(d *Detector) *Detector {

	// Register VoIP signatures
	d.RegisterSignature(voip.NewSIPSignature()) // Priority 150
	d.RegisterSignature(voip.NewRTPSignature()) // Priority 140

	// Register VPN/Tunneling signatures
	d.RegisterSignature(vpn.NewOpenVPNSignature())   // Priority 100
	d.RegisterSignature(vpn.NewWireGuardSignature()) // Priority 100
	d.RegisterSignature(vpn.NewL2TPSignature())      // Priority 100
	d.RegisterSignature(vpn.NewPPTPSignature())      // Priority 100
	d.RegisterSignature(vpn.NewIKEv2Signature())     // Priority 100

	// Register application signatures (in priority order)
	d.RegisterSignature(application.NewGRPCSignature())       // Priority 130
	d.RegisterSignature(application.NewDNSSignature())        // Priority 120
	d.RegisterSignature(application.NewQUICSignature())       // Priority 115
	d.RegisterSignature(application.NewDHCPSignature())       // Priority 110
	d.RegisterSignature(application.NewNTPSignature())        // Priority 105
	d.RegisterSignature(application.NewSSHSignature())        // Priority 100
	d.RegisterSignature(application.NewSNMPSignature())       // Priority 100
	d.RegisterSignature(application.NewPOP3Signature())       // Priority 95
	d.RegisterSignature(application.NewIMAPSignature())       // Priority 95
	d.RegisterSignature(application.NewFTPSignature())        // Priority 95
	d.RegisterSignature(application.NewSMTPSignature())       // Priority 95
	d.RegisterSignature(application.NewWebSocketSignature())  // Priority 90
	d.RegisterSignature(application.NewMySQLSignature())      // Priority 90
	d.RegisterSignature(application.NewPostgreSQLSignature()) // Priority 90
	d.RegisterSignature(application.NewMongoDBSignature())    // Priority 90
	d.RegisterSignature(application.NewRedisSignature())      // Priority 90
	d.RegisterSignature(application.NewTLSSignature())        // Priority 110
	d.RegisterSignature(application.NewTelnetSignature())     // Priority 85
	d.RegisterSignature(application.NewHTTPSignature())       // Priority 80

	// Register network-layer signatures
	d.RegisterSignature(network.NewICMPSignature()) // Priority 90

	// Register link-layer signatures
	d.RegisterSignature(link.NewARPSignature()) // Priority 95
	return d
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
