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
	// DefaultDetector is the global detector instance
	DefaultDetector *Detector
	once            sync.Once
)

// InitDefault initializes the default detector with all signatures
func InitDefault() *Detector {
	once.Do(func() {
		DefaultDetector = New()

		// Register VoIP signatures
		DefaultDetector.RegisterSignature(voip.NewSIPSignature()) // Priority 150
		DefaultDetector.RegisterSignature(voip.NewRTPSignature()) // Priority 140

		// Register VPN/Tunneling signatures
		DefaultDetector.RegisterSignature(vpn.NewOpenVPNSignature())   // Priority 100
		DefaultDetector.RegisterSignature(vpn.NewWireGuardSignature()) // Priority 100
		DefaultDetector.RegisterSignature(vpn.NewL2TPSignature())      // Priority 100
		DefaultDetector.RegisterSignature(vpn.NewPPTPSignature())      // Priority 100
		DefaultDetector.RegisterSignature(vpn.NewIKEv2Signature())     // Priority 100

		// Register application signatures (in priority order)
		DefaultDetector.RegisterSignature(application.NewGRPCSignature())       // Priority 130
		DefaultDetector.RegisterSignature(application.NewDNSSignature())        // Priority 120
		DefaultDetector.RegisterSignature(application.NewDHCPSignature())       // Priority 110
		DefaultDetector.RegisterSignature(application.NewNTPSignature())        // Priority 105
		DefaultDetector.RegisterSignature(application.NewSSHSignature())        // Priority 100
		DefaultDetector.RegisterSignature(application.NewSNMPSignature())       // Priority 100
		DefaultDetector.RegisterSignature(application.NewPOP3Signature())       // Priority 95
		DefaultDetector.RegisterSignature(application.NewIMAPSignature())       // Priority 95
		DefaultDetector.RegisterSignature(application.NewFTPSignature())        // Priority 95
		DefaultDetector.RegisterSignature(application.NewSMTPSignature())       // Priority 95
		DefaultDetector.RegisterSignature(application.NewWebSocketSignature())  // Priority 90
		DefaultDetector.RegisterSignature(application.NewMySQLSignature())      // Priority 90
		DefaultDetector.RegisterSignature(application.NewPostgreSQLSignature()) // Priority 90
		DefaultDetector.RegisterSignature(application.NewMongoDBSignature())    // Priority 90
		DefaultDetector.RegisterSignature(application.NewRedisSignature())      // Priority 90
		DefaultDetector.RegisterSignature(application.NewTelnetSignature())     // Priority 85
		DefaultDetector.RegisterSignature(application.NewTLSSignature())        // Priority 85
		DefaultDetector.RegisterSignature(application.NewHTTPSignature())       // Priority 80

		// Register network-layer signatures
		DefaultDetector.RegisterSignature(network.NewICMPSignature()) // Priority 90

		// Register link-layer signatures
		DefaultDetector.RegisterSignature(link.NewARPSignature()) // Priority 95
	})

	return DefaultDetector
}

// GetDefault returns the default detector instance
func GetDefault() *Detector {
	if DefaultDetector == nil {
		return InitDefault()
	}
	return DefaultDetector
}
