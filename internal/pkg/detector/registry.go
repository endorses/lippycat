package detector

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
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
		DefaultDetector.RegisterSignature(voip.NewSIPSignature())
		DefaultDetector.RegisterSignature(voip.NewRTPSignature())

		// Register application signatures
		DefaultDetector.RegisterSignature(application.NewDNSSignature())
		DefaultDetector.RegisterSignature(application.NewGRPCSignature())
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
