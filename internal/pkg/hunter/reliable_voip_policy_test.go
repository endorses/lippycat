//go:build hunter || all

package hunter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/hunter/packetforwarding"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestLIOwnedReliableVoIPRejectsUnselectedSignallingExport(t *testing.T) {
	hunter := &Hunter{config: Config{
		FilterPolicy: filterpolicy.Config{Owner: "li"},
		VoIPMode:     true, VoIPSignallingPolicy: "all", ForwardMode: "packets",
		Packets: packetforwarding.Config{DeliveryProfile: "reliable", DestinationID: "receiver", TrustedCert: "receipt.pem", Spool: packetforwarding.SpoolConfig{Directory: "spool", Protection: "encrypted", Keys: securestore.KeyConfig{Active: securestore.KeyRef{ID: "storage", File: "storage.key"}}}},
	}}
	require.ErrorContains(t, hunter.configureReliablePackets(), "task-selected signalling")
}
