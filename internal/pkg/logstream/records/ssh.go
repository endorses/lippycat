package records

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// SSH records directional initial-handshake observations. Ordered name-lists
// remain exact strings; banner/partial observations never imply empty KEX lists.
func SSH(event events.Event) (logstream.Record, bool, error) {
	e, ok := event.(events.SSHEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected SSH event, got %T", event)
	}
	list := func(value string) any {
		if e.Status != events.SSHStatusComplete {
			return logstream.Unset
		}
		return value
	}
	var follows any = logstream.Unset
	if e.Status == events.SSHStatusComplete {
		follows = e.FirstKEXPacketFollows
	}
	return networkRecord("ssh", e.Envelope(), string(e.Role), string(e.RoleEvidence), string(e.Status), optionalText(string(e.Reason)), optionalText(e.Banner), e.BannerEscaped, optionalText(e.ProtocolVersion), optionalText(e.SoftwareVersion),
		list(e.KEXAlgorithms), list(e.ServerHostKeyAlgorithms), list(e.EncryptionClientServer), list(e.EncryptionServerClient), list(e.MACClientServer), list(e.MACServerClient), list(e.CompressionClientServer), list(e.CompressionServerClient), list(e.LanguagesClientServer), list(e.LanguagesServerClient), follows, optionalText(e.HASSH), optionalText(e.HASSHAlgorithms), optionalText(e.HASSHVersion), optionalText(e.Envelope().EventID))
}
