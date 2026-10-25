package protoadapter

import (
	"errors"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	sshparser "github.com/endorses/lippycat/internal/pkg/ssh"
	"strconv"
	"unicode"
	"unicode/utf8"
)

func encodeSSH(e events.SSHEvent) *eventsv1.SSHEvent {
	return &eventsv1.SSHEvent{
		Role:                    string(e.Role),
		RoleEvidence:            string(e.RoleEvidence),
		Status:                  string(e.Status),
		Reason:                  string(e.Reason),
		Banner:                  e.Banner,
		BannerEscaped:           e.BannerEscaped,
		ProtocolVersion:         e.ProtocolVersion,
		SoftwareVersion:         e.SoftwareVersion,
		KexAlgorithms:           e.KEXAlgorithms,
		ServerHostKeyAlgorithms: e.ServerHostKeyAlgorithms,
		EncryptionClientServer:  e.EncryptionClientServer,
		EncryptionServerClient:  e.EncryptionServerClient,
		MacClientServer:         e.MACClientServer,
		MacServerClient:         e.MACServerClient,
		CompressionClientServer: e.CompressionClientServer,
		CompressionServerClient: e.CompressionServerClient,
		LanguagesClientServer:   e.LanguagesClientServer,
		LanguagesServerClient:   e.LanguagesServerClient,
		FirstKexPacketFollows:   e.FirstKEXPacketFollows,
		Hassh:                   e.HASSH,
		HasshAlgorithms:         e.HASSHAlgorithms,
		HasshVersion:            e.HASSHVersion,
	}
}

func decodeSSH(in *eventsv1.SSHEvent, env events.Envelope) (events.SSHEvent, error) {
	if in == nil {
		return events.SSHEvent{}, errors.New("SSH: nil payload")
	}
	e := events.NewSSHEvent(env)
	e.Role = events.SSHRole(in.Role)
	e.RoleEvidence = events.SSHRoleEvidence(in.RoleEvidence)
	e.Status = events.SSHStatus(in.Status)
	e.Reason = events.SSHReason(in.Reason)
	e.Banner = in.Banner
	e.BannerEscaped = in.BannerEscaped
	e.ProtocolVersion = in.ProtocolVersion
	e.SoftwareVersion = in.SoftwareVersion
	e.KEXAlgorithms = in.KexAlgorithms
	e.ServerHostKeyAlgorithms = in.ServerHostKeyAlgorithms
	e.EncryptionClientServer = in.EncryptionClientServer
	e.EncryptionServerClient = in.EncryptionServerClient
	e.MACClientServer = in.MacClientServer
	e.MACServerClient = in.MacServerClient
	e.CompressionClientServer = in.CompressionClientServer
	e.CompressionServerClient = in.CompressionServerClient
	e.LanguagesClientServer = in.LanguagesClientServer
	e.LanguagesServerClient = in.LanguagesServerClient
	e.FirstKEXPacketFollows = in.FirstKexPacketFollows
	e.HASSH = in.Hassh
	e.HASSHAlgorithms = in.HasshAlgorithms
	e.HASSHVersion = in.HasshVersion
	return e, nil
}

func validateSSH(e events.SSHEvent) error {
	if e.Envelope().Flow.Protocol != 6 {
		return errors.New("SSH: TCP flow is required")
	}
	switch e.Role {
	case events.SSHRoleUnknown, events.SSHRoleClient, events.SSHRoleServer:
	default:
		return errors.New("SSH: invalid role")
	}
	switch e.RoleEvidence {
	case events.SSHRoleEvidenceUnknown, events.SSHRoleEvidenceTCPSYN, events.SSHRoleEvidenceTCPSYNACK, events.SSHRoleEvidenceProtocol, events.SSHRoleEvidenceConflict:
	default:
		return errors.New("SSH: invalid role evidence")
	}
	if (e.Role == events.SSHRoleUnknown) != (e.RoleEvidence == events.SSHRoleEvidenceUnknown || e.RoleEvidence == events.SSHRoleEvidenceConflict) {
		return errors.New("SSH: role and evidence disagree")
	}
	switch e.Reason {
	case events.SSHReasonNone, events.SSHReasonKEXComplete, events.SSHReasonNewKeys, events.SSHReasonUnsupportedVersion, events.SSHReasonMalformed, events.SSHReasonResourceLimit, events.SSHReasonMissingBanner, events.SSHReasonIncomplete, events.SSHReasonNoKEX, events.SSHReasonGap, events.SSHReasonDisconnect:
	default:
		return errors.New("SSH: invalid terminal reason")
	}
	if len(e.Banner) > sshparser.MaxIdentificationBytes*4+2 || !utf8.ValidString(e.Banner) {
		return errors.New("SSH: invalid banner encoding or size")
	}
	raw := e.Banner
	if e.BannerEscaped {
		var err error
		raw, err = strconv.Unquote(e.Banner)
		if err != nil || strconv.QuoteToASCII(raw) != e.Banner {
			return errors.New("SSH: noncanonical escaped banner")
		}
	} else {
		for _, r := range raw {
			if unicode.IsControl(r) {
				return errors.New("SSH: control bytes require escaped banner")
			}
		}
	}
	if raw != "" {
		identification, err := sshparser.ParseIdentification([]byte(raw + "\n"))
		if err != nil || identification.ProtocolVersion != e.ProtocolVersion || identification.SoftwareVersion != e.SoftwareVersion {
			return errors.New("SSH: banner identification mismatch")
		}
	} else if e.ProtocolVersion != "" || e.SoftwareVersion != "" || e.BannerEscaped {
		return errors.New("SSH: identification without banner")
	}
	k := sshparser.KEXINIT{KEXAlgorithms: e.KEXAlgorithms, ServerHostKeyAlgorithms: e.ServerHostKeyAlgorithms, EncryptionClientServer: e.EncryptionClientServer, EncryptionServerClient: e.EncryptionServerClient, MACClientServer: e.MACClientServer, MACServerClient: e.MACServerClient, CompressionClientServer: e.CompressionClientServer, CompressionServerClient: e.CompressionServerClient, LanguagesClientServer: e.LanguagesClientServer, LanguagesServerClient: e.LanguagesServerClient, FirstKEXPacketFollows: e.FirstKEXPacketFollows}
	switch e.Status {
	case events.SSHStatusComplete:
		if e.Reason != events.SSHReasonKEXComplete || raw == "" || (e.ProtocolVersion != "2.0" && e.ProtocolVersion != "1.99") {
			return errors.New("SSH: complete KEX lacks supported identification/completion")
		}
		fp, ok := k.Fingerprint(sshparser.RoleClient)
		if !ok {
			return errors.New("SSH: invalid or excessive KEXINIT evidence")
		}
		if e.Role == events.SSHRoleUnknown {
			if e.HASSH != "" || e.HASSHAlgorithms != "" || e.HASSHVersion != "" {
				return errors.New("SSH: unknown role cannot have fingerprint")
			}
		} else {
			if e.Role == events.SSHRoleServer {
				fp, _ = k.Fingerprint(sshparser.RoleServer)
			}
			if fp.Hash != e.HASSH || fp.Algorithms != e.HASSHAlgorithms || fp.Version != e.HASSHVersion {
				return errors.New("SSH: fingerprint does not match exact role-specific evidence")
			}
		}
	case events.SSHStatusBanner, events.SSHStatusPartial:
		if e.Status == events.SSHStatusBanner && (raw == "" || (e.Reason != events.SSHReasonNone && e.Reason != events.SSHReasonNoKEX)) {
			return errors.New("SSH: invalid banner observation")
		}
		if e.Status == events.SSHStatusPartial && (e.Reason == events.SSHReasonNone || e.Reason == events.SSHReasonKEXComplete) {
			return errors.New("SSH: partial observation requires terminal reason")
		}
		if k != (sshparser.KEXINIT{}) || e.HASSH != "" || e.HASSHAlgorithms != "" || e.HASSHVersion != "" {
			return errors.New("SSH: incomplete observation cannot have KEXINIT/fingerprint evidence")
		}
	default:
		return errors.New("SSH: invalid status")
	}
	return nil
}
