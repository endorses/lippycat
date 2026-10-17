package packetreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func receiptAuthority(t *testing.T, authority string) (*Signer, *Verifier) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: authority}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	encoded, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	require.NoError(t, err)
	dir := t.TempDir()
	certificateFile, keyFile := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0600))
	key, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	signer, err := LoadSigner(authority, certificateFile, keyFile)
	require.NoError(t, err)
	verifier, err := LoadVerifier(authority, certificateFile)
	require.NoError(t, err)
	return signer, verifier
}
func TestReceiptSignatureBindsAuthorityIdentityAndContent(t *testing.T) {
	signer, verifier := receiptAuthority(t, "central-authority")
	message := custodyTestMessage(4)
	digest, err := BatchDigest(message.Batch)
	require.NoError(t, err)
	receipt := &data.RawPacketReceipt{Identity: proto.Clone(message.Identity).(*data.RawPacketIdentity), Sequence: 4, ContentSha256: digest}
	require.NoError(t, signer.Sign(receipt))
	require.NoError(t, verifier.Verify(receipt, message.Identity, message.Batch))
	tests := map[string]func(*data.RawPacketReceipt){
		"signature":   func(r *data.RawPacketReceipt) { r.Signature[0] ^= 1 },
		"version":     func(r *data.RawPacketReceipt) { r.ProtocolVersion++ },
		"authority":   func(r *data.RawPacketReceipt) { r.AuthorityId = "relay" },
		"destination": func(r *data.RawPacketReceipt) { r.Identity.DestinationId = "different-central" },
		"source":      func(r *data.RawPacketReceipt) { r.Identity.SourceId = "other-edge" },
		"session":     func(r *data.RawPacketReceipt) { r.Identity.ProducerSessionId = "new-session" },
		"scope":       func(r *data.RawPacketReceipt) { r.Identity.AckScope = "receiver" },
		"sequence":    func(r *data.RawPacketReceipt) { r.Sequence++ },
		"digest":      func(r *data.RawPacketReceipt) { r.ContentSha256[0] ^= 1 },
		"retirement":  func(r *data.RawPacketReceipt) { r.Retired = true },
		"losses": func(r *data.RawPacketReceipt) {
			r.LossGeneration = 1
			r.Losses = []*data.RawPacketLossRange{{First: 1, Last: 9}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := proto.Clone(receipt).(*data.RawPacketReceipt)
			mutate(tampered)
			require.Error(t, verifier.Verify(tampered, message.Identity, message.Batch))
		})
	}
	wrongKeySigner, wrongKeyVerifier := receiptAuthority(t, "central-authority")
	require.Error(t, wrongKeyVerifier.Verify(receipt, message.Identity, message.Batch))
	forged := proto.Clone(receipt).(*data.RawPacketReceipt)
	require.NoError(t, wrongKeySigner.Sign(forged))
	require.Error(t, verifier.Verify(forged, message.Identity, message.Batch))
	wrongAuthority := &Verifier{authority: "different-authority", key: verifier.key}
	require.Error(t, wrongAuthority.Verify(receipt, message.Identity, message.Batch))
	differentBatch := proto.Clone(message.Batch).(*data.PacketBatch)
	differentBatch.Packets[0].Data = []byte("altered content")
	require.ErrorContains(t, verifier.Verify(receipt, message.Identity, differentBatch), "content")
	differentBatch = proto.Clone(message.Batch).(*data.PacketBatch)
	differentBatch.HunterId = "another-edge"
	require.ErrorContains(t, verifier.Verify(receipt, message.Identity, differentBatch), "identity")
}
func TestReceiptReadinessAndRetirementSignatures(t *testing.T) {
	signer, verifier := receiptAuthority(t, "central-authority")
	identity := custodyTestMessage(1).Identity
	for _, retired := range []bool{false, true} {
		receipt := &data.RawPacketReceipt{Identity: proto.Clone(identity).(*data.RawPacketIdentity), Retired: retired}
		require.NoError(t, signer.Sign(receipt))
		require.NoError(t, verifier.Verify(receipt, identity, nil))
	}
	require.Error(t, signer.Sign(nil))
	require.Error(t, signer.Sign(&data.RawPacketReceipt{}))
	require.Error(t, verifier.Verify(nil, identity, nil))
	require.Error(t, verifier.Verify(&data.RawPacketReceipt{}, nil, nil))
	_, err := BatchDigest(nil)
	require.Error(t, err)
}
func TestRawIdentityRejectsAmbiguousOrUnboundedIdentifiers(t *testing.T) {
	for _, value := range []string{"", "source\x00", "source\n", "source\u2003", string([]byte{0xff})} {
		identity := custodyTestMessage(1).Identity
		identity.SourceId = value
		require.Error(t, ValidIdentity(identity))
	}
	identity := custodyTestMessage(1).Identity
	identity.ProtoReflect().SetUnknown([]byte{0x38, 1})
	require.Error(t, ValidIdentity(identity), "unknown identity fields must not create aliases for the same producer")
}
