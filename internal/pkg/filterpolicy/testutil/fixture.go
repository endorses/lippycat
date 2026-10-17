// Package testutil provides private temporary signing fixtures for policy tests.
package testutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func Config(t testing.TB) (filterpolicy.Config, crypto.Signer) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"authority.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "policy-private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "authority.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "authority.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	return filterpolicy.Config{Mode: "shared", Domain: "capture", AuthorityID: "central", TrustedCertFile: cert, SigningKeyFile: keyFile, StateFile: filepath.Join(dir, "policy.state"), Startup: "wait"}, key
}

// Encrypted provisions a fresh encrypted state explicitly for tests. It never
// attempts to recover or replace existing initialization evidence.
func Encrypted(t testing.TB, c filterpolicy.Config) filterpolicy.Config {
	t.Helper()
	keyFile := filepath.Join(filepath.Dir(c.StateFile), "policy-storage.key")
	key := make([]byte, securestore.KeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	clear(key)
	c.StorageProtection = "encrypted"
	c.StorageKeys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "capture-policy", File: keyFile}}
	if err := filterpolicy.Initialize(c); err != nil {
		t.Fatal(err)
	}
	return c
}
