# Test TLS Certificates

This directory contains test TLS certificates for integration testing of lippycat's secure communication features.

## ⚠️ WARNING: TEST CERTIFICATES ONLY

**DO NOT use these certificates in production environments.**

These certificates are:
- Generated with predictable keys
- **Committed to version control** for convenience and reproducibility
- Valid for 10 years (excessive for production)
- Not rotated regularly
- Used for automated testing only
- Excluded from security scanners (see `.gitguardian.yaml`)

## Why Are Test Certificates Committed?

Test certificates are committed to version control for developer convenience:
- ✅ **Immediate test execution**: TLS integration tests run without setup
- ✅ **Reproducible tests**: Everyone uses identical certificates
- ✅ **CI/CD simplicity**: No certificate generation step required
- ✅ **No security risk**: Clearly marked as test-only, excluded from scanners

This is a common practice in open-source projects (Kubernetes, Istio, etc.).

## Generating Test Certificates

The certificates are already generated and committed. To regenerate them:

```bash
cd test/testcerts
./generate_test_certs.sh
```

This will create:
- **CA Certificate**: `ca-cert.pem`, `ca-key.pem` - Certificate Authority for signing
- **Processor Server**: `processor-cert.pem`, `processor-key.pem` - Processor node TLS server
- **Hunter Client**: `hunter-cert.pem`, `hunter-key.pem` - Hunter node TLS client
- **TUI Client**: `client-cert.pem`, `client-key.pem` - Remote capture client
- **Upstream Processor**: `upstream-cert.pem`, `upstream-key.pem` - Hierarchical processor

## Certificate Details

### CA Certificate
- **Subject**: `/C=US/ST=Test/L=Test/O=Lippycat Test CA/CN=Lippycat Test CA`
- **Validity**: 10 years
- **Key Size**: 4096-bit RSA
- **Usage**: Sign server and client certificates

### Processor Server Certificate
- **Subject**: `/C=US/ST=Test/L=Test/O=Lippycat Test/CN=processor.test.local`
- **SAN**: `DNS:processor.test.local`, `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`
- **Extended Key Usage**: `serverAuth`
- **Usage**: TLS server for processor gRPC endpoint

### Hunter Client Certificate
- **Subject**: `/C=US/ST=Test/L=Test/O=Lippycat Test/CN=hunter.test.local`
- **Extended Key Usage**: `clientAuth`
- **Usage**: Mutual TLS authentication from hunter to processor

### TUI Client Certificate
- **Subject**: `/C=US/ST=Test/L=Test/O=Lippycat Test/CN=client.test.local`
- **Extended Key Usage**: `clientAuth`
- **Usage**: Mutual TLS authentication from TUI/CLI to processor

## Usage in Integration Tests

### Go Test Code

```go
// Load CA certificate
caCert, err := os.ReadFile("testcerts/ca-cert.pem")
require.NoError(t, err)
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

// Load server certificate (processor)
serverCert, err := tls.LoadX509KeyPair("testcerts/processor-cert.pem", "testcerts/processor-key.pem")
require.NoError(t, err)

// Create TLS config for processor server
serverTLSConfig := &tls.Config{
    MinVersion:   tls.VersionTLS13,
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
}

// Load client certificate (hunter)
clientCert, err := tls.LoadX509KeyPair("testcerts/hunter-cert.pem", "testcerts/hunter-key.pem")
require.NoError(t, err)

// Create TLS config for hunter client
clientTLSConfig := &tls.Config{
    MinVersion:   tls.VersionTLS13,
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    ServerName:   "processor.test.local",
}
```

### Docker Compose

```yaml
services:
  processor:
    environment:
      - LIPPYCAT_TLS_ENABLED=true
      - LIPPYCAT_TLS_CERT=/certs/processor-cert.pem
      - LIPPYCAT_TLS_KEY=/certs/processor-key.pem
      - LIPPYCAT_TLS_CA=/certs/ca-cert.pem
      - LIPPYCAT_TLS_CLIENT_AUTH=true
    volumes:
      - ./testcerts:/certs:ro
```

## Production Certificates

For production use, generate certificates properly:

```bash
# Use proper certificate authority (Let's Encrypt, internal CA)
# Use shorter validity periods (90 days recommended)
# Use certificate rotation
# Use hardware security modules (HSM) for key storage
# Use proper DNS names, not test.local
# Never commit production certificates to version control
```

See [docs/SECURITY.md](../../docs/SECURITY.md) for production TLS setup.

## Regenerating Certificates

The certificates are valid for 10 years, but you may need to regenerate them if:
- Test requirements change
- Certificate format changes
- OpenSSL version changes

Simply run:

```bash
./generate_test_certs.sh
```

Existing certificates will be replaced.

## Troubleshooting

### "certificate has expired"
Regenerate the certificates with `./generate_test_certs.sh`.

### "x509: certificate is not valid for any names"
Check that the ServerName in the client TLS config matches the certificate SAN:
- Use `ServerName: "processor.test.local"` for processor
- Use `ServerName: "localhost"` for localhost testing

### "x509: certificate signed by unknown authority"
Ensure the CA certificate is loaded into the client's RootCAs pool.

### Permission denied
The script sets restrictive permissions (600) on all `.pem` and `.key` files. This is intentional for security.
