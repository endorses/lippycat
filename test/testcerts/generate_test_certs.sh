#!/bin/bash
# Generate test TLS certificates for integration testing
# DO NOT use these certificates in production - they are for testing only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔐 Generating test TLS certificates for lippycat integration tests..."
echo "⚠️  WARNING: These certificates are for TESTING ONLY"
echo

# Clean up old certificates
rm -f *.pem *.key *.csr *.srl

# 1. Generate CA (Certificate Authority)
echo "1. Generating CA certificate..."
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca-cert.pem -subj "/C=US/ST=Test/L=Test/O=Lippycat Test CA/CN=Lippycat Test CA"

# 2. Generate server certificate (for processor)
echo "2. Generating processor server certificate..."
openssl genrsa -out processor-key.pem 4096
openssl req -new -key processor-key.pem -out processor.csr -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=processor.test.local"

# Create server certificate extensions
cat > processor-ext.cnf <<EOF
subjectAltName = DNS:processor.test.local,DNS:localhost,IP:127.0.0.1,IP:::1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days 3650 -sha256 -in processor.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out processor-cert.pem -extfile processor-ext.cnf

# 3. Generate hunter client certificate
echo "3. Generating hunter client certificate..."
openssl genrsa -out hunter-key.pem 4096
openssl req -new -key hunter-key.pem -out hunter.csr -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=hunter.test.local"

# Create client certificate extensions
cat > hunter-ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 3650 -sha256 -in hunter.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out hunter-cert.pem -extfile hunter-ext.cnf

# 4. Generate TUI/remote capture client certificate
echo "4. Generating TUI client certificate..."
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=client.test.local"

openssl x509 -req -days 3650 -sha256 -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem -extfile hunter-ext.cnf

# 5. Generate upstream processor certificate (for hierarchical setup)
echo "5. Generating upstream processor certificate..."
openssl genrsa -out upstream-key.pem 4096
openssl req -new -key upstream-key.pem -out upstream.csr -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=upstream.test.local"

openssl x509 -req -days 3650 -sha256 -in upstream.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out upstream-cert.pem -extfile processor-ext.cnf

# 6. Create combined client cert+key files (for convenience)
echo "6. Creating combined certificate files..."
cat hunter-cert.pem hunter-key.pem > hunter-combined.pem
cat client-cert.pem client-key.pem > client-combined.pem
cat processor-cert.pem processor-key.pem > processor-combined.pem
cat upstream-cert.pem upstream-key.pem > upstream-combined.pem

# Clean up intermediate files
rm -f *.csr *.srl *.cnf

# Set restrictive permissions
chmod 600 *.pem

echo
echo "✅ Test certificates generated successfully!"
echo
echo "Files created:"
echo "  - ca-cert.pem, ca-key.pem          (Certificate Authority)"
echo "  - processor-cert.pem, processor-key.pem  (Processor server)"
echo "  - hunter-cert.pem, hunter-key.pem        (Hunter client)"
echo "  - client-cert.pem, client-key.pem        (TUI/Remote client)"
echo "  - upstream-cert.pem, upstream-key.pem    (Upstream processor)"
echo "  - *-combined.pem                   (Combined cert+key files)"
echo
echo "Usage in tests:"
echo "  - CA Certificate: ca-cert.pem"
echo "  - Processor: processor-cert.pem + processor-key.pem"
echo "  - Hunter: hunter-cert.pem + hunter-key.pem"
echo "  - Client: client-cert.pem + client-key.pem"
echo
echo "⚠️  Remember: These are TEST CERTIFICATES ONLY!"
echo "    Do NOT use in production environments."
