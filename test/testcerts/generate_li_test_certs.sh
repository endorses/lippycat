#!/bin/bash
# Generate test TLS certificates for LI security testing
# DO NOT use these certificates in production - they are for testing only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating LI-specific test TLS certificates..."
echo "WARNING: These certificates are for TESTING ONLY"
echo

# Create LI-specific subdirectory
mkdir -p li

# 1. Generate LI CA (Certificate Authority)
echo "1. Generating LI CA certificate..."
openssl genrsa -out li/ca-key.pem 2048
openssl req -new -x509 -days 3650 -key li/ca-key.pem -sha256 -out li/ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat LI Test CA/CN=Lippycat LI Test CA"

# 2. Generate X1 server certificate
echo "2. Generating X1 server certificate..."
openssl genrsa -out li/x1-server-key.pem 2048
openssl req -new -key li/x1-server-key.pem -out li/x1-server.csr \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=x1-server.test.local"

cat > li/x1-server-ext.cnf <<EOF
subjectAltName = DNS:x1-server.test.local,DNS:localhost,IP:127.0.0.1,IP:::1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days 3650 -sha256 -in li/x1-server.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
    -CAcreateserial -out li/x1-server-cert.pem -extfile li/x1-server-ext.cnf

# 3. Generate ADMF client certificate (for connecting to X1 server)
echo "3. Generating ADMF client certificate..."
openssl genrsa -out li/admf-client-key.pem 2048
openssl req -new -key li/admf-client-key.pem -out li/admf-client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=admf-client.test.local"

cat > li/client-ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 3650 -sha256 -in li/admf-client.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
    -CAcreateserial -out li/admf-client-cert.pem -extfile li/client-ext.cnf

# 4. Generate MDF server certificate (for X2/X3 delivery endpoint)
echo "4. Generating MDF server certificate..."
openssl genrsa -out li/mdf-server-key.pem 2048
openssl req -new -key li/mdf-server-key.pem -out li/mdf-server.csr \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=mdf-server.test.local"

cat > li/mdf-server-ext.cnf <<EOF
subjectAltName = DNS:mdf-server.test.local,DNS:localhost,IP:127.0.0.1,IP:::1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -days 3650 -sha256 -in li/mdf-server.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
    -CAcreateserial -out li/mdf-server-cert.pem -extfile li/mdf-server-ext.cnf

# 5. Generate delivery client certificate (NE -> MDF)
echo "5. Generating delivery client certificate..."
openssl genrsa -out li/delivery-client-key.pem 2048
openssl req -new -key li/delivery-client-key.pem -out li/delivery-client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=delivery-client.test.local"

openssl x509 -req -days 3650 -sha256 -in li/delivery-client.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
    -CAcreateserial -out li/delivery-client-cert.pem -extfile li/client-ext.cnf

# 6. Generate EXPIRED certificate (for testing rejection of expired certs)
echo "6. Generating EXPIRED certificate..."
openssl genrsa -out li/expired-key.pem 2048
openssl req -new -key li/expired-key.pem -out li/expired.csr \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=expired.test.local"

# Create certificate that expired (1 day validity, backdated)
# Use faketime if available, otherwise create a short-lived cert
openssl x509 -req -sha256 -in li/expired.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
    -CAcreateserial -out li/expired-cert.pem -extfile li/client-ext.cnf -days 1

# Now we create a truly expired cert by manipulating the dates with openssl ca
# Alternative: Create a self-signed expired cert
openssl req -new -x509 -key li/expired-key.pem -sha256 -out li/expired-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Lippycat Test/CN=expired.test.local" \
    -days -1 2>/dev/null || {
    # If -days -1 doesn't work, create a very short validity cert
    # We'll just use a 1-day cert and document that tests should check date handling
    openssl x509 -req -sha256 -in li/expired.csr -CA li/ca-cert.pem -CAkey li/ca-key.pem \
        -CAcreateserial -out li/expired-cert.pem -extfile li/client-ext.cnf -days 1
    echo "  Note: Created 1-day cert since truly expired cert generation failed"
}

# 7. Generate SELF-SIGNED certificate (not signed by CA, for testing CA validation)
echo "7. Generating SELF-SIGNED certificate (not signed by CA)..."
openssl genrsa -out li/selfsigned-key.pem 2048
openssl req -new -x509 -days 3650 -key li/selfsigned-key.pem -sha256 -out li/selfsigned-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Unknown Issuer/CN=selfsigned.test.local"

# 8. Generate WRONG-CA signed certificate (signed by different CA)
echo "8. Generating certificate signed by WRONG CA..."
openssl genrsa -out li/wrong-ca-key.pem 2048
openssl req -new -x509 -days 3650 -key li/wrong-ca-key.pem -sha256 -out li/wrong-ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Wrong CA/CN=Wrong CA"

openssl genrsa -out li/wrong-ca-client-key.pem 2048
openssl req -new -key li/wrong-ca-client-key.pem -out li/wrong-ca-client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Wrong Org/CN=wrong-ca-client.test.local"
openssl x509 -req -days 3650 -sha256 -in li/wrong-ca-client.csr \
    -CA li/wrong-ca-cert.pem -CAkey li/wrong-ca-key.pem \
    -CAcreateserial -out li/wrong-ca-client-cert.pem -extfile li/client-ext.cnf

# Clean up intermediate files
rm -f li/*.csr li/*.cnf li/*.srl

# Set permissions readable for tests
chmod 644 li/*.pem

echo
echo "LI test certificates generated successfully!"
echo
echo "Files created in li/ directory:"
echo "  - ca-cert.pem, ca-key.pem                   (LI Certificate Authority)"
echo "  - x1-server-cert.pem, x1-server-key.pem     (X1 Server)"
echo "  - admf-client-cert.pem, admf-client-key.pem (ADMF Client)"
echo "  - mdf-server-cert.pem, mdf-server-key.pem   (MDF Server)"
echo "  - delivery-client-cert.pem, delivery-client-key.pem (Delivery Client)"
echo "  - expired-cert.pem, expired-key.pem         (Expired certificate)"
echo "  - selfsigned-cert.pem, selfsigned-key.pem   (Self-signed, no CA)"
echo "  - wrong-ca-client-cert.pem, wrong-ca-client-key.pem (Wrong CA)"
echo
echo "WARNING: These are TEST CERTIFICATES ONLY!"
