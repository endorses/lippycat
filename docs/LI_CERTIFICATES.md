# LI Certificate Management

This guide covers certificate generation and management for ETSI X1/X2/X3 lawful interception interfaces.

## Certificate Architecture

LI interfaces require mutual TLS with separate certificate chains:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Certificate Chains                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐           ┌─────────────────────────────────┐ │
│  │    ADMF CA      │           │           LI CA                 │ │
│  │  (admf-ca.crt)  │           │     (for NE certificates)       │ │
│  └────────┬────────┘           └────────────┬────────────────────┘ │
│           │                                 │                      │
│           │                    ┌────────────┼────────────┐         │
│           │                    │            │            │         │
│           ▼                    ▼            ▼            ▼         │
│  ┌────────────────┐   ┌──────────────┐ ┌──────────┐ ┌──────────┐  │
│  │  ADMF Client   │   │ X1 Server    │ │X1 Client │ │ Delivery │  │
│  │  Certificate   │   │ Certificate  │ │   Cert   │ │   Cert   │  │
│  │ (used by ADMF) │   │(processor)   │ │(→ ADMF)  │ │(→ MDF)   │  │
│  └────────────────┘   └──────────────┘ └──────────┘ └──────────┘  │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐                                                │
│  │     MDF CA      │                                                │
│  │  (mdf-ca.crt)   │                                                │
│  └────────┬────────┘                                                │
│           │                                                         │
│           ▼                                                         │
│  ┌────────────────┐                                                 │
│  │   MDF Server   │                                                 │
│  │  Certificate   │                                                 │
│  │ (used by MDF)  │                                                 │
│  └────────────────┘                                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Required Certificates

| Certificate | Purpose | Used By | Verifies |
|-------------|---------|---------|----------|
| X1 Server Cert | X1 HTTPS server | Processor | - |
| X1 Server Key | X1 server private key | Processor | - |
| ADMF CA | Verify ADMF clients | Processor | ADMF client certs |
| X1 Client Cert | X1 notifications to ADMF | Processor | - |
| X1 Client Key | X1 client private key | Processor | - |
| ADMF Server CA | Verify ADMF server | Processor | ADMF server cert |
| Delivery Cert | X2/X3 delivery to MDF | Processor | - |
| Delivery Key | Delivery private key | Processor | - |
| MDF CA | Verify MDF servers | Processor | MDF server certs |

## Quick Setup (Development)

Generate self-signed certificates for testing:

```bash
#!/bin/bash
# generate-li-certs.sh

# Create directory structure
mkdir -p certs/li/{ca,x1-server,x1-client,delivery}
cd certs/li

# Generate LI CA
openssl genrsa -out ca/li-ca.key 4096
openssl req -new -x509 -days 3650 -key ca/li-ca.key \
  -out ca/li-ca.crt -subj "/CN=LI CA/O=Organization/C=US"

# Generate X1 Server Certificate
openssl genrsa -out x1-server/x1-server.key 2048
openssl req -new -key x1-server/x1-server.key \
  -out x1-server/x1-server.csr \
  -subj "/CN=processor.example.com/O=Organization/C=US"

cat > x1-server/x1-server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = processor.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in x1-server/x1-server.csr \
  -CA ca/li-ca.crt -CAkey ca/li-ca.key -CAcreateserial \
  -out x1-server/x1-server.crt -days 365 \
  -extfile x1-server/x1-server.ext

# Generate X1 Client Certificate (for ADMF notifications)
openssl genrsa -out x1-client/x1-client.key 2048
openssl req -new -key x1-client/x1-client.key \
  -out x1-client/x1-client.csr \
  -subj "/CN=lippycat-processor/O=Organization/C=US"

cat > x1-client/x1-client.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in x1-client/x1-client.csr \
  -CA ca/li-ca.crt -CAkey ca/li-ca.key -CAcreateserial \
  -out x1-client/x1-client.crt -days 365 \
  -extfile x1-client/x1-client.ext

# Generate Delivery Client Certificate (for MDF delivery)
openssl genrsa -out delivery/delivery.key 2048
openssl req -new -key delivery/delivery.key \
  -out delivery/delivery.csr \
  -subj "/CN=lippycat-delivery/O=Organization/C=US"

cat > delivery/delivery.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in delivery/delivery.csr \
  -CA ca/li-ca.crt -CAkey ca/li-ca.key -CAcreateserial \
  -out delivery/delivery.crt -days 365 \
  -extfile delivery/delivery.ext

# Set secure permissions
chmod 600 */*.key
chmod 644 */*.crt

echo "Certificates generated in certs/li/"
```

## Production Setup

### Using a PKI

For production, obtain certificates from your organization's PKI:

1. **Generate CSRs** (Certificate Signing Requests)
2. **Submit to CA** for signing
3. **Install signed certificates**

### Key Requirements

| Attribute | Requirement |
|-----------|-------------|
| Key Algorithm | RSA 2048+ or ECDSA P-256+ |
| Hash Algorithm | SHA-256 or stronger |
| Key Usage | See per-certificate table below |
| Validity | Organization policy (typically 1-3 years) |

### Certificate Extensions

**X1 Server Certificate:**
```
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
```

**X1/Delivery Client Certificates:**
```
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
```

### Subject Alternative Names

For X1 Server certificate, include all hostnames and IPs:

```
subjectAltName = @alt_names

[alt_names]
DNS.1 = processor.example.com
DNS.2 = processor-01.internal
IP.1 = 10.0.1.100
IP.2 = 192.168.1.50
```

## Configuration

### Processor Configuration

```yaml
# /etc/lippycat/config.yaml
processor:
  li:
    enabled: true

    # X1 Server (receives from ADMF)
    x1_listen_addr: ":8443"
    x1_tls_cert: "/etc/lippycat/li/x1-server.crt"
    x1_tls_key: "/etc/lippycat/li/x1-server.key"
    x1_tls_ca: "/etc/lippycat/li/admf-ca.crt"  # Verify ADMF clients

    # X1 Client (notifications to ADMF)
    admf_endpoint: "https://admf.example.com:8443"
    admf_tls_cert: "/etc/lippycat/li/x1-client.crt"
    admf_tls_key: "/etc/lippycat/li/x1-client.key"
    admf_tls_ca: "/etc/lippycat/li/admf-server-ca.crt"  # Verify ADMF server

    # X2/X3 Delivery (to MDF)
    delivery_tls_cert: "/etc/lippycat/li/delivery.crt"
    delivery_tls_key: "/etc/lippycat/li/delivery.key"
    delivery_tls_ca: "/etc/lippycat/li/mdf-ca.crt"  # Verify MDF servers
```

### Command Line

```bash
lc process \
  --li-enabled \
  --li-x1-listen :8443 \
  --li-x1-tls-cert /etc/lippycat/li/x1-server.crt \
  --li-x1-tls-key /etc/lippycat/li/x1-server.key \
  --li-x1-tls-ca /etc/lippycat/li/admf-ca.crt \
  --li-admf-endpoint https://admf.example.com:8443 \
  --li-admf-tls-cert /etc/lippycat/li/x1-client.crt \
  --li-admf-tls-key /etc/lippycat/li/x1-client.key \
  --li-admf-tls-ca /etc/lippycat/li/admf-server-ca.crt \
  --li-delivery-tls-cert /etc/lippycat/li/delivery.crt \
  --li-delivery-tls-key /etc/lippycat/li/delivery.key \
  --li-delivery-tls-ca /etc/lippycat/li/mdf-ca.crt
```

## Certificate Pinning

For enhanced security, pin X2/X3 delivery certificates:

### Get Certificate Fingerprint

```bash
# Get SHA256 fingerprint of MDF certificate
openssl x509 -in mdf-server.crt -noout -fingerprint -sha256 | \
  sed 's/://g' | cut -d= -f2
```

### Configure Pinning

```bash
# Command line
--li-delivery-tls-pinned-cert sha256:A1B2C3D4E5...

# Config file
processor:
  li:
    delivery_tls_pinned_cert:
      - "sha256:A1B2C3D4E5F6..."
      - "sha256:F1E2D3C4B5A6..."  # Backup cert
```

## Certificate Rotation

### Before Expiration

1. Generate new certificate with same key (if policy allows) or new key
2. Update processor configuration
3. Restart processor (graceful)
4. Verify connections

### Rotation Script

```bash
#!/bin/bash
# rotate-li-certs.sh

# Check expiration
CERT=$1
DAYS_BEFORE=30

expiry=$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)
expiry_epoch=$(date -d "$expiry" +%s)
now_epoch=$(date +%s)
days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

if [ $days_left -lt $DAYS_BEFORE ]; then
    echo "Certificate expires in $days_left days. Rotation needed."
    # Trigger rotation workflow
fi
```

### Monitoring Expiration

Add to monitoring:

```bash
# Check certificate expiration
openssl x509 -in /etc/lippycat/li/x1-server.crt -noout -checkend 2592000
if [ $? -ne 0 ]; then
    echo "WARN: Certificate expires within 30 days"
fi
```

## Troubleshooting

### Certificate Verification

```bash
# Verify certificate chain
openssl verify -CAfile ca/li-ca.crt x1-server/x1-server.crt

# Check certificate details
openssl x509 -in x1-server/x1-server.crt -noout -text

# Check key matches certificate
openssl x509 -noout -modulus -in x1-server.crt | openssl md5
openssl rsa -noout -modulus -in x1-server.key | openssl md5
# MD5 hashes should match
```

### Common Errors

**"x509: certificate signed by unknown authority"**
- CA certificate not provided or wrong CA
- Check `--li-x1-tls-ca` or `--li-delivery-tls-ca`

**"x509: certificate has expired"**
- Certificate validity period ended
- Generate new certificate

**"tls: bad certificate"**
- Certificate rejected by peer
- Check key usage extensions match purpose
- Verify SAN includes hostname/IP

**"tls: client didn't provide a certificate"**
- Client not configured with certificate
- Mutual TLS requires client cert
- Check `--li-admf-tls-cert` and `--li-delivery-tls-cert`

### Debug TLS Handshake

```bash
# Test X1 server
openssl s_client -connect localhost:8443 \
  -cert x1-client.crt -key x1-client.key \
  -CAfile li-ca.crt

# Test delivery connection
openssl s_client -connect mdf.example.com:443 \
  -cert delivery.crt -key delivery.key \
  -CAfile mdf-ca.crt
```

## Security Best Practices

1. **Separate CAs** for ADMF and MDF if operated by different entities
2. **Short-lived certificates** (1 year or less) for automated rotation
3. **Hardware security modules** (HSM) for production key storage
4. **Certificate revocation** via CRL or OCSP
5. **Audit logging** of certificate operations
6. **Least privilege** - separate keys for different purposes
7. **Certificate transparency** for public-facing certificates

## File Permissions

```bash
# Private keys - owner read only
chmod 600 /etc/lippycat/li/*.key
chown root:root /etc/lippycat/li/*.key

# Certificates - world readable
chmod 644 /etc/lippycat/li/*.crt

# Directory
chmod 700 /etc/lippycat/li/
```

## Related Documentation

- [LI_INTEGRATION.md](LI_INTEGRATION.md) - LI deployment guide
- [SECURITY.md](SECURITY.md) - General security configuration
