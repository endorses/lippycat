# Security Features

This document describes the security enhancements available in lippycat for protecting sensitive VoIP traffic data.

## Overview

Lippycat includes four primary security enhancements:

1. **TLS Transport Encryption** - Protects hunter-processor communication in transit
2. **Call-ID Sanitization** - Prevents information leakage in log files
3. **PCAP File Encryption** - Protects captured traffic data at rest
4. **Content-Length Bounds Validation** - Prevents DoS attacks via memory exhaustion

These features are designed for sensitive deployments where VoIP traffic data requires additional protection.

## Table of Contents

- [TLS Transport Encryption](#tls-transport-encryption)
- [Call-ID Sanitization](#call-id-sanitization)
- [PCAP File Encryption](#pcap-file-encryption)
- [Content-Length Bounds Validation](#content-length-bounds-validation)
- [Security Best Practices](#security-best-practices)

## TLS Transport Encryption

### Purpose

In distributed mode, hunters forward captured network traffic to processor nodes via gRPC. This communication includes:
- Complete packet payloads (potentially containing sensitive data)
- Network topology information
- SIP credentials and authentication data
- RTP media streams
- Internal IP addresses and network configuration

**Without TLS encryption, this data is transmitted in cleartext**, making it vulnerable to:
- Man-in-the-middle (MitM) attacks
- Network eavesdropping
- Traffic injection and tampering
- Unauthorized access to captured data

### Security Model

Lippycat enforces TLS by default in v0.2.0+ with a **secure-by-default** approach:

- ✅ **TLS Required**: Hunters and processors refuse to start without TLS unless explicitly allowed
- ✅ **Mutual TLS Supported**: Processor can require client certificates for hunter authentication
- ✅ **Certificate Verification**: Server certificates validated against trusted CA by default
- ⚠️ **Insecure Mode**: Requires explicit `--insecure` flag with prominent warnings

### Quick Start

#### 1. Generate Certificates

For testing and development, use self-signed certificates:

```bash
# Create certificate directory
mkdir -p /etc/lippycat/certs
cd /etc/lippycat/certs

# Generate CA private key and certificate
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -subj "/CN=Lippycat CA"

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server-req.pem \
  -subj "/CN=processor.example.com"

# Create server certificate extensions with SANs (REQUIRED)
cat > server-cert.conf <<EOF
subjectAltName = DNS:processor.example.com,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

# Sign server certificate with CA and SANs
openssl x509 -req -in server-req.pem -days 365 \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -extfile server-cert.conf

# Generate client private key (for mutual TLS)
openssl genrsa -out client-key.pem 4096

# Generate client certificate signing request
openssl req -new -key client-key.pem -out client-req.pem \
  -subj "/CN=hunter-01.example.com"

# Create client certificate extensions
cat > client-cert.conf <<EOF
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req -in client-req.pem -days 365 \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem -extfile client-cert.conf

# Clean up intermediate files
rm -f *.conf server-req.pem client-req.pem

# Set restrictive permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem
```

**Important Notes:**
- **Subject Alternative Names (SANs) are required** - Modern Go versions reject certificates using only Common Name (CN)
- Replace `processor.example.com` with your actual processor hostname or IP address
- Add multiple SANs if needed: `DNS:processor,DNS:processor.local,IP:10.0.1.100`
- For IP-only access, use: `subjectAltName = IP:192.168.1.100,IP:127.0.0.1`

#### 2. Start Processor with TLS

```bash
# Server TLS (one-way authentication)
lippycat process \
  --listen 0.0.0.0:50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/server-cert.pem \
  --tls-key /etc/lippycat/certs/server-key.pem

# Mutual TLS (two-way authentication - recommended)
lippycat process \
  --listen 0.0.0.0:50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/server-cert.pem \
  --tls-key /etc/lippycat/certs/server-key.pem \
  --tls-client-auth \
  --tls-ca /etc/lippycat/certs/ca-cert.pem
```

#### 3. Start Hunter with TLS

```bash
# Basic TLS (verify server certificate)
lippycat hunt \
  --processor processor.example.com:50051 \
  --interface eth0 \
  --tls \
  --tls-ca /etc/lippycat/certs/ca-cert.pem

# Mutual TLS (present client certificate)
lippycat hunt \
  --processor processor.example.com:50051 \
  --interface eth0 \
  --tls \
  --tls-cert /etc/lippycat/certs/client-cert.pem \
  --tls-key /etc/lippycat/certs/client-key.pem \
  --tls-ca /etc/lippycat/certs/ca-cert.pem
```

### Configuration via YAML

For production deployments, use configuration files:

```yaml
# ~/.config/lippycat/config.yaml

# Processor configuration
processor:
  listen_addr: "0.0.0.0:50051"
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server-cert.pem"
    key_file: "/etc/lippycat/certs/server-key.pem"
    ca_file: "/etc/lippycat/certs/ca-cert.pem"
    client_auth: true  # Require client certificates

# Hunter configuration
hunter:
  processor_addr: "processor.example.com:50051"
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/client-cert.pem"
    key_file: "/etc/lippycat/certs/client-key.pem"
    ca_file: "/etc/lippycat/certs/ca-cert.pem"
```

Then start without command-line flags:

```bash
lippycat process  # Uses config file
lippycat hunt --interface eth0  # Uses config file
```

### TLS Modes

#### 1. Server TLS (One-Way Authentication)

**Use case:** Encrypt traffic, verify processor identity

```
Hunter                    Processor
  |                           |
  |---- TLS Handshake ------->|
  |<--- Server Certificate ----|
  | (verify cert)              |
  |<--- Encrypted Channel ---->|
```

**Configuration:**

```bash
# Processor: Present server certificate
lippycat process --tls --tls-cert server.crt --tls-key server.key

# Hunter: Verify server certificate
lippycat hunt --tls --tls-ca ca.crt --processor host:50051
```

**Security:** Protects against eavesdropping, but hunters are not authenticated.

#### 2. Mutual TLS (Two-Way Authentication) ⭐ Recommended

**Use case:** Encrypt traffic + authenticate both hunter and processor

```
Hunter                    Processor
  |                           |
  |---- TLS Handshake ------->|
  |<--- Server Certificate ----|
  | (verify server cert)       |
  |---- Client Certificate --->|
  |     (processor verifies)   |
  |<--- Encrypted Channel ---->|
```

**Configuration:**

```bash
# Processor: Require client certificates
lippycat process \
  --tls \
  --tls-cert server.crt \
  --tls-key server.key \
  --tls-client-auth \
  --tls-ca ca.crt

# Hunter: Present client certificate
lippycat hunt \
  --tls \
  --tls-cert client.crt \
  --tls-key client.key \
  --tls-ca ca.crt \
  --processor host:50051
```

**Security:** Strongest option - mutual authentication prevents unauthorized hunters.

#### 3. Insecure Mode (No TLS) ⚠️

**Use case:** Testing on localhost or trusted internal networks only

```bash
# Processor: Explicitly allow insecure
lippycat process --insecure

# Hunter: Explicitly allow insecure
lippycat hunt --insecure --processor localhost:50051
```

**Warning:** Prominent security banners displayed on startup:

```
═══════════════════════════════════════════════════════════
  SECURITY WARNING: TLS ENCRYPTION DISABLED
  Packet data will be transmitted in CLEARTEXT
  This mode should ONLY be used in trusted networks
  Enable TLS for production: --tls --tls-ca=/path/to/ca.crt
═══════════════════════════════════════════════════════════
```

### Production Certificate Setup

For production deployments, use proper certificate management:

#### Option 1: Internal Certificate Authority

Recommended for most deployments:

```bash
# 1. Set up CA infrastructure
mkdir -p /secure/ca/{certs,private}
cd /secure/ca

# 2. Create CA
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout private/ca-key.pem -out certs/ca-cert.pem \
  -subj "/C=US/ST=State/L=City/O=YourOrg/CN=YourOrg Root CA"

# 3. Create certificate config
cat > server-cert.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = YourOrg
CN = processor.yourorg.internal

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = processor.yourorg.internal
DNS.2 = processor
IP.1 = 10.0.1.100
EOF

# 4. Generate and sign server certificate
openssl req -new -newkey rsa:4096 -nodes \
  -keyout private/server-key.pem \
  -out server-req.pem \
  -config server-cert.conf

openssl x509 -req -in server-req.pem \
  -CA certs/ca-cert.pem -CAkey private/ca-key.pem \
  -CAcreateserial -out certs/server-cert.pem \
  -days 365 -extensions v3_req -extfile server-cert.conf

# 5. Distribute CA certificate to all hunters
# 6. Generate client certificates for each hunter
```

#### Option 2: Commercial Certificate Authority

For internet-facing deployments:

1. Purchase certificate from trusted CA (Let's Encrypt, DigiCert, etc.)
2. Install certificate on processor
3. Hunters automatically trust well-known CAs

```bash
# No --tls-ca needed for well-known CAs
lippycat hunt --tls --processor processor.example.com:50051
```

### Certificate Management

#### Certificate Expiration

Monitor certificate expiration:

```bash
# Check certificate validity
openssl x509 -in /etc/lippycat/certs/server-cert.pem -noout -dates

# Set up expiration monitoring
0 0 * * * /usr/local/bin/check-cert-expiry.sh
```

#### Certificate Rotation

Zero-downtime certificate rotation:

```bash
# 1. Generate new certificate
openssl genrsa -out server-key-new.pem 4096
openssl req -new -key server-key-new.pem -out server-req-new.pem
openssl x509 -req -in server-req-new.pem -CA ca-cert.pem \
  -CAkey ca-key.pem -out server-cert-new.pem -days 365

# 2. Update processor config
vim /etc/lippycat/config.yaml
# Change cert_file and key_file paths

# 3. Reload processor (graceful)
systemctl reload lippycat-processor

# 4. Verify new certificate in use
openssl s_client -connect processor:50051 -showcerts
```

#### Revocation

To revoke compromised certificates:

1. Remove certificate from CA signing list
2. Restart processor to disconnect affected hunters
3. Generate and distribute new certificates
4. Update hunter configurations

### Troubleshooting

#### "TLS is disabled but --insecure flag not set"

**Cause:** Attempting to start without TLS or explicit insecure flag

**Solution:**
```bash
# Enable TLS (recommended)
lippycat hunt --tls --tls-ca ca.crt --processor host:50051

# OR explicitly allow insecure (testing only)
lippycat hunt --insecure --processor host:50051
```

#### "certificate relies on legacy Common Name field, use SANs instead"

**Cause:** Certificate was generated without Subject Alternative Names (SANs). Modern Go versions require SANs and reject certificates using only Common Name (CN).

**Solution:**
```bash
# Regenerate certificate with SANs
cd /etc/lippycat/certs

# Create config with SANs
cat > server-cert.conf <<EOF
subjectAltName = DNS:your-processor-hostname,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

# Generate new server certificate
openssl genrsa -out server-key-new.pem 4096
openssl req -new -key server-key-new.pem -out server-req.pem \
  -subj "/CN=your-processor-hostname"
openssl x509 -req -in server-req.pem -days 365 \
  -CA ca-cert.pem -CAkey ca-key.pem \
  -out server-cert-new.pem -extfile server-cert.conf

# Replace old certificate
mv server-cert-new.pem server-cert.pem
mv server-key-new.pem server-key.pem
rm server-req.pem server-cert.conf

# Verify SANs are present
openssl x509 -in server-cert.pem -noout -text | grep -A1 "Subject Alternative Name"
```

#### "Failed to verify certificate"

**Cause:** Certificate validation failed (wrong CA, hostname mismatch, expired)

**Solution:**
```bash
# Check certificate details
openssl x509 -in server-cert.pem -noout -text

# Verify hostname matches
openssl x509 -in server-cert.pem -noout -subject

# Check for SANs (required)
openssl x509 -in server-cert.pem -noout -text | grep -A1 "Subject Alternative Name"

# For testing, skip verification (INSECURE)
lippycat hunt --tls --tls-skip-verify --processor host:50051
```

#### "No client certificate provided"

**Cause:** Processor requires client certificates but hunter didn't provide one

**Solution:**
```bash
# Provide client certificate
lippycat hunt \
  --tls \
  --tls-cert client.crt \
  --tls-key client.key \
  --tls-ca ca.crt \
  --processor host:50051
```

#### "Certificate has expired"

**Cause:** Certificate validity period has passed

**Solution:**
```bash
# Check expiration
openssl x509 -in cert.pem -noout -enddate

# Generate new certificate
# (see Certificate Rotation section)
```

### Performance Impact

TLS encryption has minimal performance impact with modern hardware:

- **CPU**: ~2-5% overhead for TLS handshake and encryption
- **Latency**: +1-5ms for initial handshake, <1ms per packet thereafter
- **Throughput**: ~95-98% of non-TLS throughput on modern CPUs
- **Memory**: ~50KB per connection for TLS session state

**Hardware acceleration:** Modern CPUs with AES-NI provide near-zero overhead.

### Security Considerations

#### Threat Model

TLS protects against:
- ✅ Network eavesdropping (passive attacks)
- ✅ Man-in-the-middle attacks (active attacks)
- ✅ Traffic injection and tampering
- ✅ Unauthorized hunter connections (with mutual TLS)
- ✅ Replay attacks (via TLS nonce)

TLS does NOT protect against:
- ❌ Compromised hunter or processor hosts
- ❌ Malicious insiders with valid certificates
- ❌ Side-channel attacks (timing, power analysis)
- ❌ Vulnerabilities in application code

#### Defense in Depth

TLS is one layer in a comprehensive security strategy:

1. **Network Layer:** Firewall rules, network segmentation
2. **Transport Layer:** **TLS encryption (this feature)**
3. **Application Layer:** Call-ID sanitization, input validation
4. **Storage Layer:** PCAP file encryption
5. **Access Control:** OS-level permissions, SELinux/AppArmor
6. **Monitoring:** Log analysis, intrusion detection

#### Compliance

TLS encryption helps meet regulatory requirements:

- **GDPR:** Encryption of personal data in transit
- **HIPAA:** Protected health information (PHI) safeguards
- **PCI DSS:** Requirement 4 - Encrypt cardholder data in transit
- **SOX:** Data integrity and confidentiality controls
- **NIST 800-53:** SC-8 Transmission Confidentiality

### Best Practices

#### ✅ DO

- **Use mutual TLS in production** for strongest security
- **Use proper CA infrastructure** with internal or commercial CA
- **Monitor certificate expiration** with automated alerting
- **Rotate certificates regularly** (annually or per policy)
- **Use strong key sizes** (4096-bit RSA or 256-bit ECDSA)
- **Restrict certificate permissions** (600 for keys, 644 for certs)
- **Use configuration files** instead of command-line flags in production
- **Test TLS setup** in development before deploying to production

#### ❌ DON'T

- **Don't use --tls-skip-verify in production** (defeats certificate verification)
- **Don't use --insecure in production** (transmits sensitive data in cleartext)
- **Don't share private keys** across multiple systems
- **Don't commit certificates to git** (use secrets management)
- **Don't use weak key sizes** (<2048-bit RSA)
- **Don't ignore certificate expiration warnings**
- **Don't rely on TLS alone** (use defense-in-depth)

## Call-ID Sanitization

### Purpose

Call-IDs in SIP traffic often contain sensitive information such as:
- User identifiers
- Domain names
- Session tokens
- Internal system information

When logged, this information can lead to privacy breaches or expose internal network topology.

### How It Works

Call-ID sanitization uses SHA-256 hashing to create consistent but anonymized identifiers for logging:

```
Original:   john.doe@company.com-session-12345
Sanitized:  john.d...a1b2c3d4
```

This allows log correlation while preventing information leakage.

### Configuration

```yaml
voip:
  security:
    sanitize_call_ids: true           # Enable sanitization
    call_id_hash_length: 8            # Hash prefix length (4-16 bytes)
    call_id_max_log_length: 16        # Sanitization threshold
```

**Parameters:**
- `sanitize_call_ids`: Master toggle for Call-ID sanitization
- `call_id_hash_length`: Length of hash prefix (affects uniqueness)
- `call_id_max_log_length`: Call-IDs longer than this are sanitized

### Usage Examples

```go
// Logging with sanitization
logger.Info("Processing call", "call_id", SanitizeCallIDForLogging(callID))

// Display with sanitization
fmt.Printf("Call: %s\n", SanitizeCallIDForDisplay(callID))
```

## PCAP File Encryption

### Purpose

PCAP files contain complete network traffic, including:
- SIP signaling data
- RTP media streams
- Authentication credentials
- Network topology information

Encryption protects this data when stored on disk.

### How It Works

PCAP encryption uses **AES-256-GCM** with the following features:

- **Algorithm**: AES-256 in Galois/Counter Mode
- **Key Management**: Automatic key generation with PBKDF2
- **Authentication**: Built-in integrity protection via GCM
- **Nonce**: Unique nonce per data block prevents replay attacks

### File Format

Encrypted PCAP files use this structure:

```
[Header: Algorithm/Version info]
[Block 1: Length + Nonce + Encrypted Data]
[Block 2: Length + Nonce + Encrypted Data]
...
```

### Configuration

```yaml
voip:
  security:
    enable_pcap_encryption: true      # Enable PCAP encryption
  encryption:
    enabled: true                     # Master encryption toggle
    key_file: "/etc/lippycat/keys/pcap.key"  # Key file path
    algorithm: "aes-256-gcm"         # Encryption algorithm
    key_derive: "pbkdf2"             # Key derivation method
    pbkdf2_iterations: 100000        # PBKDF2 iterations
```

**Parameters:**
- `enable_pcap_encryption`: Master toggle for PCAP encryption
- `key_file`: Path to encryption key file (auto-generated if missing)
- `algorithm`: Encryption algorithm (only "aes-256-gcm" supported)
- `pbkdf2_iterations`: Key derivation iterations (minimum 10,000)

### Key Management

#### Automatic Key Generation

If the key file doesn't exist, lippycat automatically generates a new key:

```
WARN: Encryption key file not found, generating new key
INFO: Generated new encryption key file=/etc/lippycat/keys/pcap.key permissions=0600
```

#### Manual Key Management

For production deployments, manage keys manually:

```bash
# Generate key manually
openssl rand -out /secure/path/pcap.key 32

# Set restrictive permissions
chmod 600 /secure/path/pcap.key
chown lippycat:lippycat /secure/path/pcap.key
```

#### Key Rotation

To rotate encryption keys:

1. Stop lippycat
2. Move old key file: `mv pcap.key pcap.key.old`
3. Generate new key (automatic on restart)
4. Decrypt old files with old key if needed

### Usage

#### Creating Encrypted Writers

```go
// Create encrypted PCAP writer
writer, err := NewEncryptedPCAPWriter("capture.pcap")
if err != nil {
    log.Fatal("Failed to create encrypted writer:", err)
}
defer writer.Close()

// Write encrypted data
err = writer.WriteData(packetData)
```

#### Decrypting Files

```go
// Decrypt PCAP file for analysis
err := DecryptPCAPFile("capture.pcap.enc", "decrypted.pcap", "/path/to/key")
if err != nil {
    log.Fatal("Failed to decrypt PCAP:", err)
}
```

## Security Best Practices

### Development Environment

For development, security features can be disabled:

```yaml
voip:
  security:
    sanitize_call_ids: false
    enable_pcap_encryption: false
```

### Production Environment

For production deployments:

```yaml
voip:
  security:
    sanitize_call_ids: true
    call_id_hash_length: 12
    call_id_max_log_length: 8
    enable_pcap_encryption: true
  encryption:
    enabled: true
    key_file: "/secure/keys/lippycat-pcap.key"
    pbkdf2_iterations: 200000
```

### Key Storage

- Store encryption keys on secure, encrypted filesystems
- Use restrictive file permissions (600 or 400)
- Consider hardware security modules (HSMs) for high-security environments
- Implement key rotation procedures
- Backup keys securely and separately from data

### Monitoring

Monitor security feature usage:

```bash
# Check if encryption is working
lippycat debug metrics | grep -i encrypt

# Verify Call-ID sanitization
tail -f /var/log/lippycat.log | grep call_id
```

### Compliance

These features help with:
- **GDPR**: Call-ID sanitization reduces PII in logs
- **HIPAA**: Encryption protects healthcare communications
- **SOX**: Data integrity through authenticated encryption
- **PCI DSS**: Secure handling of payment card voice traffic

## Troubleshooting

### Common Issues

#### "Encryption key file not found"
**Cause**: Key file path doesn't exist or lacks permissions
**Solution**: Check path and permissions, or let lippycat generate automatically

#### "Failed to decrypt data"
**Cause**: Wrong key file or corrupted data
**Solution**: Verify key file matches the one used for encryption

#### "Unsupported encryption algorithm"
**Cause**: Configuration specifies unsupported algorithm
**Solution**: Use "aes-256-gcm" (only supported algorithm)

#### "PBKDF2 iterations too low"
**Cause**: Less than 10,000 iterations configured
**Solution**: Use at least 10,000 iterations (100,000+ recommended)

### Debugging

Enable debug logging for security features:

```yaml
log:
  level: debug

voip:
  security:
    sanitize_call_ids: true
  encryption:
    enabled: true
```

Check logs for security-related messages:

```bash
grep -i "encryption\|sanitiz" /var/log/lippycat.log
```

## Performance Impact

### Call-ID Sanitization

- **CPU**: Minimal (SHA-256 hashing is fast)
- **Memory**: Negligible additional allocation
- **Latency**: < 1μs per Call-ID

### PCAP Encryption

- **CPU**: ~5-10% overhead for AES-256-GCM
- **Storage**: ~1-2% size increase (nonce + auth tag overhead)
- **Memory**: Additional buffer allocation for encryption
- **Latency**: ~10-50μs per packet depending on size

### Recommendations

- Enable Call-ID sanitization in all environments (minimal impact)
- Enable PCAP encryption only for sensitive deployments
- Monitor performance metrics when enabling encryption
- Consider hardware acceleration for high-throughput environments

## Migration Guide

### Enabling Security Features

1. **Update Configuration**
   ```bash
   # Add security section to config
   vim /etc/lippycat/config.yaml
   ```

2. **Test in Development**
   ```bash
   # Test with sample traffic
   lippycat sniff --config dev-secure.yaml
   ```

3. **Deploy to Production**
   ```bash
   # Restart with new config
   systemctl reload lippycat
   ```

### Disabling Security Features

To disable security features (not recommended for production):

```yaml
voip:
  security:
    sanitize_call_ids: false
    enable_pcap_encryption: false
  encryption:
    enabled: false
```

This restores original behavior with no performance overhead.

## Content-Length Bounds Validation

### Purpose

SIP messages can include Content-Length headers that specify the size of message bodies. Without proper validation, attackers can:
- Cause memory exhaustion by specifying enormous Content-Length values
- Trigger integer overflow conditions
- Consume excessive server resources through DoS attacks

### How It Works

Content-Length bounds validation provides multiple layers of protection:

- **Input Validation**: Restricts Content-Length string length and format
- **Integer Overflow Protection**: Prevents arithmetic overflow during parsing
- **Memory Bounds Checking**: Enforces configurable limits on content and message sizes
- **Secure Parsing**: Uses safe parsing logic that stops at the first non-digit

### Configuration

```yaml
voip:
  security:
    max_content_length: 1048576     # Maximum Content-Length value (1MB)
    max_message_size: 2097152       # Maximum total SIP message size (2MB)
```

**Parameters:**
- `max_content_length`: Maximum allowed Content-Length header value in bytes
- `max_message_size`: Maximum allowed total SIP message size in bytes

### Security Features

#### Content-Length Parsing

The secure parser validates:
- String length (max 10 characters to prevent overflow)
- Numeric format (digits only, stops at first non-digit)
- Integer overflow protection during conversion
- Configurable maximum value limits

#### Attack Prevention

```go
// These attacks are prevented:
"999999999999999"    // Extremely large numbers
"2147483648"         // Integer overflow attempts
strings.Repeat("9", 20) // Long digit strings
"1073741824"         // 1GB memory allocation attempts
```

#### Error Handling

Security violations are logged with detailed information:

```
WARN: Content-Length security validation failed value=999999999 error="Content-Length exceeds maximum allowed: 999999999 > 1048576" source=tcp_stream
```

### Usage Examples

#### TCP Stream Processing

The validation is automatically applied during TCP SIP message processing:

```go
// In readCompleteSipMessage()
if length, parseErr := ParseContentLengthSecurely(lengthStr); parseErr == nil {
    contentLength = length
} else {
    logger.Warn("Content-Length security validation failed",
        "value", lengthStr, "error", parseErr)
    return nil, fmt.Errorf("invalid Content-Length: %w", parseErr)
}
```

#### Manual Validation

For custom implementations:

```go
// Validate Content-Length value
if err := ValidateContentLength(contentLength); err != nil {
    return fmt.Errorf("Content-Length validation failed: %w", err)
}

// Validate total message size
if err := ValidateMessageSize(len(messageBytes)); err != nil {
    return fmt.Errorf("Message size validation failed: %w", err)
}
```

### Configuration Examples

#### Development Environment
```yaml
voip:
  security:
    max_content_length: 10485760    # 10MB - generous for development
    max_message_size: 20971520      # 20MB - generous for development
```

#### Production Environment
```yaml
voip:
  security:
    max_content_length: 1048576     # 1MB - reasonable for production
    max_message_size: 2097152       # 2MB - reasonable for production
```

#### High-Security Environment
```yaml
voip:
  security:
    max_content_length: 65536       # 64KB - strict limit
    max_message_size: 131072        # 128KB - strict limit
```

### Performance Impact

Content-Length validation has minimal performance impact:

- **CPU**: < 1μs additional processing per Content-Length header
- **Memory**: No additional allocation for validation logic
- **Latency**: Negligible impact on message processing times

The security benefits far outweigh the minimal performance cost.

### Common Content-Length Attack Vectors

#### Memory Exhaustion
```
Content-Length: 1073741824
```
*Attempts to allocate 1GB of memory*

#### Integer Overflow
```
Content-Length: 999999999999999999
```
*Attempts to cause integer overflow during parsing*

#### Resource Consumption
```
Content-Length: 2147483647
```
*Attempts to consume maximum possible memory*

#### Format Attacks
```
Content-Length: 123456789012345678901234567890
```
*Attempts to exhaust parsing resources with long strings*

All of these attacks are prevented by the bounds validation system.

## Virtual Interface Security

**Status:** Production-ready (v0.2.10+)

Virtual interface creation requires elevated privileges. Follow these guidelines to minimize security risks.

### Privilege Requirements

Creating TAP/TUN devices requires the `CAP_NET_ADMIN` Linux capability.

**Required for:**
- `lc sniff --virtual-interface`
- `lc sniff voip --virtual-interface`
- `lc process --virtual-interface`

### Recommended Setup: File Capabilities

**Preferred method** - grants only the necessary capability without running as root:

```bash
# Grant CAP_NET_ADMIN to lippycat binary
sudo setcap cap_net_admin+ep /usr/local/bin/lc

# Verify capability
getcap /usr/local/bin/lc
# Output: /usr/local/bin/lc = cap_net_admin+ep

# Now run without sudo
lc sniff voip -i eth0 --virtual-interface
```

**Security benefits:**
- Process runs as regular user (not root)
- Only `CAP_NET_ADMIN` capability is granted (not all root capabilities)
- Capability is effective only when needed
- Follows principle of least privilege

**Capability is used for:**
1. Creating TAP/TUN device via netlink
2. Bringing interface up (`ip link set up`)
3. Opening `/dev/net/tun` for packet injection

### Alternative: Run as Root (Not Recommended)

```bash
sudo lc sniff voip -i eth0 --virtual-interface
```

**Security drawbacks:**
- Entire process runs with full root privileges
- Increased attack surface if process is compromised
- Violates principle of least privilege
- Not necessary with file capabilities

**Only use when:**
- File capabilities are not available
- Testing in containerized/isolated environments

### Privilege Dropping (Advanced)

**Status:** Available in v0.2.10+

For maximum security when running as root, lippycat can automatically drop privileges to a non-privileged user after creating the virtual interface.

**How it works:**
1. Process starts as root (or with `CAP_NET_ADMIN`)
2. Virtual interface is created and brought up
3. Process drops to specified user's UID/GID
4. Packet injection continues as unprivileged user

**Example usage:**

```bash
# Drop to 'nobody' user after interface creation
sudo lc sniff voip -i eth0 --virtual-interface --vif-drop-privileges nobody

# Drop to custom 'lippycat' user
sudo lc sniff voip -i eth0 --virtual-interface --vif-drop-privileges lippycat

# Processor node with privilege dropping
sudo lc process --listen :50051 --virtual-interface --vif-drop-privileges lippycat
```

**Configuration file:**

```yaml
virtual_interface:
  enabled: true
  name: lc0
  drop_privileges_user: lippycat
```

**Requirements:**
- Must run as root (UID 0) for privilege dropping to work
- Target user must exist on the system
- Go 1.16+ (privilege dropping fixed in Go 1.16)

**Security benefits:**
- Minimizes attack surface after interface creation
- Follows principle of least privilege
- Injection loop runs as unprivileged user
- Limits damage from potential process compromise

**Limitations:**
- Only works on Linux (no-op on other platforms)
- Requires running as root initially
- File capabilities (`setcap`) are still preferred for most use cases

**When to use:**
- Production deployments requiring maximum isolation
- Environments with strict security policies
- When combined with other security features (network namespaces, seccomp, etc.)

**When NOT to use:**
- If you can use file capabilities instead (`setcap cap_net_admin+ep`)
- Non-root deployments (privilege dropping is skipped)
- macOS/Windows (not supported)

### Permission Errors

If you encounter permission errors:

```
ERROR Failed to create virtual interface: operation not permitted
```

**Diagnosis:**
```bash
# Check if CAP_NET_ADMIN is set
getcap /usr/local/bin/lc

# Check if user has permissions
id -u  # Should show non-zero for regular user
```

**Solution:**
```bash
# Set file capability
sudo setcap cap_net_admin+ep /usr/local/bin/lc

# Verify
getcap /usr/local/bin/lc
```

### Access Control

Virtual interfaces are visible to all users on the system. To restrict access:

#### Option 1: File Descriptor Permissions (Current)

The `/dev/net/tun` device controls who can create interfaces:

```bash
# Check current permissions
ls -l /dev/net/tun
# Output: crw-rw-rw- 1 root root 10, 200 ...

# Restrict to root and specific group
sudo chgrp netdev /dev/net/tun
sudo chmod 660 /dev/net/tun

# Add user to netdev group
sudo usermod -aG netdev $USER
```

#### Option 2: Network Namespace Isolation (Production-ready)

Create virtual interfaces in isolated network namespaces for enhanced security.

```bash
# Create namespace
sudo ip netns add lippycat-isolated

# Run lippycat with interface in namespace
sudo lc sniff voip -i eth0 --virtual-interface --vif-netns lippycat-isolated

# Only tools in the namespace can access lc0
sudo ip netns exec lippycat-isolated wireshark -i lc0
```

**Benefits:**
- Complete isolation from host network stack
- Prevents unauthorized sniffing of virtual interface traffic
- Container-like security model
- Interface invisible to host network tools
- Additional layer of defense against privilege escalation

**Requirements:**
- `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` capabilities (or run as root)
- Network namespace must exist before starting lippycat

#### Option 3: Per-Tool Access Control (Advanced)

Control which users/tools can capture from the virtual interface using group-based permissions and interface ownership.

**Method 1: Interface Group Ownership**

After the interface is created, change its ownership to a specific group:

```bash
# Start lippycat (creates lc0 interface)
sudo lc sniff voip -i eth0 --virtual-interface &

# Wait for interface to be created
sleep 3

# Create a dedicated group for virtual interface access
sudo groupadd lippycat-monitor

# Add authorized users to the group
sudo usermod -aG lippycat-monitor alice
sudo usermod -aG lippycat-monitor bob

# Note: Interface permissions are controlled via /dev/net/tun
# To restrict interface access, combine with namespace isolation (Option 2)
```

**Method 2: Namespace + Group-based Access**

Combine namespace isolation with selective user access:

```bash
# Create namespace
sudo ip netns add lippycat-isolated

# Create monitoring group
sudo groupadd lippycat-monitor
sudo usermod -aG lippycat-monitor alice

# Run lippycat in namespace
sudo lc sniff voip -i eth0 --virtual-interface --vif-netns lippycat-isolated &

# Create wrapper script for authorized users
cat > /usr/local/bin/lc-monitor <<'EOF'
#!/bin/bash
# Only users in lippycat-monitor group can access
if ! groups | grep -q lippycat-monitor; then
    echo "ERROR: You must be in the lippycat-monitor group"
    exit 1
fi
sudo ip netns exec lippycat-isolated "$@"
EOF

sudo chmod 755 /usr/local/bin/lc-monitor
sudo chown root:lippycat-monitor /usr/local/bin/lc-monitor

# Configure sudo to allow lippycat-monitor group to execute ip netns
cat > /etc/sudoers.d/lippycat-monitor <<'EOF'
%lippycat-monitor ALL=(root) NOPASSWD: /usr/sbin/ip netns exec lippycat-isolated *
EOF
sudo chmod 440 /etc/sudoers.d/lippycat-monitor

# Now authorized users can access the interface
lc-monitor wireshark -i lc0       # alice can run this
lc-monitor tcpdump -i lc0 -nn     # bob can run this
```

**Method 3: Tool-Specific Capabilities**

Grant specific monitoring tools the ability to capture without full root access:

```bash
# Grant Wireshark/dumpcap the ability to capture
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap

# Grant tcpdump the ability to capture
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/tcpdump

# Now these tools can capture from lc0 without sudo
wireshark -i lc0
tcpdump -i lc0 -nn
```

**Best Practices for Per-Tool Access Control:**

1. **Namespace Isolation First:** Always use network namespace isolation as the primary security boundary
2. **Least Privilege:** Grant only the necessary capabilities to monitoring tools
3. **Group-based Access:** Use system groups to manage who can access monitoring tools
4. **Audit Logging:** Monitor and log all access to the virtual interface
5. **Regular Reviews:** Periodically review group memberships and tool capabilities

**Example Production Setup:**

```bash
# 1. Create isolated namespace
sudo ip netns add lippycat-prod

# 2. Create monitoring group
sudo groupadd lippycat-monitor
sudo usermod -aG lippycat-monitor security-team

# 3. Run lippycat with namespace isolation and privilege dropping
sudo lc sniff voip -i eth0 \
  --virtual-interface \
  --vif-netns lippycat-prod \
  --vif-drop-privileges lippycat

# 4. Configure sudo for authorized users
cat > /etc/sudoers.d/lippycat-monitor <<'EOF'
%lippycat-monitor ALL=(root) NOPASSWD: /usr/sbin/ip netns exec lippycat-prod /usr/bin/tcpdump *
%lippycat-monitor ALL=(root) NOPASSWD: /usr/sbin/ip netns exec lippycat-prod /usr/bin/wireshark *
%lippycat-monitor ALL=(root) NOPASSWD: /usr/sbin/ip netns exec lippycat-prod /usr/bin/tshark *
EOF

# 5. Authorized users can now monitor
sudo ip netns exec lippycat-prod wireshark -i lc0
```

**Creating persistent namespaces:**

```bash
# Create namespace (persists until deleted)
sudo ip netns add lippycat-isolated

# List namespaces
sudo ip netns list

# Access namespace
sudo ip netns exec lippycat-isolated bash

# Delete namespace
sudo ip netns delete lippycat-isolated
```

**Configuration file support:**

```yaml
# ~/.config/lippycat/config.yaml
sniff:
  virtual_interface: true
  vif_name: lc0
  vif_netns: lippycat-isolated

processor:
  virtual_interface: true
  vif_name: lc0
  vif_netns: lippycat-isolated
```

**Security implications:**
- Interface is completely isolated from the default namespace
- Only processes running in the target namespace can access the interface
- Namespace provides additional containment boundary
- Recommended for production deployments with strict security requirements

### Packet Integrity

Virtual interfaces only expose packets that:
1. Pass lippycat's capture filters
2. Pass protocol-specific filters (e.g., `--sipuser`)
3. Have valid checksums and headers

**Packets are NOT injected if:**
- Conversion to Ethernet/IP fails
- Payload is missing or malformed
- Injection queue is full (dropped, not delayed)

This prevents malformed packets from reaching downstream tools.

### Containerized Deployment

When running lippycat in Docker/Kubernetes:

```dockerfile
# Dockerfile
FROM debian:bookworm-slim

# Install lippycat
COPY lc /usr/local/bin/lc

# Grant capability in container
RUN setcap cap_net_admin+ep /usr/local/bin/lc

# Run as non-root user
USER lippycat:lippycat

CMD ["lc", "sniff", "voip", "--virtual-interface"]
```

**Docker run with required privileges:**
```bash
# Grant CAP_NET_ADMIN to container
docker run --cap-add=NET_ADMIN lippycat:latest
```

**Kubernetes deployment:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: lippycat
spec:
  containers:
  - name: lippycat
    image: lippycat:latest
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
      runAsNonRoot: true
      runAsUser: 1000
```

### Security Checklist

Before deploying virtual interface in production:

- [ ] Use file capabilities (`setcap`) instead of running as root
- [ ] Restrict `/dev/net/tun` permissions if needed (Option 1)
- [ ] Implement network namespace isolation (Option 2) - **Recommended**
- [ ] Configure per-tool access control via groups and sudo (Option 3)
- [ ] Set up privilege dropping with `--vif-drop-privileges` flag
- [ ] Grant only necessary capabilities to monitoring tools (`setcap`)
- [ ] Verify lippycat binary integrity (checksums, signatures)
- [ ] Use TLS encryption for distributed mode (hunter→processor)
- [ ] Monitor virtual interface creation/deletion logs
- [ ] Audit group memberships for monitoring access
- [ ] Validate downstream tool security (Wireshark, Snort, etc.)
- [ ] Implement monitoring for unauthorized interface creation
- [ ] Review and update sudoers rules regularly

### Threat Model

**Threats mitigated:**
- Unauthorized packet capture (via filtered stream)
- Privilege escalation (file capabilities vs. root)
- Memory exhaustion (bounded injection queue)
- Unauthorized interface access (namespace isolation + per-tool access control)
- Lateral movement (isolated namespaces prevent interface visibility)
- Unauthorized user access (group-based access control with sudo policies)

**Threats NOT mitigated (future work):**
- Packet tampering (read-only TAP/TUN, no ingress)
- Resource exhaustion by malicious tools (Phase 3: rate limiting)
- Side-channel attacks via packet timing analysis

### Performance vs. Security Trade-offs

| Setting | Security | Performance | Recommendation |
|---------|----------|-------------|----------------|
| `--vif-buffer-size 1024` | High (low memory) | Lower throughput | High-security environments |
| `--vif-buffer-size 4096` | Balanced | Balanced | Default (recommended) |
| `--vif-buffer-size 16384` | Lower (high memory) | Higher throughput | Trusted environments only |

**Guideline:** Use default buffer size unless justified by specific requirements.