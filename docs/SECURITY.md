# Security Features

This document describes the security enhancements available in lippycat for protecting sensitive VoIP traffic data.

## Overview

Lippycat includes three primary security enhancements:

1. **Call-ID Sanitization** - Prevents information leakage in log files
2. **PCAP File Encryption** - Protects captured traffic data at rest
3. **Content-Length Bounds Validation** - Prevents DoS attacks via memory exhaustion

These features are designed for sensitive deployments where VoIP traffic data requires additional protection.

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