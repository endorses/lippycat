# API Key Authentication

This document describes the API key authentication feature for lippycat processor nodes.

## Overview

API key authentication provides a lightweight alternative to mutual TLS (mTLS) for authenticating hunters and TUI clients connecting to processor nodes. It is designed for deployments where:

- Certificate management overhead is not desirable
- mTLS infrastructure is not available
- Simpler authentication is preferred for development/testing

**Production Recommendation:** For production deployments, mTLS (mutual TLS with client certificates) provides stronger security. API key authentication should be combined with TLS encryption at minimum.

## Security Model

### Authentication Flow

1. Client (hunter or TUI) sends API key in gRPC metadata header `x-api-key`
2. Processor validates the API key against configured keys
3. Processor checks if the key's role matches the required permission
4. Request is allowed or denied based on validation result

### Roles

API keys have one of three roles:

- **`hunter`** - Can register as hunter and send packet batches
- **`subscriber`** - Can subscribe to packet streams, topology updates, and monitoring APIs
- **`admin`** - Can perform all operations (future use for management APIs)

Admin role satisfies all role requirements (acts as a wildcard).

## Configuration

### Processor Configuration

Add API key configuration to your config file (e.g., `~/.config/lippycat/config.yaml`):

```yaml
security:
  api_keys:
    enabled: true
    keys:
      - key: "hunter-production-abc123def456"
        role: "hunter"
        description: "Production hunters in datacenter A"
      - key: "hunter-edge-xyz789ghi012"
        role: "hunter"
        description: "Edge hunters in remote locations"
      - key: "tui-monitoring-jkl345mno678"
        role: "subscriber"
        description: "Monitoring TUI clients"
      - key: "admin-ops-pqr901stu234"
        role: "admin"
        description: "Operations team admin access"
```

**Key Requirements:**
- Keys should be cryptographically random (minimum 32 characters recommended)
- Use a secure key generator (e.g., `openssl rand -base64 32`)
- Never commit keys to version control

### Enable via Flag

```bash
lc process --api-key-auth --listen :50051
```

This enables API key authentication using keys defined in the config file.

### Production Mode Enforcement

When `LIPPYCAT_PRODUCTION=true` is set, the processor requires **either**:
- Mutual TLS (`--tls-client-auth`), **or**
- API key authentication (`--api-key-auth`)

Without one of these, the processor will refuse to start.

## Client Configuration

### Hunter Configuration

Hunters must provide an API key when connecting to a processor with API key authentication enabled.

**Via Flag:**
```bash
lc hunt --processor processor:50051 \
  --api-key "hunter-production-abc123def456"
```

**Via Config File:**
```yaml
hunter:
  processor_addr: "processor:50051"
  api_key: "hunter-production-abc123def456"
```

**Via Environment Variable:**
```bash
export LIPPYCAT_API_KEY="hunter-production-abc123def456"
lc hunt --processor processor:50051
```

### TUI Configuration

TUI clients must provide an API key when connecting to remote processors:

**Via Flag:**
```bash
lc tui --remote \
  --nodes-file nodes.yaml \
  --api-key "tui-monitoring-jkl345mno678"
```

**Via Config File:**
```yaml
tui:
  remote: true
  nodes_file: "nodes.yaml"
  api_key: "tui-monitoring-jkl345mno678"
```

**Via Environment Variable:**
```bash
export LIPPYCAT_API_KEY="tui-monitoring-jkl345mno678"
lc tui --remote --nodes-file nodes.yaml
```

## Generating API Keys

Use a cryptographically secure random generator:

```bash
# Generate a 32-byte (256-bit) random key, base64 encoded
openssl rand -base64 32

# Example output:
# 7xK9mP2qN5wR8tV1yU4hG6jL0oI3eA7sD9fX2cB5nM8=
```

**Best Practices:**
- Generate unique keys for each hunter/client group
- Use descriptive descriptions for audit trails
- Rotate keys periodically
- Store keys securely (e.g., secrets management system)

## Audit Logging

Failed authentication attempts are logged with structured context:

```json
{
  "time": "2025-11-01T16:30:45Z",
  "level": "WARN",
  "msg": "Authentication failed: invalid API key",
  "key_prefix": "hunter-p****",
  "operation": "/data.DataService/RegisterHunter",
  "client_info": "grpc-go/1.50.0"
}
```

Successful authentications are logged at debug level:

```json
{
  "time": "2025-11-01T16:30:46Z",
  "level": "DEBUG",
  "msg": "Authentication successful",
  "description": "Production hunters in datacenter A",
  "role": "hunter"
}
```

## Security Considerations

### When to Use API Key Authentication

**Suitable for:**
- Development and testing environments
- Internal networks with controlled access
- Environments where certificate management is impractical
- Combined with TLS encryption for transport security

**Not suitable for:**
- Public-facing deployments without TLS
- Environments with strict compliance requirements (prefer mTLS)
- Untrusted networks

### Security Best Practices

1. **Always use TLS encryption** - API keys are sent in cleartext over the connection
2. **Never log full API keys** - Use the masking function (logs first 8 chars + "****")
3. **Rotate keys regularly** - Especially after team member changes
4. **Use role-based keys** - Don't use admin keys for hunters/subscribers
5. **Monitor failed auth attempts** - Set up alerts for repeated failures
6. **Secure key storage** - Use secrets management (Vault, AWS Secrets Manager, etc.)
7. **Principle of least privilege** - Grant only the minimum required role

### Comparison with mTLS

| Feature | API Key Auth | Mutual TLS |
|---------|-------------|------------|
| **Ease of setup** | Simple | Complex |
| **Key management** | Manual rotation | Certificate lifecycle |
| **Transport security** | Requires separate TLS | Built-in |
| **Identity verification** | Key-based | Certificate-based |
| **Compliance** | May not meet requirements | Industry standard |
| **Performance** | Minimal overhead | TLS handshake overhead |
| **Audit trail** | Logged by description | Logged by CN/DN |

## Method-Role Mapping

The following table shows which role is required for each gRPC method:

### Data Service Methods

| Method | Required Role |
|--------|--------------|
| `RegisterHunter` | `hunter` |
| `SendPacketBatch` | `hunter` |
| `SubscribeToPackets` | `subscriber` |
| `GetTopology` | `subscriber` |
| `TopologyUpdates` | `subscriber` |

### Management Service Methods

| Method | Required Role |
|--------|--------------|
| `GetHealth` | `subscriber` |
| `GetMetrics` | `subscriber` |
| `GetHunters` | `subscriber` |
| `GetCalls` | `subscriber` |
| `UpdateCallFilters` | `admin` |
| `UpdateProtocolFilters` | `admin` |
| `GetProcessorInfo` | `subscriber` |

**Note:** Admin role satisfies all requirements.

## Troubleshooting

### Authentication Failures

**Problem:** `Authentication failed: invalid API key`

**Solutions:**
1. Verify the API key is correct (check for typos)
2. Ensure the key is defined in the processor's config file
3. Check if the processor was restarted after config changes
4. Verify the key hasn't been removed or rotated

**Problem:** `Authentication failed: insufficient permissions`

**Solutions:**
1. Check the role of your API key
2. Ensure hunter keys are used for hunters, subscriber keys for TUI
3. Consider using an admin key if multiple roles are needed

**Problem:** `Authentication failed: missing API key in metadata`

**Solutions:**
1. Ensure `--api-key` flag is provided
2. Check config file has `api_key` field set
3. Verify environment variable `LIPPYCAT_API_KEY` is exported
4. Ensure the hunter/TUI client is sending the key in metadata

### Configuration Issues

**Problem:** `API key authentication enabled but no keys configured`

**Solution:** Add at least one key to `security.api_keys.keys` in config file

**Problem:** Processor refuses to start in production mode

**Solution:** Enable either `--tls-client-auth` (mTLS) or `--api-key-auth`

## Example Deployment

### Processor Setup

```yaml
# /etc/lippycat/processor-config.yaml
processor:
  listen_addr: "0.0.0.0:50051"
  processor_id: "central-processor"
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"

security:
  api_keys:
    enabled: true
    keys:
      - key: "{{ HUNTER_API_KEY }}"  # Injected from secrets manager
        role: "hunter"
        description: "Production hunters"
      - key: "{{ TUI_API_KEY }}"     # Injected from secrets manager
        role: "subscriber"
        description: "Monitoring clients"
```

```bash
# Start processor
LIPPYCAT_PRODUCTION=true \
  lc process \
  --config /etc/lippycat/processor-config.yaml \
  --tls \
  --api-key-auth
```

### Hunter Setup

```bash
# Hunter connects with API key
lc hunt \
  --processor central-processor:50051 \
  --tls \
  --tls-ca /etc/lippycat/certs/ca.crt \
  --api-key "${HUNTER_API_KEY}"
```

### TUI Setup

```bash
# TUI monitors remotely with API key
lc tui \
  --remote \
  --nodes-file nodes.yaml \
  --api-key "${TUI_API_KEY}"
```

## Implementation Details

### Package: `internal/pkg/auth`

**Files:**
- `types.go` - Core types (Config, APIKey, Role, errors)
- `validator.go` - API key validation logic
- `interceptor.go` - gRPC interceptors for authentication
- `validator_test.go` - Unit tests

**Integration Points:**
- `internal/pkg/processor/processor.go` - Adds interceptors to gRPC server
- `cmd/process/process.go` - Loads config and passes to processor
- `cmd/hunt/hunt.go` - Sends API key in metadata (future)
- `cmd/tui/tui.go` - Sends API key in metadata (future)

### gRPC Metadata

API keys are transmitted in gRPC metadata with key `x-api-key`:

```go
// Client-side
md := metadata.New(map[string]string{
    "x-api-key": apiKey,
})
ctx := metadata.NewOutgoingContext(ctx, md)

// Server-side (automatic via interceptor)
md, _ := metadata.FromIncomingContext(ctx)
apiKeyValues := md.Get("x-api-key")
```

## Related Documentation

- [Security Documentation](SECURITY.md) - Overall security architecture
- [TLS/mTLS Setup](SECURITY.md#tlsmtls) - Certificate-based authentication
- [Processor Configuration](../cmd/process/README.md) - Full processor options
- [Hunter Configuration](../cmd/hunt/README.md) - Full hunter options
- [TUI Configuration](../cmd/tui/README.md) - Full TUI options

## Changelog

- **v0.2.6** - Initial implementation (Phase 1.3)
  - API key authentication for processors
  - Role-based access control (hunter, subscriber, admin)
  - gRPC metadata-based transport
  - Audit logging for auth failures
  - Production mode enforcement
