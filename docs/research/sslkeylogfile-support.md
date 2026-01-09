# SSLKEYLOGFILE Support Survey

**Date:** 2026-01-09
**Purpose:** Document SSLKEYLOGFILE (NSS Key Log Format) support across TLS implementations for Phase 7 TLS decryption planning.

## Overview

SSLKEYLOGFILE is a de facto standard format for logging TLS session keys, originally created by NSS (Mozilla's crypto library). It enables passive TLS decryption by tools like Wireshark without requiring private keys.

**Format (NSS Key Log):**
```
# Each line: <label> <client_random_hex> <secret_hex>
CLIENT_RANDOM 1234...abcd 5678...efgh
```

## Support Matrix

### Web Servers

| Server | Support | Version | Mechanism | Notes |
|--------|---------|---------|-----------|-------|
| **Caddy** | ✅ Native | v2.6.0+ (Sep 2022) | Environment variable | Uses Go's `KeyLogWriter` |
| **Apache** | ✅ Native | 2.4.49+ | Environment variable | Requires OpenSSL 1.1.1+ |
| **nginx Plus** | ✅ Native | R33+ (Nov 2024) | `ssl_key_log` directive | Commercial only |
| **nginx OSS** | ❌ Rejected | - | Third-party only | Maintainer refused patch |

### Programming Languages / Libraries

| Language | Library | Support | Mechanism |
|----------|---------|---------|-----------|
| **Go** | crypto/tls | ✅ Native | `tls.Config.KeyLogWriter` |
| **Python** | ssl | ⚠️ Manual | No native env var support |
| **Node.js** | tls | ✅ Native | `keylog` event on TLS sockets |
| **OpenSSL** | 1.1.1+ | ✅ Native | `SSL_CTX_set_keylog_callback()` |
| **Java** | JSSE | ⚠️ Manual | Custom implementation required |

### Client Applications

| Application | Support | Mechanism |
|-------------|---------|-----------|
| **Firefox** | ✅ Native | `SSLKEYLOGFILE` env var |
| **Chrome/Chromium** | ✅ Native | `SSLKEYLOGFILE` env var |
| **curl** | ✅ Native | `SSLKEYLOGFILE` env var |
| **wget** | ✅ Native | `SSLKEYLOGFILE` env var |

## Detailed Notes

### Apache httpd

Added in Apache 2.4.49 via OpenSSL's `SSL_CTX_set_keylog_callback()`.

**Usage:**
```bash
# Set environment variable before starting Apache
export SSLKEYLOGFILE=/var/log/apache2/sslkeys.log
systemctl start apache2

# Or in systemd unit file
# /etc/systemd/system/apache2.service.d/override.conf
[Service]
Environment="SSLKEYLOGFILE=/var/log/apache2/sslkeys.log"
```

**Caveats:**
- Some distributions disable this feature by default (e.g., FreeBSD requires DEBUG build option)
- Not a config directive - must be set as environment variable
- Requires OpenSSL 1.1.1+

**Sources:**
- [mod_ssl documentation](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)
- [FreeBSD forum discussion](https://forums.freebsd.org/threads/decryption-tls1-3-on-server-side-apache24.80936/)

### nginx

**nginx Plus (Commercial):**

Native support added in R33 (November 2024) with `ssl_key_log` directive.

```nginx
server {
    listen 443 ssl;
    ssl_key_log /tmp/sslkey.log;
    # ...
}
```

Also supports `proxy_ssl_key_log`, `grpc_ssl_key_log`, and `uwsgi_ssl_key_log` for upstream connections.

**nginx Open Source:**

A patch was submitted in January 2024 to add SSLKEYLOGFILE support via a `debug_keylog` error log level. The patch was rejected by nginx maintainer Maxim Dounin:

> "Logging session keying material is known to be problematic from ethical point of view. As such, I would rather avoid introducing relevant functionality in nginx."

**Workarounds for nginx OSS:**

1. **Third-party module**: [nginx-sslkeylog](https://github.com/tiandrey/nginx-sslkeylog)
   - Requires OpenSSL 1.1.1+
   - Tested on nginx 1.20, 1.24
   - Requires patching nginx sources for TLSv1.3

2. **LD_PRELOAD method**: Preload a shared library that intercepts OpenSSL calls
   - No patching/rebuilding required
   - Works with any OpenSSL-based application

**Sources:**
- [nginx-devel patch submission](https://mailman.nginx.org/pipermail/nginx-devel/2024-January/W5CRPNYOC72XXFF45KQSD3VNNMGJ4WMR.html)
- [Maintainer rejection response](https://www.mail-archive.com/nginx-devel@nginx.org/msg14257.html)
- [nginx-sslkeylog module](https://github.com/tiandrey/nginx-sslkeylog)
- [NGINX Plus R33 release notes](https://community.f5.com/kb/technicalarticles/f5-nginx-plus-r33-release-now-available/336403)

### Caddy

Native support added in v2.6.0 (September 2022) via [PR #4808](https://github.com/caddyserver/caddy/pull/4808).

**Usage:**
```bash
export SSLKEYLOGFILE=/tmp/caddy-keys.log
caddy run
```

Leverages Go's built-in `crypto/tls.Config.KeyLogWriter`.

**Sources:**
- [Feature request #4668](https://github.com/caddyserver/caddy/issues/4668)
- [Implementation PR #4808](https://github.com/caddyserver/caddy/pull/4808)

### Go Applications

Any Go application using `crypto/tls` can enable key logging:

```go
keylogFile, _ := os.Create("/tmp/keys.log")
config := &tls.Config{
    KeyLogWriter: keylogFile,
}
```

### OpenSSL CLI

```bash
openssl s_client -connect example.com:443 -keylogfile /tmp/keys.log
```

## Security Considerations

- Key log files contain session secrets that can decrypt all captured TLS traffic
- Restrict file permissions (e.g., `chmod 600`)
- Never enable in production unless for authorized monitoring
- Clear/rotate key log files regularly
- Consider encrypted storage for key log files

## Implications for lippycat

For Protocol Expansion Phase 7 TLS decryption:

1. **Good coverage**: Apache, Caddy, nginx Plus, and Go applications have native support
2. **nginx OSS gap**: Requires third-party module or LD_PRELOAD - document workarounds
3. **Same-machine deployment**: Key log file must be accessible to lippycat capture node
4. **Named pipe support**: Useful for real-time key injection without file I/O
