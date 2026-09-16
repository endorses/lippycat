# HTTP Analysis

The HTTP analyzer reconstructs request/response pairs from TCP streams and measures response latency.

## Request/Response Correlation

lippycat tracks HTTP conversations by correlating requests with their responses on the same TCP connection. When correlation succeeds, the `RequestResponseTimeMs` field shows the server response time.

Start HTTP capture:

```bash
sudo lc sniff http -i eth0
```

Filter by host, path, method, or status code:

To filter by host:

```bash
sudo lc sniff http -i eth0 --host "*.example.com"
```

To filter by path pattern:

```bash
sudo lc sniff http -i eth0 --path "/api/*"
```

To capture only POST and PUT requests:

```bash
sudo lc sniff http -i eth0 --method "POST,PUT"
```

To capture only error responses:

```bash
sudo lc sniff http -i eth0 --status "4xx,5xx"
```

To combine filters:

```bash
sudo lc sniff http -i eth0 --host api.example.com --method POST --status "5xx"
```

## HTTP Metadata Fields

| Field         | Description                      | JSON Path                         |
| ------------- | -------------------------------- | --------------------------------- |
| Method        | GET, POST, PUT, DELETE, etc.     | `.HTTPData.Method`                |
| Path          | URL path                         | `.HTTPData.Path`                  |
| Host          | Host header                      | `.HTTPData.Host`                  |
| Status Code   | Response status                  | `.HTTPData.StatusCode`            |
| Content-Type  | Response content type            | `.HTTPData.ContentType`           |
| User-Agent    | Client identifier                | `.HTTPData.UserAgent`             |
| Response Time | Request-to-response latency (ms) | `.HTTPData.RequestResponseTimeMs` |

## Common HTTP Investigations

**Find slow API responses:**

```bash
sudo lc sniff http -i eth0 2>/dev/null | \
  jq -r 'select(.HTTPData.Type == "response" and .HTTPData.RequestResponseTimeMs > 500) |
    [.Timestamp, .HTTPData.Host, .HTTPData.Path,
     (.HTTPData.StatusCode|tostring),
     (.HTTPData.RequestResponseTimeMs|tostring) + "ms"] | @tsv'
```

**Monitor error rates:**

```bash
sudo lc sniff http -i eth0 2>/dev/null | \
  jq -r 'select(.HTTPData.Type == "response") |
    (.HTTPData.StatusCode|tostring|.[0:1]) + "xx"' | \
  sort | uniq -c | sort -rn
```

**Content type analysis:**

```bash
sudo lc sniff http -i eth0 2>/dev/null | \
  jq -r 'select(.HTTPData.ContentType != null and .HTTPData.ContentType != "") |
    .HTTPData.ContentType' | \
  sort | uniq -c | sort -rn
```

## HTTPS Decryption

For HTTPS traffic, lippycat can decrypt application data if you provide a TLS key log file (SSLKEYLOGFILE):

```bash
sudo lc sniff http -i eth0 --tls-keylog /tmp/sslkeys.log
```

This requires the application to export session keys. See [Security](security.md) for details on TLS decryption setup.

## Body Capture

By default, HTTP body content is not captured. Enable it for content inspection:

```bash
sudo lc sniff http -i eth0 --capture-body --max-body-size 65536
```

For keyword matching across many requests, use the Aho-Corasick bulk matcher:

```bash
sudo lc sniff http -i eth0 --capture-body --keywords-file suspicious-terms.txt
```
