# Filters

Press `/` on the Capture tab to enter filter mode. Filters stack with AND logic.

## Quick Reference

| Key | Action |
|-----|--------|
| `/` | Enter filter mode |
| `c` | Remove last filter |
| `C` | Clear all filters |
| `p` | Protocol selector |

## Text Search

Plain text searches all fields (IP, port, protocol, info):

```
192.168.1.1
5060
INVITE
```

## Field-Specific

Filter by specific field:

```
protocol:SIP
src:192.168.1.1
dst:10.0.0.1
info:INVITE
```

## VoIP/SIP Filters

Filter SIP packets by header fields. Supports wildcards (`*`).

| Filter | Description |
|--------|-------------|
| `sip.user:value` | From header username |
| `sip.from:value` | Same as sip.user |
| `sip.to:value` | To header |
| `sip.method:value` | SIP method (INVITE, BYE, etc.) |
| `sip.callid:value` | Call-ID header |
| `sip.fromtag:value` | From tag |
| `sip.totag:value` | To tag |

**Wildcards:**

```
sip.user:555*        # Starts with
sip.user:*@domain    # Ends with
sip.callid:*abc*     # Contains
```

## BPF-Style Filters

Berkeley Packet Filter syntax for network-level filtering:

**Protocols:**

```
tcp
udp
icmp
```

**Ports:**

```
port 5060
src port 5060
dst port 443
```

**Hosts:**

```
host 192.168.1.1
src host 192.168.1.1
dst host 10.0.0.1
```

**Networks:**

```
net 192.168.0.0/24
src net 10.0.0.0/8
dst net 172.16.0.0/12
```

## Metadata Filters

Filter by packet metadata:

```
has:voip       # Packets with VoIP metadata
```

## Node Filters

Filter by source node (distributed mode). Supports wildcards.

```
node:hunter-1       # Exact match
node:edge-*         # Prefix wildcard
node:*-kamailio     # Suffix wildcard
```

## Boolean Operators

Combine filters with boolean logic:

**AND:**

```
sip.user:alice AND port 5060
src:192.168.1.1 && protocol:SIP
```

**OR:**

```
sip.user:alice OR sip.user:bob
port 5060 || port 5061
```

**NOT:**

```
NOT protocol:ICMP
!sip.method:ACK
```

**Parentheses:**

```
(sip.user:alice OR sip.user:bob) AND port 5060
NOT (port 53 OR port 67)
```

## Filter Stacking

Each filter entered with `/` is AND-ed with existing filters:

1. `/` → `sip.user:alice` → Enter
2. `/` → `port 5060` → Enter
3. Result: SIP packets from alice on port 5060

Use `c` to remove the last filter, `C` to clear all.
