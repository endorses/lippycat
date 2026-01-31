# Common Workflows

## Basic VoIP Monitoring

**Goal:** Monitor SIP/RTP traffic on a local interface.

1. Start the TUI:
   ```bash
   sudo lc watch
   ```
2. Press `p` to open protocol selector
3. Select "VoIP (SIP/RTP)"
4. Monitor calls in real-time
5. Press `v` to toggle between packets and calls view
6. Press `d` to show/hide packet details

## Filtering Traffic

**Goal:** Find specific calls or packets.

1. Press `/` to enter filter mode
2. Type filter expression:
   - `from:alice` - Calls from alice
   - `ip:192.168.1.100` - Specific IP
   - `callid:12345` - Specific call
3. Press `Enter` to apply
4. Repeat to stack filters (AND logic)
5. Press `c` to remove last filter
6. Press `C` to clear all filters

## Save Capture to File

**Goal:** Export packets to PCAP for analysis.

1. Capture traffic with filters applied
2. Press `w` to open save dialog
3. Enter filename or navigate directories
4. Press `Enter` to save
5. For continuous capture:
   - First `w` starts streaming save
   - Second `w` stops and finalizes

## Distributed Capture

**Goal:** Monitor traffic across multiple network segments.

### On Each Edge Node (Hunter):
```bash
sudo lc hunt voip -i eth0 \
  --processor central:55555 \
  --tls --tls-ca ca.crt
```

### On Central Node (Processor):
```bash
lc process --listen 0.0.0.0:55555 \
  --per-call-pcap \
  --tls --tls-cert server.crt --tls-key server.key
```

### From TUI (Remote Monitoring):
```bash
lc watch remote --nodes-file nodes.yaml
```

1. Go to Nodes tab (`Alt+2`)
2. Press `a` to add processor node
3. Press `s` to select which hunters to subscribe to
4. Return to Capture tab (`Alt+1`) to view packets

## Analyzing PCAP Files

**Goal:** Review captured traffic offline.

```bash
lc watch file -r capture.pcap
```

1. Use `/` to filter packets
2. Press `d` to view packet details
3. Use `j`/`k` to navigate packets
4. Press `v` to switch to calls view (VoIP)

## Managing Nodes

**Goal:** Configure distributed capture topology.

1. Go to Nodes tab (`Alt+2`)
2. Press `v` to toggle table/graph view
3. Press `a` to add nodes
4. Press `d` to delete selected node
5. Press `s` to manage hunter subscriptions
6. Press `f` to configure filters on hunters

## Troubleshooting Steps

### No Packets Showing
1. Check capture is not paused (press `Space`)
2. Verify interface with `lc list interfaces`
3. Check protocol filter with `p`
4. Clear filters with `C`

### High CPU Usage
1. Use `--udp-only` for VoIP capture
2. Add BPF filter: `--bpf "port 5060"`
3. Limit buffer: `--buffer-size 1000`

### TLS Connection Issues
1. Verify certificates match
2. Check `LIPPYCAT_PRODUCTION` environment
3. Use `--insecure` for testing only
