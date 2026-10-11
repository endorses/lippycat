# Synthetic demo traffic

Generate a mixed-protocol Ethernet PCAP for lippycat screenshots, recordings,
and interactive demonstrations. Generation opens no sockets and requires no
capture privileges. It uses the repository's existing Go dependencies.

From the repository root:

```bash
go run ./scripts/demo-traffic
```

The default output is `testdata/pcaps/demo-mixed.pcap`: 1,800 packets over one
minute at 30 packets per second. The capture has a fixed starting timestamp,
fictional `example.test` identities, documentation IPv4/IPv6 addresses, locally
administered MAC addresses, and silent PCMU media. DHCP discovery uses its normal
unspecified source and broadcast destination. Identical options produce identical
capture bytes. Generated PCAPs are ignored by Git.

Customize the destination, duration, and timestamp rate:

```bash
go run ./scripts/demo-traffic -output testdata/pcaps/demo-long.pcap -duration 2m -pps 45
```

The generator interleaves exchanges while preserving each flow's packet order.
TCP conversations include connection establishment, payload acknowledgments,
and orderly closes. A duration can end partway through the final cycle.

## Protocols and colors

The capture covers all seven color groups in the current TUI palette:

| Color   | Generated protocols |
| ------- | ------------------- |
| Yellow  | DNS, ARP            |
| Blue    | SIP                 |
| Green   | RTP, UDP            |
| Cyan    | TCP                 |
| Violet  | HTTP                |
| Magenta | TLS, SSH, WireGuard |
| Orange  | ICMP, ICMPv6        |

SMTP, IMAP, POP3, RADIUS, DHCP, and NTP add more protocol labels and detail fields;
they use the default foreground color. Tests decode the frames, verify wire
checksums and TCP sequence/acknowledgment accounting, and run lippycat's actual
protocol detector. ICMPv6 and plain TCP/UDP use the TUI's base protocol labels.

These are observations for presentation: TLS and SSH contain greeting exchanges,
WireGuard has deliberately invalid synthetic cryptographic fields, and RADIUS
uses placeholder authenticators. They do not establish working encrypted or
authenticated sessions. DHCP stops at the offer; IMAP/POP3 remain unauthenticated.

## Inspect the capture

```bash
./lc watch file testdata/pcaps/demo-mixed.pcap
```

File mode indexes the capture without paced playback. For packets visibly
scrolling through the list, use live replay.

## Flowing packets for a recording

On Linux, install `iproute2` and `tcpreplay` and build a lippycat binary that
includes `watch` (`make build`, for example). Run:

```bash
sudo scripts/demo-traffic/replay.sh
```

The helper creates a temporary virtual Ethernet pair, configures neither end
with an IP address, disables automatic IPv6 address configuration, and replays
the capture continuously into the pair. It opens `lc watch live` on the other
end in promiscuous mode, using an empty configuration file. No physical interface
is used. Quitting the TUI stops replay and removes the virtual interfaces and
temporary session files, including on normal interrupt/termination signals.

To use another capture, binary, or replay speed:

```bash
sudo scripts/demo-traffic/replay.sh testdata/pcaps/demo-mixed.pcap ./bin/lc-tui 20
```

The rate argument controls actual replay independently of the timestamps in the
capture. The helper uses [`tcpreplay --loop=0 --pps`](https://tcpreplay.appneta.com/reference/man/tcpreplay/).

For the packet-stream view, use a wide terminal so the packet list and details
fit side by side. Press `d` to show details, `h` or `Escape` to focus the packet
list, then `G` or `End` to follow the newest packet. Moving upward suspends
following. Press `p`, select **All**, and press `Enter` if a protocol filter is
active; `C` clears display filters. Press `q` to exit.

## Verification

```bash
go test -v ./scripts/demo-traffic
bash -n scripts/demo-traffic/replay.sh
```

The replay helper additionally needs Linux network-administration/capture
privileges and a terminal. Generator tests never create an interface or send
traffic.
