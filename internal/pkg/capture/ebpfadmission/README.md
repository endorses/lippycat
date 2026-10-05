# Socket media admission

This Linux implementation attaches `BPF_PROG_TYPE_SOCKET_FILTER` to a libpcap
socket. It does not filter host forwarding. `Backend` owns maps; the capture
installer owns attached program handles and libpcap owns the socket descriptor.

`cilium/ebpf` v0.22.0 loads checked-in little/big-endian objects. The small C
program is dual MIT/GPL licensed, compatible with the repository's MIT license
and the kernel's GPL helper requirements. Ordinary builds require no clang.

The initial supported link type is Ethernet, including in-frame single/double
VLAN headers. Linux cooked capture is rejected at startup: its libpcap synthetic
header does not exist in the socket packet. Cooked expressions must not be
translated as though those bytes existed. Hardware-stripped VLAN metadata is
not needed by endpoint lookup (it sees the resulting Ethernet/IP frame); VLAN
capture expressions with offload are currently rejected by the installer until
metadata-aware predicate composition is supported.

The explicit classic predicate always executes first. `Translate` uses socket
`LD_ABS`/`LD_IND`, 32-bit classic arithmetic and skb wire length; unsupported
ancillary extensions fail at startup. Cloudflare cbpfc was evaluated and not
selected: its `ToEBPF` requires direct packet pointers, while Linux
`sk_filter_is_valid_access` explicitly forbids socket filters from reading
`__sk_buff.data` and `data_end`. Translation preserves predicate decisions; the
configured capture snapshot length determines accepted length. No dynamic
admission state may override explicit restrictions.

The immutable UDP-only, SIP-port and explicitly configured RTP-range options
are checked before shadow, degraded-open or independent-selector bypass. The
shared `voip.BuildAdmissionFilter` returns these separately from the classic
base predicate; callers must supply every field. No default RTP range is added.
UDP-only also rejects ESP even when ESP decapsulation is enabled. SIP-port
constraints apply to parsed signaling TCP/UDP; RTP ranges apply to recognized
media. Non-initial fragments cannot supply ports and retain packet-local
compatibility within the explicit base predicate.

After these constraints, admission conservatively passes complete allowed TCP input,
non-RTP UDP for arbitrary-port SIP discovery, configured SIP ports, IPv4/IPv6
fragments, bounded-parser unknown/truncated packets, VXLAN (4789/8472, including
ESP inside), and ESP when enabled. IPv6 extension walking is bounded at six
headers; deeper chains pass individually. These compatibility decisions are
counted and never change domain mode. RTP/RTCP-version-2 UDP with at least eight
payload bytes is rejected unless a source/destination endpoint, independent
address/prefix, no-filter policy, shadow mode or degraded-open scope admits it.
Userspace still validates and attributes every admitted candidate.

Endpoint maps are ordinary hashes without LRU eviction. Control hash entries
are preallocated independently of endpoint capacity. Selector replacement is a
multi-step operation: the controller must retain the appropriate degraded state
until full selector and endpoint reconciliation succeeds. Domain IDs must fit the
configured control-map size. Maps are shared across sockets in one backend.

Counters are per-domain/per-CPU. Optional shadow events use a bounded ring buffer,
monotonic timestamps and the control's confirmed generation. Sampling is explicit:
`--rtp-ebpf-shadow-sample-every N` samples approximately one in N decisions and
does not enable admission by itself. Header fingerprints are not unique packet
IDs. Complete frames up to 256 bytes provide transient exact-byte correlation;
larger or truncated frames have no complete identity. These bytes can include
payload and stay within the local bounded correlation state, expiring after two
configured `pending_ttl` intervals. Retained samples, status, logs and management
transport contain no frame bytes. Duplicate, late, missing, changed-lifetime or
changed-generation evidence remains incomplete. Classified counts describe sampled
observations, never all-traffic parity. Ring loss, retained overwrite, malformed
records, collection errors and correlation pressure have separate accounting.
Packet diagnostics drop on lock contention and invalidate overlapping correlation
windows rather than waiting for maintenance. Explicit predicate rejection
has its own counter and occurs before diagnostic event emission. Out-of-bounds
classic packet loads are rejected directly by the kernel without a counter event.

## Generation and tests

The recorded toolchain is clang 18.1.3, libbpf 1.3.0, Ubuntu 24.04. The Dockerfile
pins the base image digest; package repositories supply compiler/header packages.
Build it with `docker build -t lippycat-ebpf-toolchain:local
internal/pkg/capture/ebpfadmission`. Run `go generate` in this package with Go
1.25+, `BPF2GO_CC=clang-18`, and on Debian/Ubuntu
`BPF2GO_CFLAGS=-I/usr/include/x86_64-linux-gnu`. Both endian objects must be checked
in with generated Go files. Full verification runs in the documented compiler
container so header and compiler choice are explicit.

`go test ./internal/pkg/capture/ebpfadmission` runs object/translator/packing tests.
`LIPPYCAT_EBPF_TEST=1 go test -v ./internal/pkg/capture/ebpfadmission` also loads and
executes real kernel programs, requiring BPF privileges (use an isolated privileged
container). Without explicit opt-in these tests report skipped, not passed kernel
coverage. The `toolchain.sh generate` and `toolchain.sh test` entry points automate these
container invocations; all Go caches are ephemeral container files. Runtime requires ring buffer support (Linux 5.8+) plus permission to load
socket BPF, allocate maps and capture packets; loader errors are startup failures.

Linux's socket-filter `BPF_PROG_TEST_RUN` removes one Ethernet header, unlike an
actual raw AF_PACKET receive. The test harness adds a disposable outer Ethernet
header to reproduce real socket bytes. Real libpcap receive tests separately
exercise actual attachment, receive lengths and stable socket identity.
