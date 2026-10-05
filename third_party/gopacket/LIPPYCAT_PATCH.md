# Local gopacket socket-filter binding

Baseline: `github.com/google/gopacket v1.1.19`, copied verbatim from the Go module
cache. Upstream license is retained in `LICENSE`; this is a module-local fork
selected by the root `go.mod` replacement, without import-path changes.

Changes: `pcap/pcap.go` tracks filter ownership and serializes classic filter
installation; `pcap/socket_filter_linux.go` provides the supported
`SetSocketFilter`, `DrainSocketBuffer`, and `DrainSocketBufferCount` operations.
`pcap/socket_filter_linux_test.go` covers rejected handles, bounded draining, and
filter ownership. Neither operation exposes a private C
pointer or transfers socket ownership. Classic installation before/after socket
admission is rejected to avoid incompatible libpcap userspace filter state.

Reproduce baseline with `go mod download github.com/google/gopacket@v1.1.19` and
copy that module directory. Apply the checked-in `lippycat-socket-filter.patch`
with `patch -p1 < lippycat-socket-filter.patch` from the copied module directory
to restore the extension and its tests. From the root lippycat module, run
`go test github.com/google/gopacket/pcap -run TestSocketAdmission` to check the
binding without capture privileges. Ordinary builds use the local module; no download
or patch command is run by the build. The local `replace` means the root `go.sum`
does not retain a gopacket module checksum. The baseline version, upstream license,
checked-in source, and reproducible patch record provenance.

Dependency-first container/package builds must copy `third_party/gopacket` before
running `go mod download`, alongside the root `go.mod` and `go.sum`. Copying only
the root manifests is insufficient for the local module replacement.

Enabled capture requests immediate mode and host timestamps. Startup attaches a
reject-all program, synchronizes AF_PACKET receivers by temporarily rebinding its
protocol and restoring the original binding, drains retained frames under a
bounded context, then activates the final program. The socket and interface
membership remain owned by libpcap. Binding failure aborts startup and the caller
closes the handle. TPACKET_V3 is rejected because a partially filled block may
remain hidden; immediate modes expose all frames after receiver synchronization.
Startup discards are counted separately from kernel and application queue drops.
There is no post-activation timestamp fence, so subsequent host clock changes do
not discard valid packets.

The synchronization argument follows Linux
[`packet_do_bind` and `__unregister_prot_hook`](https://github.com/torvalds/linux/blob/v6.18/net/packet/af_packet.c):
a changed protocol retires the old hook and waits in `synchronize_net` before
registering the replacement. The already attached startup filter rejects new
receives while the original protocol is restored and queues are drained. Protocol
zero is not an unbind operation for an existing socket; the kernel substitutes
its current protocol. Fanout sockets are rejected by kernel bind validation.
