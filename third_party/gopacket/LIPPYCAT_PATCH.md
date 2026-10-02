# Local gopacket socket-filter binding

Baseline: `github.com/google/gopacket v1.1.19`, copied verbatim from the Go module
cache. Upstream license is retained in `LICENSE`; this is a module-local fork
selected by the root `go.mod` replacement, without import-path changes.

Changes: `pcap/pcap.go` tracks filter ownership and serializes classic filter
installation; `pcap/socket_filter_linux.go` provides the supported
`SetSocketFilter` and `DrainSocketBuffer` operations.
`pcap/socket_filter_linux_test.go` covers rejected handles, bounded draining, and
filter ownership. Neither operation exposes a private C
pointer or transfers socket ownership. Classic installation before/after socket
admission is rejected to avoid incompatible libpcap userspace filter state.

Reproduce baseline with `go mod download github.com/google/gopacket@v1.1.19` and
copy that module directory. Apply the checked-in `lippycat-socket-filter.patch`
with `patch -p1 < lippycat-socket-filter.patch` from the copied module directory
to restore the extension and its tests. From the root lippycat module, run
`go test github.com/google/gopacket/pcap -run TestSocketAdmission` to check the
binding without capture privileges. Ordinary builds use the local module; no download or
patch command is run by the build. The root module checksum for v1.1.19 records
upstream provenance, while the checked-in local source records the exact patch.

Enabled capture requests immediate mode and host timestamps. Startup attaches a
reject-all program, drains visible queued frames under a bounded context, then
activates the final program. TPACKET_V3 drain is rejected rather than treating an
unretired block as empty. The capture pipeline additionally discards host-timestamp
frames at/before the post-activation boundary, including in-flight old frames.
Clock changes during startup can affect this timestamp boundary, so startup is
not a promise of lossless media capture.
