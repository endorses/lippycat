# TCP reassembly dependency patch

This package copies `github.com/google/gopacket/reassembly` from gopacket
v1.1.19, including its upstream tests and BSD license. All lippycat stream
factories use this package so the assembler and callback types stay consistent.
The rest of gopacket remains a normal module dependency.

The local patch retains the original assembler context on every continuation
page of a buffered TCP packet. Upstream keeps context only on the first
1,900-byte page, but dereferences it for `ScatterGather.CaptureInfo`, causing
a nil-pointer panic for large queued packets. Continuation pages also need
that context when delivered during a flush after earlier pages were released.
The first-page marker remains separate so packet statistics do not count
continuation pages as additional packets. Returning pages to the cache clears
both context references.

Upstream source is otherwise unchanged apart from gofmt. Keep this patch and
its regression tests when updating the copied package; remove the local copy
once a replacement dependency preserves metadata on every buffered page.
