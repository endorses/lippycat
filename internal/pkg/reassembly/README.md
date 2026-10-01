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

The package also provides `ForEachCaptureInfo`, which visits capture metadata
once per nonempty byte container using exclusive end offsets. Application
reassembly uses these ranges to preserve frame completion timestamps and
provenance without looking up metadata for every payload byte. The existing
`ScatterGather` interface is unchanged; other implementations fall back to
per-byte visits.

Connection-pool entries are pinned while an assembler holds a pointer. Retired
entries are recycled only after their final pin is released, and recycled entries
release both stream references. Factory calls for a tuple are serialized without
holding the pool lock across the callback.

Unmatched control-only packets without SYN are counted by `OrphanControls` and
cannot create a stream. Payload still supports passive midstream capture. A new
bare SYN with a different initial sequence number retires the previous tuple
incarnation, releases queued and retained pages, completes its stream once, and
creates fresh sequence state. SYN retransmission preserves the current stream.
A delayed SYN matching the first passive payload sequence is attached to that
stream; when only the opposite half was seen, its acknowledgment can correlate
the missing opening SYN. An unmatched SYN after opposite-half passive data starts
a fresh incarnation. Bare SYNs alone can be simultaneous open and do not provide
that evidence.

Capture buffers separately keep a TCP tuple in the regular lane while it has
regular-lane predecessors awaiting output. This prevents SIP promotion from
moving application bytes ahead of their handshake or earlier demoted segments,
while unrelated flows retain SIP priority. The ordering map stores counters only;
channel capacities and assembler page limits still bound packet retention. The
`packet_buffer_sip_ordered` heartbeat counter reports this ordering separately
from capacity demotion and drops.

Keep these local patches and their regression tests when updating the copied
package. A replacement must preserve pool pin/recycle safety, completion and page
release, metadata on every buffered page, and efficient metadata ranges.
