# Pipeline behavior fixtures

These fixtures freeze the observable semantics used during pipeline unification.
The named PCAPs describe the representative capture scenario; the fixture stores
the stable decoded observation rather than a host-dependent CLI rendering or a
Bubble Tea frame. `protocol-events.json` is shared by CLI and TUI consumers.

`per-call-pcap.json` deliberately compares semantic packet properties: packet
count, link type, capture timestamp, five-tuple, SIP fields, payload SHA-256, and
call association. PCAP global-header bytes and writer timing are not contractual.
