# Pipeline behavior fixtures

These fixtures freeze the observable semantics used during pipeline unification.
Tests construct deterministic representative packets, pass them through the real
offline sniff and TUI conversion paths, and compare the resulting observations.
The `source_pcap` names identify those generated capture scenarios; the generated
files live in test temporary directories rather than being checked-in binaries.

`per-call-pcap.json` is consumed by the processor per-call writer test. That test
writes real SIP and RTP PCAPs, closes and reopens them, decodes every packet, and
compares packet count, link type, capture timestamp, five-tuple, SIP fields,
payload SHA-256, and call association. PCAP global-header bytes and writer timing
are not contractual.
