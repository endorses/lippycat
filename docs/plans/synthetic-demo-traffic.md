# Synthetic traffic for terminal demos

Create a repeatable mixed-protocol Ethernet PCAP for screenshots and recordings
of packet mode with the details panel open. Exercise the existing TUI color
groups without modifying the application or recording a GIF in this task.

- [x] Generate deterministic packet bytes with fictional identities, documentation addresses, valid lengths/checksums, and ordered TCP exchanges.
- [x] Include DNS, SIP/RTP, HTTP, TLS, SSH, ARP, ICMP/ICMPv6, VPN, plain TCP/UDP, and additional email/network protocol traffic.
- [x] Provide a standalone command with configurable output, duration, and packet rate; generate a usable demo capture.
- [x] Provide an isolated virtual-link replay helper and document capture/details controls and prerequisites.
- [x] Verify determinism, wire validity, packet pacing, and actual lippycat detection; run focused tests and formatting.
- [x] Commit the generator, documentation, and completed plan.

Generated PCAPs remain untracked, consistent with the repository's existing
policy. Recording scripts and media were added in subsequent work. No new dependencies or
changes to the translated manual are needed for this generator.

## Verification

The default capture was generated at `testdata/pcaps/demo-mixed.pcap` with 1,800
packets over 60 seconds. Three focused Go tests passed, covering deterministic
PCAP bytes, exact pacing, independently verified checksums, TCP sequence and
acknowledgment accounting, all 18 protocol labels through lippycat's detector
and base packet types, invalid options, and cancellation before publication.
`go vet` and replay-helper Bash syntax checking passed. Markdown and Go files
were formatted. The PCAP remains untracked as intended.

A preliminary manual TUI inspection loaded the capture and successfully displayed the
packet-details split. Quitting with `q` and then Ctrl+C did not return; the
inspection process required explicit termination. This is an observed issue
in the existing TUI, outside the generator changes. Work stopped in accordance
with the repository instruction for unrelated issues; application code was not
changed during that initial inspection. The temporary inspection process,
its offline dataset, and the temporary verification/cache directory were removed.

Subsequent work added native repeated replay to `lc sniff`. The user verified
live capture of the generated packets on `lc0` and the completed VHS recording.
The recording recipe is in `docs/demos/`, and the GIF is embedded in the README
and manual introduction. The separate `tcpreplay` helper's privileged lifecycle
remains unverified because `tcpreplay` is not installed; Bash syntax was checked.

Before committing the remaining files, generator tests, `go vet`, and VHS tape
validation passed again. The generator and recording recipe introduce no binary
dependencies into the repository.
