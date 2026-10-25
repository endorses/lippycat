# SSH initial-handshake observations

The shared analysis runtime observes initial cleartext SSH handshakes in sniff,
tap, processor packet mode, hunter event mode, and offline `watch file` analysis.
No dedicated SSH subcommand or port restriction is required. Existing signature
detection remains available independently of complete handshake analysis.

```bash
lc sniff -r ssh.pcap --log-dir ./logs --log-streams conn,ssh
sudo lc tap -i eth0 --insecure --log-dir ./logs --log-streams conn,ssh
```

SSH is an explicitly selected log stream; the default seven streams are unchanged.
The same typed observations appear in local/remote Events and complete offline
Events history. Use event filters such as `kind:ssh`, `hassh:<hash>` and
`role:client`. Packet filters and packet detail fields have their existing scope.

## Evidence and fingerprint availability

Each observed endpoint can produce a banner snapshot and a terminal snapshot.
`status=banner` records identification; `complete` requires a complete first
KEXINIT; `partial` records a terminal unsupported, missing, malformed, interrupted
or bounded-out observation. Snapshots have separate event identities. They count
observations rather than unique connections and share the flow's canonical UID
across observed directions. The event tuple retains the emitting direction.

`role` describes the emitting endpoint. TCP SYN/SYNACK evidence establishes the
client/server pair; absent or conflicting evidence remains explicit. First-seen
direction and port 22 alone cannot establish a role. A complete KEXINIT without
a proven role retains its lists but has no fingerprint.

HASSH 1.0 hashes four exact ordered lists joined with semicolons: key exchange,
encryption, MAC and compression. Client HASSH uses the client-to-server lists;
HASSHServer uses the server-to-client lists. Both use the `hassh` column, with
`role` distinguishing them. `hassh_algorithms` retains the input and
`hassh_version` identifies the definition. The cookie is excluded from the hash and is not retained. Host-key algorithms,
languages and the follows flag are retained but do not enter the hash. The
maintained [Corelight definition](https://github.com/corelight/hassh/blob/main/scripts/hassh.zeek)
is the reference. A hash describes offered algorithms, not negotiated algorithms,
authentication, user identity or application content.

All ten directional lists preserve ordering, duplicates and negotiation markers.
Missing evidence is unset, not an empty list or a synthetic zero hash. Optional
banner comments containing invalid UTF-8 or control bytes use the complete quoted
ASCII representation with `banner_escaped=true`; consumers can unquote it to
recover the original bytes. TUI presentation escapes control sequences.

## Framing, ownership and limits

The parser supports SSH 2.0 and 1.99 identification, including LF-only compatibility,
then uncompressed initial binary packets. Identification lines fit 255 bytes;
ignored prelude lines are bounded to 32 lines/8 KiB, each within the line buffer.
Binary packets fit 35,000 bytes. Lengths, padding, alignment, list framing,
reserved values and algorithm-name bounds are checked before decoding.
See [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) and
[RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html).

Shared TCP reassembly handles segmentation and retransmission. Each direction
owns its parser; completion or NEWKEYS stops only that direction. Gaps stop the
affected observation, while tuple reuse creates new state. Expiry and EOF finalize
partial observations rather than inventing a KEXINIT. Encrypted rekeys,
authentication and application traffic are not parsed.

| Flag                       | YAML key               | Default    |
| -------------------------- | ---------------------- | ---------- |
| `--ssh-analysis`           | `events.ssh.enabled`   | `true`     |
| `--ssh-analysis-max-flows` | `events.ssh.max_flows` | `1024`     |
| `--ssh-analysis-max-bytes` | `events.ssh.max_bytes` | `33554432` |

Both positive limits constrain admission. Each admitted flow reserves its bounded
two-direction parser and algorithm-evidence space until close/expiry; the byte cap
can admit fewer flows than the count cap. Shared TCP pages, event queues, output
queues and UI retention have separate bounds. These reservations are not process
RSS limits. Runtime `Stats.SSH` separates active flows/reserved bytes, admissions,
rejections, banners, complete and partial observations. Shared connection idle
expiry releases state. Policy participates in analysis identity.

## Output and compatibility

[`ssh.log`'s schema](structured-protocol-log-schema.md) fixes field order and types
for TSV/JSONL. It follows existing bounded queues, loss reporting, rotation and
graceful draining. Initial handshake offers are ordinary protocol metadata;
credentials and decrypted content are absent. Existing subscription authorization
and sensitive-option checks still apply.

Event-mode peers negotiate SSH support. Optional unsupported events report
compatibility loss; a configured required SSH stream must negotiate support or
use explicitly enabled packet fallback. Transport retries and relays preserve
observation identity and never re-run SSH analysis.

Offline base revision 0 keeps Events pending. Completed revision 1 publishes all
admitted metadata history with packet metadata/statistics. Local and remote live
Events retain their existing bounded window. The isolated QUIC experiment does
not add QUIC production analysis or SSH dependencies.
