# Marked packet export

Mark packets independently of the current row and retain them for a one-shot PCAP
export. Existing save/record behaviour remains unchanged when there are no marks.

- [x] Give resident packets stable arrival IDs and retain immutable capture bytes
      for marked live/remote packets; offline marks reference dataset packet IDs.
      Preserve marks across filtering, scrolling, view changes and buffer eviction.
      Clear them on explicit packet flush or capture/dataset replacement.
- [x] Add `m` toggle and `M` additive range marking on the packet list. Plain click
      moves the cursor and anchor without clearing marks; Ctrl+click toggles,
      Shift+click replaces with a range, Ctrl+Shift+click adds a range. Ranges follow
      displayed order. If the anchor is no longer displayed, require a new anchor.
- [x] Paint `*` in existing left padding, show the marked count and a contextual
      save hint, and provide a Clear marks action in the save dialog.
- [x] With any marks, `w` exports only those marks (including hidden/evicted ones),
      in capture order, without starting streaming recording. Snapshot the marks
      at export submission; retain marks after saving. Keep existing recording-stop
      behaviour while a recording is active. Validate PCAP compatibility and publish
      atomically so errors cannot leave a partial replacement file.
- [x] Bound retention using `watch.marked_packet_limit` (default 10,000) and
      `watch.marked_bytes_limit` (default 64 MiB of retained payload). Reject additions
      or ranges that exceed limits atomically, with a visible explanation, keeping
      existing marks. Offline references remain within the count limit and existing
      dataset resource/lifecycle rules; do not duplicate offline payloads in RAM.
- [x] Cover identities, ranges, filtering/eviction, mouse/keyboard routing, retained
      export contents, offline lifecycle, resource limits and rendering with focused
      tests. Update built-in Help, format, run relevant tests/build, and commit.

Verified with the TUI, components, packet-store, and offline package tests, focused
race checks for marking/export ownership, and `make build`. The bounded closure
review is complete; save-dialog refresh and resident-export lifecycle findings
were fixed and regression-tested.
