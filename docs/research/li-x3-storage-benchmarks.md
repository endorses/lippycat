# LI X3 storage measurements

Status: **calibration only; X3 qualification is not complete**. The current
per-record protocol is infeasible for the required workload on the measured
filesystem. All three benchmark-only immutable batch/head kernels, including
grouped publication and head-container exchange, fail the frozen median-latency
gate. No production alternative is selected. Phase 5 remains open;
its final integration must repeat the frozen workload.

The next [bounded segment experiment](../design/li-x3-segment-layout.md) has a
reviewed helper/codec/recovery implementation and a passing focused test gate.
Its separately approved 2/200 ×40 real-ext4 measurement passes the small callback
floor. Full workload and production qualification remain incomplete.

## Synthetic fixture erratum

The segment's new exact-PDU preflight exposed a defect in the earlier synthetic
fixture: assigning `pdu.Payload` directly left its header payload length at zero,
followed by uncounted RTP bytes. The general decoder tolerated that trailing
data. The fixture now uses `SetPayload`; a regression checks that both X2 proxy
and X3 headers describe the entire encoded PDU and recover all RTP bytes. The
synthetic payload mix and encoded byte lengths are unchanged; header bytes are
corrected.

Earlier per-record/immutable measurements and their ciphertext/byte oracles
remain observations of those exact bytes, including their failed latencies.
They cannot establish protocol-validity for the original malformed synthetic
PDUs. No old log or measurement has been rewritten, and the already-failed
variants have not been rerun as a performance campaign. Future segment
measurements must use the corrected valid PDUs. The sensitive strict-preflight
failure is retained at `/tmp/li-fixed-segment-preflight-fixture-failure.log`.

## Callback timestamp erratum

The immutable-kernel harness and first segment probe subtracted a modeled
per-record arrival offset from one batch timestamp. Those PDUs already existed;
the result was a schedule-model latency, not measured admission-to-callback
latency. The old immutable observations still failed even under that favorable
model and are not qualification evidence. Their raw logs remain unchanged.

The first segment log `/tmp/li-fixed-segment-measurements.log` is also retained
unchanged and **superseded** for callback qualification. Its modeled medians
9.375082/9.767713 ms must not be used as measured admission latency. After review,
the harness removed the virtual offset and reran only the same 2/200 ×40 probes.
Every callback now measures elapsed time from its batch's single actual admission
timestamp before the full 10 ms accumulation wait. The corrected log is
`/tmp/li-fixed-segment-actual-admission.log`; only those results appear in the
current segment table below.

## Method and scope

The acceptance criteria are frozen in
[the encrypted-storage contract](../design/li-encrypted-storage.md#x3-layout-qualification-gate).
The opt-in Linux benchmark is
`BenchmarkJournalStorageCalibration` in
`internal/pkg/li/delivery/storage_calibration_bench_test.go`.

The first calibration uses the existing X2 `Journal`, because its current reader
and sequence validator explicitly reject X3. The benchmark builds a synthetic
X3 RTP PDU and uses an equally sized X2 header for journal admission. This is an
X2 storage-protocol proxy, not a claim of implemented X3 persistence. A unit test
checks equal encoded lengths and that the real X3 counterpart is still rejected
by the X2 sequence validator.

One synthetic bidirectional call produces 100 source PDUs/s and two independently
queued destination copies, for 200 offered copies/s. Media payloads are
160/320/1,200 bytes in a deterministic 70/20/10% mix; the minimal encoded PDUs
are 220/380/1,260 bytes. Mean media/encoded lengths are 296/356 bytes. SSRCs,
ordering, identities, and payload generation are deterministic; media consists
of pseudorandom bytes, never captured traffic or intelligible audio. RTP sequence
wrap and an adjacent reordered pair in each 100-packet stream run are included;
the independent ETSI sequence also wraps. Fresh random raw keys are generated
for every disposable store. Cryptographic nonces are never made deterministic.

The short run has a 1-second warmup, 2 seconds of healthy reads, a 2-second reader
outage, then 2 seconds of recovery with the same live arrival rate. After live
traffic stops, all accepted work drains. Each destination has its own bounded
reader queue. A reader decrypts the persisted record, verifies its destination,
XID and SHA-256 of the original encoded PDU, then invokes the real `Complete`
path. There is no loopback MDF or TLS in this calibration. The final qualification
must add real bounded transport sinks and per-destination capacity enforcement.

The original protocol is used without production modifications: JSON/base64,
LCS1 envelopes, key-usage reservations, product/state replacements, advancing
sequence checkpoints, file/directory sync, authenticated reads, and durable
completion removal. With two adjacent copies of the same PDU, normally only the
first advances the shared sequence checkpoint. Thus the pair generally requires
ten replacement sync calls plus two completion-directory sync calls; actual
sequence progress, checkpoint scheduling and usage reservations can add work.

Admission and callback timing are separate. Callback latency is attributed to
the phase in which admission occurred, even when it completes during the final
drain. Throughput counts callbacks actually completed inside each phase window.
Source schedule lag is measured independently. Bounded logarithmic histograms
report conservative quantile upper bounds, with up to 6.25% rounding; those
bounds can exceed the separately reported exact maximum. Histograms do not grow
with packet count. RSS and actual allocated blocks (`st_blocks × 512`) are sampled
once per second, including directory, control, sequence, usage, lock, and
temporary inodes. Concurrent samples are not atomic inventories. Sampling stops
at a fixed 1,800-sample ceiling. CPU/allocation figures include the synthetic
producer, readers and instrumentation, but exclude initialization and the later
restart probe.

A separate 128-held-record warm restart probe times `OpenJournal`, authenticated
reads, and synchronous `Purge`. Purge is a physical reclaim/control-I/O proxy;
it does not establish task revocation, expiry, or the authorization claim boundary.
The current restart reads/decrypts product payloads and repairs checkpoints. It
does not satisfy the future metadata-only recovery design.

## Environment and space bounds

Measured 2026-09-26 against production journal code at
`f472ab627a4e2d838377faae8f9dd45c9c3fe37f`, with the new benchmark file uncommitted.

| Item                    | Observed configuration                                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Durable directory       | A fresh mode-0700 `.li-storage-calibration-*` child of `/home/grischa/Projects/lippycat`                                              |
| Filesystem              | `/dev/mapper/volgroup0-lv_home`, ext4, 4 KiB blocks, `rw,nosuid,nodev,relatime`                                                       |
| Device stack            | Home LV → LUKS mapper `volgroup0` → healthy md0 RAID1 → two Samsung SSD 990 PRO 2 TB NVMe devices                                     |
| Drive cache             | Both devices expose `write back`; physical power-loss survival was not tested                                                         |
| Space before run        | 80,133,537,792 bytes available; filesystem 94% used; approximately 80.4 million free inodes                                           |
| CPU                     | Intel Core i9-13900HX, 32 logical CPUs; `GOMAXPROCS=32`                                                                               |
| Memory                  | Approximately 62.5 GiB total; approximately 24 GiB available at inventory time                                                        |
| Kernel / Go             | Linux 6.18.52-1-lts; `go1.27.1-X:nodwarf5 linux/amd64`                                                                                |
| Process cgroup          | No explicit memory or CPU quota in the visible process scope                                                                          |
| Journal limits          | 512 MiB; 131,072 records; 4,096 pending operations; sequence preservation enabled                                                     |
| Calibration space bound | One store at a time, under 1 GiB including inspection/metadata slack; at least 2 GiB and 262,144 free inodes required before starting |

The machine and filesystem are shared with other activity. CPU frequency,
temperature and unrelated I/O were not isolated. These are local calibration
results, not a universal NVMe performance claim. `/tmp` is tmpfs, has only
1,048,576 total inodes, and cannot qualify this workload. It holds only the build
cache and temporary measurement logs, which are removed after the report is
recorded.

The sandbox maps `/` and `/home` to UID 65534, so its first attempt correctly
failed securestore ancestor ownership validation. The successful benchmark ran
outside that sandbox with authorization; validation was not relaxed.

## Reproduction

Run this exact fixed-duration calibration on the declared filesystem:

```sh
LC_LI_STORAGE_BENCH_DIR=/home/grischa/Projects/lippycat \
GOCACHE=/tmp/li-storage-calibration-cache \
go test -tags li ./internal/pkg/li/delivery -run '^$' \
  -bench '^BenchmarkJournalStorageCalibration$/calls=1$/copies=200$' \
  -benchtime=1x -count=1 -timeout=3m -v
```

Each successful sub-benchmark prints a `STORAGE_CALIBRATION` JSON object with
phase counts, latency summaries, one-second samples, CPU, allocation, RSS and
restart/reclaim measurements. Test completion alone is not qualification:
threshold failures remain visible measurements. If all calibration levels are
selected, a failing lower load skips larger levels. Selecting a higher
sub-benchmark explicitly overrides that protection. No larger per-file run was
performed after the first result established insufficient headroom.

The concurrent harness is separately exercised with the same command plus
`-race` and `-run '^TestStorageCalibrationSyntheticProducts$'`. Race-instrumented
timings are validation only and are excluded from the performance table.
That check passed in 88.152 seconds without a race report. The synthetic product
and histogram unit check also passed independently. Both disk runs removed their
disposable stores successfully.

## Measured per-record calibration

All 1,400 offered copies were admitted and eventually authenticated and reclaimed.
Each destination reader received exactly 700 copies. Zero admission rejection
reflects temporary queue room, not sustainable throughput.

| Traffic phase              | Actual seconds | Offered / accepted | Durable callbacks in window | Durable copies/s | Pending at phase end | Callback p50 / p99 upper (ms) | Callback exact max (ms) |
| -------------------------- | -------------: | -----------------: | --------------------------: | ---------------: | -------------------: | ----------------------------: | ----------------------: |
| Warmup                     |       1.000530 |          200 / 200 |                          18 |            17.99 |                  182 |         5,242.880 / 9,961.472 |               9,941.173 |
| Healthy                    |       2.000085 |          400 / 400 |                          37 |            18.50 |                  545 |       19,922.944 / 30,408.704 |              30,039.968 |
| Outage                     |       2.000936 |          400 / 400 |                          40 |            19.99 |                  905 |       41,943.040 / 52,428.800 |              50,553.326 |
| Recovery with live traffic |       2.000310 |          400 / 400 |                          29 |            14.50 |                1,276 |       60,817.408 / 71,303.168 |              69,757.262 |
| Final drain, no arrivals   |      69.790846 |              0 / 0 |                       1,276 |            18.28 |                    0 |                           n/a |                     n/a |

| Other measurement                                            |                        Result |
| ------------------------------------------------------------ | ----------------------------: |
| Healthy admission p50 / p99 upper / exact max                |   0.004 / 0.031 / 0.034056 ms |
| Healthy source schedule lag p99 upper / exact max            |           1.216 / 3.008963 ms |
| Main measured wall time, including final drain               |             76.792907 seconds |
| Main measured CPU time                                       |          1.580898 CPU seconds |
| CPU per 1,000 durable copies                                 |          1.129213 CPU seconds |
| Allocated bytes / objects per durable copy                   |            17,022.67 / 154.33 |
| Sampled RSS, first / peak                                    | 35,631,104 / 54,292,480 bytes |
| Sampled peak actual allocation                               |                 184,320 bytes |
| Sampled peak journal charge, including pending reservations  |              31,367,168 bytes |
| Warm restart of 128 held records                             |              0.054664 seconds |
| Recovered authenticated read p99 upper / exact max           |           0.072 / 0.079888 ms |
| Held purge sync proxy p50 / p99 upper / exact max            | 9.216 / 14.848 / 17.936779 ms |
| Allocation after final reclaim, before store removal         |                  24,576 bytes |
| Complete benchmark time, including setup and restart/reclaim |                85.260 seconds |

Low disk allocation is a consequence of slow persistence and prompt completion
after the short outage. Most accepted traffic was still pending in memory. It
does not measure the disk cost of a 1.2-million-record outage. The small RSS run
also does not establish the 15-minute memory criterion.

The current serial per-record protocol fails to keep up even with the smallest
200-copy/s calibration and produces callback delays tens of seconds beyond the
one-second maximum. Its admission path is fast, but accumulating accepted work
does not make that work durable. This is enough evidence to reject adoption of
the unchanged layout for the 20,000-copy/s primary requirement on this platform.
A full overloaded per-file campaign would add drain time without qualifying it.

## Immutable batch/head kernel: failed latency gate

The review approved a small durability kernel before spending work on the full
checkpoint tree or control runtime. `BenchmarkBatchHeadDurabilityKernel` in
`internal/pkg/li/delivery/batch_kernel_bench_test.go` creates real encrypted
immutable batches and then atomically replaces an authenticated commit head.
Purpose 9, `JournalBatchIndex`, was explicitly added to the shared envelope
contract, rather than mislabeling indexes as journal state.

This is a lower-bound feasibility probe with reduced owner metadata explicitly
marked `kernel_version`, not the production version-2 X3 record schema. Every
synthetic X3 PDU has its own purpose-4 encrypted frame and binding. A purpose-9
index authenticates framing, per-frame ciphertext hashes, synthetic record
identity, original PDU hash, sequence evidence and references to two already
durable synthetic call-control objects. The head authenticates the transaction
chain. Recovery validates all referenced batches, product frames, dependencies,
and sequence evidence; unresolved complete orphans fail closed.

The probe measures 40 sequential batches at each size, with a real 10 ms
accumulation wait. Per-record arrival times are distributed uniformly through
that window. PDU generation is outside the callback interval; encryption,
index construction, real usage reservation renewals, batch `Create`, head seal
and `Replace`, and callbacks are inside. Initial usage/control/head creation is
outside the reported interval but consumes the same durable ledger. There is
no growing arrival queue: callback results therefore omit the extra delay a
sustained stream would incur while this worker is busy. There is no TLS,
completion, compaction or checkpoint-tree work to make this optimistic probe
artificially slow.

Run on the same declared ext4 filesystem, with approximately 80.11 GB free:

```sh
LC_LI_STORAGE_BENCH_DIR=/home/grischa/Projects/lippycat \
GOCACHE=/tmp/li-batch-kernel-cache \
go test -tags li ./internal/pkg/li/delivery ./internal/pkg/securestore \
  -run '^TestBatchKernel|^TestJournalBatchIndexPurpose' \
  -bench '^BenchmarkBatchHeadDurabilityKernel$' \
  -benchtime=1x -count=1 -timeout=3m -v
```

Only one fresh mode-0700 store exists at a time. Forty files of at most 2 MiB plus
small metadata bound the probe below 81 MiB; startup requires 1 GiB available.
There is no production-directory or production-key input. The two measurement
sub-benchmarks completed in 4.264 seconds total and removed their stores.

| Metric                                           |       2 records/batch |     200 records/batch |
| ------------------------------------------------ | --------------------: | --------------------: |
| Batches / committed callbacks                    |               40 / 80 |            40 / 8,000 |
| Measured wall seconds                            |              1.861123 |              2.105218 |
| Sequential-kernel copies/s                       |                 42.98 |              3,800.08 |
| Callback p50 / p99 upper, ms                     |       45.056 / 55.296 |       47.104 / 65.536 |
| Callback exact max, ms                           |             53.979997 |             66.785051 |
| Commit including usage/crypto p50 upper, ms      |                36.864 |                43.008 |
| Batch publication p50 upper, ms                  |                18.432 |                23.552 |
| Head publication p50 upper, ms                   |                18.432 |                18.432 |
| Usage reserved invocations, before → after       |         4,096 → 4,096 |         4,096 → 8,192 |
| Usage reserved blocks, before → after            | 1,048,576 → 1,048,576 | 1,048,576 → 1,048,576 |
| Actual retained allocation, bytes                |               200,704 |            10,178,560 |
| Warm reopen and complete authentication, seconds |              0.000770 |              0.054465 |

The latency buckets containing both medians lie entirely above 25 ms. The failure
does not depend on quantile rounding. Removing the accumulation window would
still leave measured commit medians above that threshold. There is no basis to
run the full workload or implement the checkpoint tree for this unoptimized
publication path. The frozen thresholds remain unchanged.

Focused tests cover definite/uncertain batch failure, definite/uncertain head
failure, committed-head cleanup errors, no callback before head publication,
exact callback counts, complete orphan rejection, committed corruption,
framing bounds, and purpose/usage classification. These are owner-boundary fault
injections composed with real durable files, not a substitute for the eventual
syscall-level fault and child-process-death matrix. The next candidate is the
[grouped publication experiment](../design/li-x3-batch-layout.md#reviewed-grouped-publication-experiment-failed-latency-gate),
subsequently reviewed and measured below.

Final focused race validation passed for kernel tests, purpose 9 and the existing
envelope tests (`go test -race -tags li ./internal/pkg/li/delivery
./internal/pkg/securestore -run '^TestBatchKernel|^TestJournalBatchIndexPurpose|^TestEnvelope'
-count=1`): delivery 1.056 s, securestore 1.305 s. This includes authenticated
malformed offsets/lengths/revision/record IDs and a reauthenticated index pointing
to a corrupted product frame. Build cache and temporary logs were removed after
recording the measurements; no `.li-batch-kernel-*` directory remained.

## Grouped batch/head kernel: failed latency gate

The narrowly reviewed optimization writes the complete encrypted batch and head
to two mode-0600 temporary files in the held directory, syncs their independent
descriptors with exactly two concurrent workers, and joins both results. Only
then does it publish the batch without replacement, replace the existing locked
head, and sync the parent directory once. Both file syncs and the final directory
sync are real; callback timing includes them. Usage reservation remains a separate
durable prerequisite to encryption. No actual X2 journal or production X3 path
uses this helper.

The helper is `Dir.CreateAndReplace(newName, newData, headName, headData)` in
`internal/pkg/securestore/grouped.go`. It returns `(Outcome, error)`, requires an
existing head owned through this directory, retains its stable and inode locks,
rejects unsafe/identical names, existing prerequisite targets, inode substitution,
and zero/oversize objects. The prerequisite is limited to 2 MiB and the head to
64 KiB plus maximum envelope overhead. The owner must reserve capacity and supply
already encrypted bytes. The exact benchmark schemas, bindings, byte bounds,
ownership requirements and crash matrix are recorded in the
[reviewed experiment contract](../design/li-x3-batch-layout.md#implemented-helper-and-kernel-contract).
The reduced `kernel_version: 1` schema is unchanged; this is not the production
record or checkpoint implementation.

Before running, `df -hT . /tmp` showed approximately 75 GiB available on the same
declared ext4 volume and 26 GiB on tmpfs. Only ext4 was used for durability. Each
sub-benchmark owns one disposable directory and synthetic raw key; 40 bounded
batches plus metadata/pending allocation remain below 81 MiB, within the approved
1 GiB artifact ceiling. The benchmark refuses to start below 1 GiB available.

```sh
LC_LI_STORAGE_BENCH_DIR=/home/grischa/Projects/lippycat \
GOCACHE=/tmp/li-grouped-kernel-cache \
go test -tags li ./internal/pkg/li/delivery -run '^$' \
  -bench '^BenchmarkGroupedBatchHeadDurabilityKernel$' \
  -benchtime=1x -count=1 -timeout=3m -v
```

The same 40-batch, 10 ms accumulation probe now retains at most 8,000 durations
(64 KiB) and reports exact nearest-rank callback percentiles as well as the
existing histogram upper bounds. There is still no continuous arrival queue,
transport, completion, checkpoint tree, compaction or capacity-pressure work;
this is an optimistic kernel feasibility probe, not the full workload. Initialization
is outside the callback interval; all measured product/index/head encryption,
usage renewal, grouped publication and callbacks are inside it. The two
sub-benchmarks completed in 3.187 seconds including setup/reopen/cleanup.

| Metric                                           |       2 records/batch |     200 records/batch |
| ------------------------------------------------ | --------------------: | --------------------: |
| Batches / committed callbacks                    |               40 / 80 |            40 / 8,000 |
| Measured wall seconds                            |              1.209601 |              1.680940 |
| Sequential-kernel copies/s                       |                 66.14 |              4,759.24 |
| Callback exact p50 / p99, ms                     | 27.071412 / 43.879871 | 36.230369 / 64.746029 |
| Callback exact max, ms                           |             43.879871 |             68.743683 |
| Callback histogram p50 / p99 upper, ms           |       27.648 / 45.056 |       36.864 / 65.536 |
| Commit including usage/crypto p50 upper, ms      |                18.432 |                32.768 |
| Grouped file/name/directory I/O p50 upper, ms    |                18.432 |                31.744 |
| Usage reserved invocations, before → after       |         4,096 → 4,096 |         4,096 → 8,192 |
| Usage reserved blocks, before → after            | 1,048,576 → 1,048,576 | 1,048,576 → 1,048,576 |
| Actual retained allocation, bytes                |               200,704 |            10,178,560 |
| Warm reopen and complete authentication, seconds |              0.001117 |              0.047670 |

Both exact medians exceed the frozen 25 ms bound, including the two-record
best-case probe. Grouping reduces latency compared with the four-sync kernel,
but the 200-record result also remains far below 20,000 copies/s even before
adding the omitted runtime work. The 200-record probe crosses an actual
4,096-invocation usage reservation boundary, and its durable renewal is included.
No full workload, sustained recovery, checkpoint tree or next layout was run.
The acceptance criteria remain unchanged.

Callback success occurs only after final parent sync. Failure before head
replacement is `NotCommitted` for the transaction and may leave a complete orphan;
the prototype stops and requires reconciliation. Failure after head replacement
is `Uncertain` and latches the owner fault. A cleanup failure after parent sync
remains `Committed` plus error and cannot authorize retrying the same admission.
Each record receives exactly one typed callback. Reopen authenticates the selected
head's whole dependency graph and fails closed if its batch is missing or corrupt,
even when a prior chain remains intact. A crash before the shared directory sync
can leave such a stopped store; no atomic multi-file rollback is claimed.

Final focused race validation passed:

```sh
GOCACHE=/tmp/li-grouped-kernel-cache \
go test -race -tags li ./internal/pkg/securestore ./internal/pkg/li/delivery \
  -run '^TestGrouped|^TestBatchKernel|^TestJournalBatchIndexPurpose' \
  -count=1 -timeout=2m
```

Results: securestore 1.051 s; delivery 1.066 s. The helper tests inject each write,
sync, prepublication close, no-replace publication, head rename, parent sync,
postcommit close and cleanup failure; cover no-clobber, path/size/inode bounds,
stable and replacement inode locks across renaming the directory, concurrent sync
joining even after one peer fails, and child-process death before batch, before
head, before directory sync and after it. Kernel tests cover callback outcomes,
complete orphans, missing selected batches, authenticated malformed indexes and
committed corruption. Child-process death does not simulate power loss; the
missing selected-batch case is an explicit recovery-state injection.

The head-container/archive format was subsequently reviewed and measured below;
a faster declared durable platform remains another option. No layout is selected.
The grouped probe's artifact directories were removed
by the harness; its build cache and temporary logs are removed after recording
this report.

## Head-container exchange kernel: failed latency gate

The third narrowly reviewed probe combines one unchanged encrypted `LCB1` batch
and a purpose-6 authenticated head into a single `LCH1` container. Its fixed
`LHK1` head payload authenticates exact outer lengths/identity, the embedded
batch ciphertext digest, predecessor container digest, record/revision evidence
and actual durable call-control digests. The root has no batch but remains fully
authenticated. There is no self-digest or circular length calculation. The
[exact reviewed schema and API](../design/li-x3-batch-layout.md#reviewed-head-container-exchange-experiment)
bound the container to 2,097,591 bytes and keep all production metadata,
checkpoint and lifecycle decisions open.

The Linux helper `Dir.ExchangeAndArchive(stage, head, archive, encryptedBytes)`
fully writes, syncs and closes one staged inode while retaining its inode lock.
It exchanges that name with the existing `.head`, immediately transfers the
head's inode lock, archives the displaced inode without replacement, then syncs
the same parent directory. Every pre-sync failure after exchange is `Uncertain`;
there is no swap-back. A post-sync cleanup failure remains `Committed` plus
error. Every error stops the kernel. Both stable and replacement-inode locks
remain enforced, with no hardlink exception. Neither actual X2 nor production
X3 uses this helper.

Stages use `.lch-stage-*`, outside generic temporary cleanup. Normal recovery
authenticates only the selected head's exact archive chain and stops on a missing
or corrupt predecessor, even if older data remains intact. It recognizes a
complete unpublished candidate or a displaced predecessor through its exact
authenticated relationship, then stops without mutation. Explicit stage
reconciliation is deliberately deferred to phase 8; malformed/partial stages,
unknown objects, duplicate identities and excess inventory also stop without
deleting evidence. The callback/claim semantics of a full production runtime
are not implemented by this probe.

Before measuring, the focused race gate passed without failures:

```sh
GOCACHE=/tmp/li-exchange-kernel-cache \
go test -race -tags li ./internal/pkg/securestore ./internal/pkg/li/delivery \
  -run '^TestExchange|^TestHeadContainer|^TestBatchKernel|^TestGrouped|^TestJournalBatchIndexPurpose' \
  -count=1 -timeout=2m
```

Results: securestore 1.120 s; delivery 1.084 s. This covers faults at staged write,
sync, close, exchange, archive and directory-sync boundaries; committed cleanup
errors; lock retention through renamed directories and moved inodes; process
death around exchange/archive/sync; exact maximum helper size, short writes and
stage substitution; authenticated malformed container fields; current-head
corruption before mutation; typed callbacks once per record and no continued
writer after fault; missing/corrupt predecessors and stage classification without
cleanup. Existing grouped/batch/purpose tests also pass. Child-process tests
remain process-death tests, not power-cut certification.

Ext4 still had approximately 75 GiB available. Each probe uses a fresh private
disposable store and synthetic key. The owner reserves a conservative 513 × 4 KiB
for every attempted container plus a 4 MiB metadata/reconciliation allowance,
charging old/new/staged objects simultaneously. The 96 MiB artifact cap is
checked before candidate encryption; the harness requires 1 GiB free and the
reviewed 4 KiB ext4 allocation unit. Codec inputs, frames, plaintext, indexes,
containers and inventory are bounded; the declared codec/read scratch reservation
is 16 MiB plus at most 64 KiB of exact-percentile samples. This is a bounded
kernel, not the final production memory-budget implementation.

```sh
LC_LI_STORAGE_BENCH_DIR=/home/grischa/Projects/lippycat \
GOCACHE=/tmp/li-exchange-kernel-cache \
go test -tags li ./internal/pkg/li/delivery -run '^$' \
  -bench '^BenchmarkHeadContainerDurabilityKernel$' \
  -benchtime=1x -count=1 -timeout=3m -v
```

The machine remained shared. Root integration tests had finished and command
variant tests waited for this measurement; another agent could run focused
tests on `/tmp`. There was no exclusive-host or power-loss test. Both probes
retain 40 real commits with 10 ms accumulation and the same synthetic payload
mix. Callback timing includes current-head read/authentication, all new
product/index/head encryption, usage renewal, the exchange/archive protocol,
final directory sync and callback dispatch. Actual root/control/usage startup
cost is separately reported. Per-batch RSS/heap samples occur after callbacks
and are included in wall time, so copies/s is not a pure I/O rate. No checkpoint,
compaction, continuous-arrival queue, completion or transport cost is included.

| Metric                                                 |          2 records/batch |        200 records/batch |
| ------------------------------------------------------ | -----------------------: | -----------------------: |
| Batches / committed callbacks                          |                  40 / 80 |               40 / 8,000 |
| Root/control/usage initialization, seconds             |                 0.152482 |                 0.111729 |
| Measured wall seconds                                  |                 1.209420 |                 1.402847 |
| Sequential-kernel copies/s                             |                    66.15 |                 5,702.69 |
| Callback exact p50 / p99, ms                           |    28.607633 / 36.386660 |    29.515850 / 51.498116 |
| Callback exact max, ms                                 |                36.386660 |                55.495273 |
| Callback histogram p50 / p99 upper, ms                 |          28.672 / 36.864 |          29.696 / 53.248 |
| Commit including validation/usage/crypto p50 upper, ms |                   19.456 |                   26.624 |
| Exchange/archive/directory I/O p50 upper, ms           |                   19.456 |                   25.600 |
| Usage reserved invocations, before → after             |            4,096 → 4,096 |            4,096 → 8,192 |
| Usage reserved blocks, before → after                  |    1,048,576 → 1,048,576 |    1,048,576 → 1,048,576 |
| Actual retained allocation, bytes / files              |             200,704 / 46 |          10,178,560 / 46 |
| Conservative charged bytes / artifact budget           | 88,260,608 / 100,663,296 | 88,260,608 / 100,663,296 |
| Sampled process heap at start / peak, bytes            |    1,597,944 / 2,763,776 |    1,717,224 / 8,666,512 |
| Sampled process RSS peak, bytes                        |               33,538,048 |               44,339,200 |
| Warm reopen and complete authentication, seconds       |                 0.000916 |                 0.066839 |

The whole benchmark command completed in 2.956 seconds including setup/reopen/
cleanup. Heap/RSS values are samples after commits, not proof of the maximum
intracommit live memory or the final 15-minute memory gate. The deliberate
worst-case container reservation is much larger than the small actual files;
it prevents those small files from hiding the admitted maximum allocation.

Both exact callback medians exceed 25 ms. The 200-record probe includes actual
usage reservation renewal, improves on the grouped kernel's 36.23 ms median,
and still fails. Its sequential rate also remains below the required 20,000
copies/s before adding the omitted runtime obligations. Implementation stopped
at this failed gate. No full workload, checkpoint tree, production adoption or
fourth layout attempt followed, and no acceptance threshold changed.

Raw output is preserved for review at `/tmp/li-exchange-kernel-measurements.log`
and the focused gate output at `/tmp/li-exchange-kernel-check.log`. Disposable
stores are removed by the harness and the dedicated build cache is cleaned after
recording this report. Further architecture/platform work requires a new review.

## Fixed segment implementation gate (no measurement)

Root approved only the minimal descriptor-owned fixed-file helper plus the
benchmark codec and read-only recovery described in
[the exact segment design](../design/li-x3-segment-layout.md). This implementation
keeps existing X2/X3 production paths and the three immutable protocols unchanged.
The shared benchmark codec adds an optional predecode guard, enabled only for the
segment experiment: exact wire framing and a 4 KiB header cap before TLV object
allocation. The design derives a conservative 14 MiB live codec-object bound
inside its 16 MiB reservation, including decoded objects and growing slice tables.

The helper creates a fully allocated and zero-written 32 MiB inode, with two
authenticated bootstrap heads, before publication. A retained descriptor appends
one at-most-2 MiB padded batch and overwrites the inactive 4 KiB head, then performs
one real `fdatasync`. It validates parent/name/inode/lock/size/allocation before
writes; duplicate mutable handles and rotation-helper coexistence are rejected.
It preserves committed outcomes after post-sync validation/cleanup errors and
poisons the owner after every fault. Recovery requires both adjacent heads and
the exact lower and higher selected data boundaries. Dirty tails are classified
and preserved, and repeated reopen never resumes or mutates them.

The final focused gate used:

```sh
GOCACHE=/tmp/li-fixed-segment-cache go test -race -tags li \
  ./internal/pkg/securestore ./internal/pkg/li/delivery \
  -run '^Test(FixedSegment|SegmentKernel|BatchKernel|HeadContainer|Grouped|Exchange|RotationIO|StorageCalibrationSyntheticProducts)' \
  -count=1 -v -timeout=4m
```

It passed: securestore 3.409 s; delivery 10.289 s. Raw verbose output is retained
at `/tmp/li-fixed-segment-gate.log`, including every subtest. Coverage includes
the helper fault and process-death boundaries, fixed-allocation/descriptor
substitution, sole-writer and cross-helper exclusion, maximum write bounds,
two-slot and authenticated schema/overflow checks, both selected boundaries,
committed corruption, dirty/oversized tails, strict PDU preflight before general
decoding, callback outcomes and stopped-writer behavior. Existing grouped,
exchange, batch and head-container regressions passed in the same gate. These
disposable-directory tests are separate from any ext4 latency measurement and
do not emulate a power cut. The matrix combines helper-process death with
separately constructed authenticated codec states, not an integrated
cryptographic process-crash recovery run. Explicit offline tail repair remains
deferred.

After tightening child fault setup to check every partial write count/error,
`go test -race ./internal/pkg/securestore -run '^TestFixedSegmentProcessDeath$'
-count=1 -v` passed again in 1.593 s; its log is
`/tmp/li-fixed-segment-process-death.log`. Focused `go vet -tags li` on both
packages and `git diff --check` also passed. The dedicated
`/tmp/li-fixed-segment-cache` is removed after the handoff; the three test logs,
empty successful vet log and prior measurement logs are preserved.

This test gate preceded the separately approved measurement below. The root-owned
raw I/O diagnostic remains explicitly incomplete protocol evidence. The task
host is shared, and no full-workload or final-integration result is implied.

## Fixed segment callback-floor measurement

After the reviewed fault/recovery gate and a passing independent byte-oracle
test, root approved only the 2- and 200-record probes, 40 transactions each.
The command was:

```sh
LC_LI_STORAGE_BENCH_DIR=/home/grischa/Projects/lippycat \
GOCACHE=/tmp/li-fixed-segment-cache go test -tags li ./internal/pkg/li/delivery \
  -run '^$' -bench '^BenchmarkSegmentDurabilityKernel$' \
  -benchtime=1x -count=1 -timeout=3m -v
```

The actual project volume was `/dev/mapper/volgroup0-lv_home`, ext4 with 4 KiB
blocks, `rw,nosuid,nodev,relatime`. Before running, 79,991,136,256 bytes were
available. Each case created one private disposable store, physically zero-wrote
and synced its full 32 MiB segment, and durably installed its controls, usage
ledger and two initial authenticated heads before admitting products. Actual
allocated blocks and the conservative 4 MiB metadata reserve stayed below the
96 MiB artifact budget; no settings or flushes were changed.

The machine remained a shared amd64/i9-13900HX host. Other task/test activity was
not excluded or synchronized for the corrected rerun; root codec race/build
and lifecycle tests ran during that interval. No controlled host or task-load
isolation is claimed. This was one warm probe per batch size, in 2- then
200-record order, with no power-loss test or randomized repetition.

All records in a batch share one actual admission timestamp before the real
10 ms accumulation wait. No virtual per-record offset is subtracted. Callback
timing includes current-head authentication, the corrected valid
PDU preflight, product/index/head encryption, real usage reservation renewals,
data/head writes, the definite `fdatasync`, and callback dispatch. Every commit
invokes that sync exactly once; there is no per-commit segment rename or directory
sync. Usage renewals still perform the existing independently durable file and
directory synchronization protocol. Setup's file/directory fsync costs remain
included in the separately reported initialization duration. The helper I/O
histogram includes writes and identity validation around `fdatasync`; it is not
an isolated syscall latency measurement.

| Metric                                                                     |                   2 records/batch |                 200 records/batch |
| -------------------------------------------------------------------------- | --------------------------------: | --------------------------------: |
| Batches / definite data-sync transactions                                  |                           40 / 40 |                           40 / 40 |
| Committed callbacks / externally verified original PDUs                    |                           80 / 80 |                     8,000 / 8,000 |
| Initialization including zero-write and bootstrap fsync, s                 |                          0.195700 |                          0.174332 |
| Measured wall seconds                                                      |                          0.556386 |                          0.626471 |
| Sequential-kernel copies/s                                                 |                            143.79 |                         12,769.94 |
| Callback exact p50 / p99 / max, ms                                         | 13.718546 / 18.682567 / 18.682567 | 14.767265 / 39.836771 / 39.838384 |
| Commit including usage/crypto/validation p50 / p99 upper, ms               |                     3.584 / 8.704 |                    4.608 / 30.720 |
| Append/head/validation/data-sync p50 / p99 upper, ms                       |                     3.456 / 8.192 |                     3.840 / 4.608 |
| Usage reserved invocations before → after                                  |                     4,096 → 4,096 |                     4,096 → 8,192 |
| Usage reserved blocks before → after                                       |             1,048,576 → 1,048,576 |             1,048,576 → 1,048,576 |
| Actual retained journal allocation, bytes / files                          |                    33,570,816 / 6 |                    33,570,816 / 6 |
| Fixed segment allocated bytes                                              |                        33,554,432 |                        33,554,432 |
| Conservative charged bytes / artifact budget                               |          37,765,120 / 100,663,296 |          37,765,120 / 100,663,296 |
| Codec scratch reservation, bytes                                           |                        16,777,216 |                        16,777,216 |
| Process CPU seconds / microseconds per copy                                |               0.016440 / 205.5000 |              0.087787 / 10.973375 |
| Process allocations / total allocated bytes during measured loop           |                 4,664 / 1,938,808 |              179,331 / 69,726,424 |
| Sampled heap at start / peak, bytes                                        |             2,035,472 / 3,974,280 |             2,178,432 / 9,860,584 |
| Sampled RSS peak, bytes                                                    |                        33,124,352 |                        43,089,920 |
| Warm reopen with both heads, all selected data and full tail validation, s |                          0.026312 |                          0.063781 |
| Additional external original-byte oracle check, s                          |                          0.000204 |                          0.006580 |

Both cases pass the frozen small p50 ≤25 ms, p99 ≤100 ms, max ≤1 s gate. The
200-record case crosses a real invocation reservation boundary, and every
callback and encoded byte matches after reopen. The oracle hashes exact original
input bytes with explicit lengths, then independently decrypts the recovered
records and compares that digest; it does not trust only stored record hashes.
The measured 12,770 copies/s remains below 20,000/s in this sequential harness,
which pauses accumulation during each commit. No concurrent producer admission,
completion, revocation, expiry, segment rotation, compaction, X2 contention,
full-capacity workload or soak is implemented or qualified by these measurements.

Heap/RSS samples occur after callbacks and do not establish the intracommit peak.
The measured loop's CPU/allocation totals include product generation, oracle
hashing, sampling, crypto and storage; initialization and reopen/oracle-check
costs are reported separately. The 4 MiB reserve covers the private parent/key
and other bounded metadata in addition to the reported journal allocation.
The corrected benchmark command finished in 1.664 s, including setup/reopen and
cleanup. Both disposable stores were removed by the harness.

Corrected exact output is preserved at `/tmp/li-fixed-segment-actual-admission.log`;
the superseded schedule-model log remains at `/tmp/li-fixed-segment-measurements.log`. The
external-byte-oracle race check passed in 1.273 s, with raw output at
`/tmp/li-fixed-segment-oracle-check.log`. The earlier failing strict-fixture log
and all prior measurement logs remain unchanged. The dedicated cache is removed
after reporting. Implementation stops here for review of the remaining
production-layout, throughput, rotation, compaction and control requirements;
this passing floor selects no production layout and does not close phase 5.

## Required final comparison and acceptance

The primary workload remains 100 bidirectional calls, 50 pps per direction, two
destinations: 10,000 source PDUs/s and 20,000 stored copies/s. Run 10 seconds of
warmup, 60 healthy seconds, 60 outage seconds, then drain with unchanged live
arrivals. Inject 100 X2 products/s of 512–4,096 bytes to two destinations during
recovery and compare isolated X2. Use real immutable X3 metadata, independently
bounded destinations, controls and transport; retain the encoded-byte oracle.

The primary outage requires 1.2 million records. Per-record allocation alone
would be at least 4,915,200,000 bytes (4.58 GiB) before metadata and reserves.
Configure X3 for two million entries and sufficient byte capacity plus live
recovery allowance. Before any full run, report the actual configured data,
control, scratch, destination, index, memory and free-filesystem bounds. The
current 512 MiB calibration configuration cannot qualify that outage.

The 100-call/four-destination/60-second variant produces 2.4 million copies. It is
an explicit saturation case with expected bounded rejection at the frozen
two-million-entry ceiling, not a second lossless qualification case. The
two-destination primary remains the supported workload.

| Metric             | Frozen primary acceptance                                                             | Current evidence                                                                     |
| ------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Durable copies     | ≥20,000/s, no loss with sufficient configured capacity                                | Unchanged per-record protocol infeasible from 200/s calibration                      |
| Callback latency   | p50 ≤25 ms, p99 ≤100 ms, max ≤1 s                                                     | Immutable kernels fail; small fixed-segment kernel passes, full workload unqualified |
| Producer admission | p99 ≤5 ms, no storage-sync wait                                                       | Short 200/s proxy passes timing only                                                 |
| Healthy backlog    | No positive slope in final 30 s                                                       | Short proxy backlog grows; full run not performed                                    |
| Recovery           | ≥40,000 copies/s total, backlog drained ≤90 s with arrivals                           | Full workload not performed                                                          |
| Revocation         | No claim after memory boundary; durable p99 ≤250 ms, max ≤2 s, including full spool   | Not implemented by calibration                                                       |
| Expiry             | No late claim; notice ≤1 s; healthy reclaim ≤5 s                                      | Not implemented by calibration                                                       |
| Restart            | ≤10 s for 100k / ≤60 s for 1m, payloads lazy                                          | Only 128-record warm probe; current payload recovery is eager                        |
| Allocation         | All allocations and conservative pending/rewrite reservations within budget           | Sampled small-store observations only                                                |
| Memory             | RSS ≤managed reservation +256 MiB; final 10 min of 15-min soak <5% unexplained growth | Soak not performed                                                                   |
| CPU/allocations    | Report per-copy cost; ≥20% CPU headroom at target                                     | Small proxy measured; target not sustained                                           |
| X2 shared device   | p99 ≤2× isolated and ≤100 ms; no rejection from X3 capacity                           | Not measured                                                                         |

Further work remains explicit:

- [x] Measure the existing protocol on real ext4 with paced synthetic products.
- [x] Record the failure and preserve production limits unchanged.
- [x] Review the purpose-9/bounded-framing and batch-before-head ordering for a benchmark-only kernel.
- [x] Measure that kernel's complete callback floor and record its failed median gate.
- [x] Review the grouped-publication alternative before implementing another kernel.
- [x] Measure the grouped kernel with exact callback percentiles and real usage renewal; record its failed median gate.
- [x] Review the exact head-container/exchange protocol before its narrow implementation.
- [x] Implement and fault-test that kernel, measure exact callback percentiles with real usage renewal, and stop at its failed median gate.
- [x] Obtain review for the narrow fixed-segment helper/codec/recovery implementation and test gate; defer tail reconciliation.
- [x] Obtain separate approval and run the corrected-PDU segment callback-floor measurement; its small latency gate passes.
- [ ] Review the remaining segment layout, throughput, rotation, compaction and control requirements before further runtime work.
- [ ] Complete and freeze [the full checkpoint/control protocol](../design/li-x3-batch-layout.md).
- [ ] Implement a benchmark-only prototype with the full durable reader and completion obligations after a kernel demonstrates headroom.
- [ ] Measure comparable batching results before selecting a production layout.
- [ ] Add actual X3 admission, lifecycle controls, independent X2/X3 capacity and transport to the harness.
- [ ] Run the primary workload, secondary saturation cases, full-capacity controls, 15-minute soak and 100k/1m restart cases.
- [ ] Repeat the complete acceptance campaign after final integration; publish supported load and limitations.
