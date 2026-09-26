# Legacy LI administrative-state fixture

`legacy_state_v1.json` is canonical, hand-authored synthetic JSON for the schema
at `77f7abfe`. Copy the checked-in text to reproduce it; no live task, captured
content or deployment secret is included. Dates and identities are fixed.

| XID prefix | Case                                                                                                              |
| ---------- | ----------------------------------------------------------------------------------------------------------------- |
| `11111111` | Active SIP task, generation 3; startup candidate pending ADMF confirmation                                        |
| `33333333` | Active scoped RADIUS conjunction, generation 31, explicit MAC profile; requires fresh authorization after restart |
| `44444444` | Pending task starting in 2100, referencing a removed destination                                                  |
| `55555555` | Retained deactivated task, generation 7, removed destination, later generation watermark 8                        |
| `66666666` | Retained failed task, removed destination, durable error text and generation 9                                    |
| `77777777` | Expired task with no explicit map entry; its task-only generation 13 must still seed the watermark                |
| `88888888` | Absent task with cleanup obligation and retained generation watermark 21                                          |

The only present destination has prefix `22222222`, both interfaces enabled and
delivery revision 5. Prefix `99999999` deliberately remains absent while pending
and retained task definitions still reference it. Cleanup includes full UUID IDs
and a pre-migration short RADIUS ID. `written_at`, creation, activation and
deactivation examples use `2026-01-02T03:04:05Z`.

`TestPersistenceLegacyStateFixture` checks decoding and real manager restoration
using a private copy: no filter is armed, active tasks remain candidates, pending
and retained definitions survive removed destinations, cleanup is replayed,
expired and absent-task watermarks survive, and no file-derived task is authorized
for replay. The fixture also exercises every persisted task/destination field,
including RADIUS scope and profile. Task JSON field capitalization is intentional:
the legacy task struct had no JSON field-name tags.

The baseline `loadPersistedState` reader checks the version but uses an unbounded
`ReadFile` and ordinary JSON unmarshal. It accepts unknown fields, and missing
files mean no state. These are legacy limitations, not requirements for the new
encrypted reader or offline migration. Strict migration must additionally validate
the complete schema, duplicate identities, resource bounds and lifecycle
invariants. This fixture does not claim that a plaintext file can authorize X3.
