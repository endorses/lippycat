# Event View Filtering

## Goal

Make `/` a first-class event-query entry point when the Capture tab is in the
Events view. Event filters must search retained structured events immediately
and behave identically for remote, live, and future file-backed event sources.

Protocol scope selected with `p` remains independent:

```text
visible events = protocol scope AND stacked event filters
```

## User-facing behavior

- Bare text searches event kind, summary, envelope/provenance values, and every
  delivered canonical event field. For example, `firefox` matches an HTTP host
  or user agent even when it is only visible in Details.
- Structured fields use canonical `logschema` names, with common aliases:
  `kind:conn`, `event:conn`, `node:node-1`, `src:192.0.2.1`,
  `host:example.org`, and `status_code:>=400`.
- Text matching is case-insensitive. Lists match any member. Numeric, duration,
  time, and boolean fields support typed comparisons.
- Boolean expressions support `AND`, `OR`, `NOT`, parentheses, and quoted
  values. Successive submissions stack with `AND`.
- Unknown fields and invalid values produce an error without changing the
  current projection.
- Applying or removing a filter immediately rescans retained events in all
  capture modes; live mode does not clear the timeline and wait for new events.

## Implementation

- [x] Extract canonical event projection from the Events renderer into a shared
      package that exposes typed canonical fields plus envelope and provenance
      fields without defining a second schema.
- [x] Add an event-query parser and compiled predicate supporting bare text,
      kind aliases, common flow/provenance aliases, canonical fields, typed
      comparisons, and boolean composition.
- [x] Extend `EventStore` with a user-filter chain separate from protocol kind
      scope. Maintain the full bounded store, derive a filtered projection,
      filter new arrivals incrementally, and preserve selection by event ID.
- [x] Add independent event-filter input state and history. Extend the existing
      context-sensitive `/` dispatch: Packets uses packet filters, Calls uses
      call filters, and Events uses event filters.
- [x] Route `c`, `C`, active-filter descriptions, and filter counts to the
      current Capture view while preserving each view's filters when cycling
      with `v`.
- [x] Keep the Events filter prompt and timeline consistent with packet and call
      filtering, without view-specific prompt text or projection counts.
- [x] Reuse the same store and query behavior for `watch live`, `watch remote`,
      and `watch file`; clear event filters when a new offline input replaces
      the current analysis session.
- [x] Keep filtering local initially. Treat remote server-side subscription
      narrowing as a later optimization with identical semantics, not as the
      source of truth for interactive filtering.

## Verification

- [x] Test bare-text matches in hidden/detail-only fields such as HTTP host,
      user agent, TLS server name, DNS answers, recipients, filenames, and
      hashes.
- [x] Test kind filtering with `conn`, `kind:conn`, and `event:conn`.
- [x] Test canonical fields, aliases, typed comparisons, quoting, boolean
      expressions, lists, empty values, and invalid expressions.
- [x] Test protocol-scope intersection, stacked filters, remove-last, clear,
      view cycling, live arrivals, pause/resume, eviction, and stable selection.
- [x] Test that packet, call, and event filters have independent state and
      context-sensitive key handling.
- [x] Test equivalent projections for locally produced and decoded remote
      events, then add deterministic `watch file` coverage when that ingestion
      path is enabled.

## Non-goals

- Applying packet/BPF filter grammar directly to normalized events.
- Filtering unauthorized or omitted fields unavailable to the client.
- Exporting filtered events or adding server-side arbitrary query execution in
  the initial implementation.
