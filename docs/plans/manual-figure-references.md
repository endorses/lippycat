# Figure references and appendix index

Extend the numbered figures with linked number references in chapter prose and a
List of Figures appendix. Generate labels and the index from the same localized
figure catalog so numbers, captions, and destinations stay synchronized.

- [x] Add build-time figure references and a generated figure-list placeholder, preserving fenced examples and rejecting unknown targets.
- [x] Refer to every existing diagram from its surrounding prose using stable identifiers.
- [x] Add the appendix to the table of contents and translate new/changed prose into German and Catalan.
- [x] Document authoring syntax and validate translation marker preservation.
- [x] Verify forward/cross-chapter links, list entries, print behavior, and language switching in tests and the browser.
- [x] Run `make manual-check`, strict translation checking, and `make manual`.
- [x] Commit the verified implementation and plan.

The original numbered-figure implementation is already closed. This plan covers
only the requested references and appendix extension; existing diagram content
and captions remain unchanged. No new dependencies or performance gates are needed.

## Verification and closure

Campaign `manual-figure-references-20261010` is **CLOSED**. The independent
bounded review found no material issues; no remediation was needed.

All 39 Python checks passed. `make manual-check`, strict translation checking,
and `make manual` passed, with all 5,697 current messages translated in German
and Catalan. Every edition contains all 29 numbered prose references and all
29 generated appendix entries.

Focused browser checks activated every appendix and prose link in all three
editions and their print output, verified language switching and navigation
without JavaScript, and checked desktop English and 320-pixel German navy
layouts. Screenshot review found no clipped entries. Formatter checks and
`git diff --check` passed. Temporary browser artifacts were removed after review.

Implementation and plan committed as `16f121a8` on
`docs/manual-numbered-figures`; the working tree was clean after the commit.
