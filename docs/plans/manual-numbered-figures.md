# Numbered manual figures

Add academic-style figure numbers and descriptive captions to all 29 Mermaid
diagrams. Use continuous numbering in the manual's reading order, shared by all
editions and the print page. Keep descriptive anchors stable when figures move;
numbers may change when diagrams are inserted or reordered.

- [x] Wrap each Mermaid diagram in a semantic figure with a descriptive anchor and English caption.
- [x] Translate captions into German and Catalan without changing diagram source or anchors.
- [x] Add an HTML preprocessor that numbers figures after translation and before Mermaid rendering.
- [x] Style captions for all themes, small screens, and printing; document authoring conventions.
- [x] Verify numbering, malformed input rejection, translated invariants, and browser rendering.
- [x] Run `make manual-check`, strict translation checking, and `make manual`.
- [x] Commit the verified implementation and plan.

Use existing Python tooling and mdBook's preprocessor protocol; no new runtime
dependency is required. Figure numbers are generated at build time so captions
remain visible without JavaScript and print numbering matches individual pages.
Existing code samples, text command trees, and TUI examples retain their formatting.

## Verified results

The completed implementation gives all 29 Mermaid diagrams descriptive captions
and stable figure anchors. Numbers follow the complete manual's reading order;
localized labels are Figure, Abbildung, and Figura. Original Mermaid content is
unchanged, and existing catalog entries were preserved while adding 29 captions
to each translated edition.

All 32 Python checks pass, including nested chapter numbering, renderer negotiation,
malformed wrapper/caption rejection, generated-ID collisions, and actual mdBook
chapter/print rendering. `make manual-check`, `make manual`, and strict translation
checking pass; German and Catalan each have 5,695/5,695 current messages translated.
Rendered figure identifiers, numbers, and caption identifiers are compared across
editions alongside the existing chapter invariants.

Chromium verification confirms all three print editions have numbers 1–29 matching
their individual chapter figures, 29 rendered SVGs, and no Mermaid errors. Stable
fragments, language switching, accessible caption labels, and captions with
JavaScript disabled pass. Desktop/light and 320px mobile Navy/Coal screenshots
were reviewed: captions remain readable and fit their containers. All 12 existing
glossary-hint browser checks pass. Browser mobile checks use emulated viewports.

The bounded implementation-plan closure review reached `CLOSED`: the independent
review found no material issue, and build/browser evidence covers the scoped
requirements. No remediation batch, performance target, or external gate was
added. Temporary review artifacts were removed. The existing local mdBook/Gettext
version warning remains harmless; tool pins and runtime dependencies are unchanged.

Implementation and the verified plan were committed as `21a0bc99`. This final
plan update records the commit task after verifying that commit succeeded.
