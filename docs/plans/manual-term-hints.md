# Manual glossary and abbreviation hints

## Objective and scope

Extend the mdBook manual with definitions for unfamiliar abbreviations and terms.
Readers can preview a definition on hover or keyboard focus and keep it open by
clicking or tapping. Definitions come from the appendix glossary in the reader's
language, with a link to the corresponding glossary entry.

Implementation branch: `docs/manual-term-hints`.

This plan covers the manual build, glossary metadata, browser interaction,
translations, contributor documentation, and validation. It does not change the
lippycat application. The current task creates this plan only; implementation
tasks below remain unchecked until their results have been verified.

## Existing integration points

`docs/manual/book.toml` already loads JavaScript and CSS from `theme/`.
`docs/manual/tools/manual.py` builds every edition in `languages.json`, using
Gettext catalogs before HTML rendering, then checks chapter paths, heading IDs,
examples, inline code, and links across languages. Catalan is published at the
site root, with English under `/en/` and German under `/de/`.

`docs/manual/src/appendices/glossary.md` contains a term/definition table with
translations in the existing PO catalogs. Reuse those definitions rather than
maintaining another collection of translated explanations.

## Design

### Glossary identity and generated data

Give each glossary term a stable, language-independent identifier, preserved in
the translated term cell through a small HTML marker. Do not derive identifiers
from translated labels or table row order. Validate that every edition contains
the same identifiers and that each appears exactly once.

Extend the existing Python build workflow to read each edition's rendered
glossary and generate its own dictionary after mdBook has run. Each entry contains
its identifier, localized label, plain-text definition, permitted matching aliases,
and glossary fragment destination. Use the full existing definition initially;
keep the popup readable with wrapping and scrolling rather than duplicating or
automatically truncating technical explanations. The full glossary retains its
formatted text and reference links.

Keep matching policy and aliases in a small committed metadata file, separate
from definitions. Distinctive abbreviations such as PCAP, BPF, SIP, and TLS can
match automatically. Ambiguous words such as filter and tap require explicit
annotation. Language-specific aliases may be configured, but definitions remain
in the glossary and PO catalogs. Missing identifiers, conflicting aliases, or
empty definitions must produce actionable build errors.

Generate data into the ignored book output, not the source tree. Resolve it from
the current edition root so nested chapters and the root Catalan edition work.
Use the assembled `make manual-serve` preview; document that a bare `mdbook build`
does not run any added post-build processing.

### Term recognition and author controls

Load the edition dictionary once and enhance eligible text nodes inside the
chapter's main content. Match complete terms with Unicode-aware boundaries,
longest aliases first, and deliberate case rules for abbreviations. Do not match
inside longer identifiers, paths, or flag names. Preserve the original text.

Exclude existing links, inline and fenced code, headings, diagrams, scripts,
styles, navigation, form controls, glossary definitions, and generated hint UI.
Repeated initialization must not create nested or duplicate triggers. Initially,
enhance only the first automatic occurrence of each term in a chapter to avoid
excessive keyboard stops; explicit annotations always remain available.

Provide a documented explicit marker such as
`<span data-term="processor">processor</span>` and an opt-out marker such as
`<span data-no-term-hints>...</span>`. Stable identifiers and attributes must survive
translation, while visible words remain translatable. Add examples showing how
to introduce a term, an alias, and an exclusion.

### Hover, touch, and keyboard interaction

Style triggers with a subtle dotted underline and a visible focus indicator.
Use a keyboard-operable trigger and one reusable popup. Hover and focus show a
preview without moving focus; click, tap, Enter, or Space pins it open. Pointer
movement from the term into the popup must not dismiss it.

The popup includes the localized term, definition, a glossary link, and a close
control. Because it contains interactive controls, use an appropriate non-modal
popover/dialog pattern rather than placing links inside an ARIA tooltip. Associate
the trigger and definition for assistive technology and expose open/closed state.
Keyboard users must be able to reach the glossary link and close control. Escape
closes the popup and returns focus when it was moved into the popup; do not trap
focus or intercept mdBook shortcuts outside the active interaction.

Only one popup may be open. A second activation of its trigger, outside click or
tap, close control, or Escape dismisses it. Switching terms updates the popup.
An unpinned preview closes after hover and focus leave both trigger and popup.
Avoid synthetic mouse events reopening a dismissed touch popup.

Keep the popup within the viewport, reposition it on resize and scrolling, and
support long definitions on narrow screens. Use mdBook theme variables for all
themes, retain legibility at browser zoom, and hide hint UI in printed output.
With JavaScript disabled or dictionary loading failing, chapter text and the full
glossary must remain readable. Report loading failures without breaking the page.

### Localization and compatibility

Read languages from `languages.json`; do not hard-code the three current editions
into matching or URL resolution. Localize popup controls through the existing
language UI metadata. Update every affected PO catalog when adding glossary
markers or annotations, and review affected fuzzy entries in the same task.

Preserve existing examples, code spans, links, and heading IDs. Extend build
verification for glossary identifiers and dictionaries without weakening existing
checks. Keep generated popup content out of the search index, and ensure the
combined print edition has no duplicate glossary IDs or automatic hints.

Prefer the existing Python standard library and plain JavaScript/CSS. No new
runtime service or framework is needed. If an additional tool or package becomes
necessary, verify its latest stable release and compatibility before adding it;
do not upgrade unrelated manual dependencies as part of this feature.

## Implementation checklist

- [ ] Add stable glossary identifiers and matching metadata; update and review
      affected German and Catalan catalog entries.
- [ ] Implement per-edition dictionary generation and validation in the manual
      build, including stable glossary destinations and existing verification.
- [ ] Implement safe automatic matching, explicit annotations, exclusions, and
      initialization that can run repeatedly without duplicating hints.
- [ ] Add the accessible popup interaction and responsive styling, register assets
      in `book.toml`, and localize its controls for every configured edition.
- [ ] Document contributor usage in `docs/manual/README.md`; if reader-facing
      manual text changes, translate it in every configured language.
- [ ] Add focused regression checks for extraction, matching boundaries, language
      isolation, interaction state, and accessibility behavior.
- [ ] Run the validation below, inspect desktop and mobile behavior, and record
      results and any genuine limitations in this plan.
- [ ] Format changed files, check off only verified tasks, and commit the code,
      translations, documentation, and updated plan on this branch.

## Validation and completion

- [ ] Run the existing Python manual tests plus focused dictionary tests covering
      Unicode, punctuation, missing/duplicate IDs, alias collisions, and nested
      chapter URLs in root and non-root editions.
- [ ] Run `make manual-check` and `make manual`; verify affected translations have
      no missing or fuzzy entries. Preserve all existing cross-edition checks.
- [ ] Exercise browser checks for hover, movement into the popup, pinned click,
      repeated activation, outside dismissal, switching terms, and Escape.
- [ ] Exercise keyboard-only use, focus restoration, accessible relationships,
      touch input, and dismissal without immediate synthetic-event reopening.
- [ ] Inspect representative English, German, and Catalan chapters, including
      abbreviations, translated terms, explicit annotations, and exclusions.
- [ ] Inspect narrow screens, zoom, every mdBook theme, long definitions, nested
      chapter navigation, language switching, search, and the print edition.
- [ ] Check that code, links, diagrams, headings, and glossary definitions remain
      unchanged by matching; check no-JavaScript and failed-data loading behavior.

Completion means the requested hover and click/tap hints work across all configured
editions, accessible interaction is verified, glossary content remains the single
source of definitions, and the implementation is committed. Performance
observations may inform implementation choices but do not introduce numerical
acceptance targets.

## Planning references

mdBook documents additive JavaScript/CSS in its
[HTML renderer configuration](https://rust-lang.github.io/mdBook/format/configuration/renderers.html)
and optional Markdown transformation in its
[preprocessor configuration](https://rust-lang.github.io/mdBook/format/configuration/preprocessors.html).
The proposed implementation uses existing assets and the project's build wrapper;
it does not require modifying mdBook itself.
