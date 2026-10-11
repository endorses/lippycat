# Manual glossary and abbreviation hints

## Objective and scope

Extend the mdBook manual with definitions for unfamiliar abbreviations and terms.
Readers can preview a definition on hover or keyboard focus and keep it open by
clicking or tapping. Definitions come from the appendix glossary in the reader's
language. The popup contains only the term and definition.

Implementation branch: `docs/manual-term-hints`.

This plan covers the manual build, glossary metadata, browser interaction,
translations, contributor documentation, and validation. It does not change the
lippycat application. Implementation and validation are complete. Completed tasks below are backed by
the recorded build, translation, browser, and visual checks.

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
its identifier, localized label, plain-text definition, and permitted matching
aliases. Use the full existing definition initially;
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
Repeated initialization must not create nested or duplicate triggers. Enhance
every eligible automatic occurrence so terms remain available when readers jump
to a subsection; explicit annotations also remain available.

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

The popup includes only the localized term and definition, including the glossary's
inline reference links. Definitions with links use a labeled, nonmodal ARIA dialog;
plain definitions use a descriptive tooltip. The trigger references its definition
with `aria-describedby` and exposes open/closed state. Focus stays on the triggering
term; Tab reaches reference links before continuing through the chapter. Escape
from a reference link dismisses the popup and returns focus to the term.
Overflowing definitions can be scrolled with arrow keys, Page Up/Down, or Home/End
while the term has focus. Do not intercept mdBook shortcuts outside the active
interaction.

Only one popup may be open. A second activation of its trigger, outside click or
tap, or Escape dismisses it. Switching terms updates the popup.
An unpinned preview closes after hover and focus leave both trigger and popup.
Avoid synthetic mouse events reopening a dismissed touch popup.

Keep the popup within the viewport, reposition it on resize and scrolling, and
support long definitions on narrow screens. Use mdBook theme variables for all
themes, retain legibility at browser zoom, and hide hint UI in printed output.
With JavaScript disabled or dictionary loading failing, chapter text and the full
glossary must remain readable. Report loading failures without breaking the page.

### Localization and compatibility

Read languages from `languages.json`; do not hard-code the three current editions
into matching or URL resolution. Definitions use the existing translated glossary;
no separate control-label translations are needed. Update every affected PO
catalog when adding glossary
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

- [x] Add stable glossary identifiers and matching metadata; update and review
      affected German and Catalan catalog entries.
- [x] Implement per-edition dictionary generation and validation in the manual
      build, preserving stable glossary IDs and existing verification.
- [x] Implement safe automatic matching, explicit annotations, exclusions, and
      initialization that can run repeatedly without duplicating hints.
- [x] Add the accessible popup interaction and responsive styling, register assets
      in `book.toml`, using localized definitions in every configured edition.
- [x] Document contributor usage in `docs/manual/README.md`; if reader-facing
      manual text changes, translate it in every configured language.
- [x] Add focused regression checks for extraction, matching boundaries, language
      isolation, interaction state, and accessibility behavior.
- [x] Run the validation below, inspect desktop and mobile behavior, and record
      results and any genuine limitations in this plan.
- [x] Format changed files, check off only verified tasks, and commit the code,
      translations, documentation, and updated plan on this branch.

## Validation and completion

- [x] Run the existing Python manual tests plus focused dictionary tests covering
      Unicode, punctuation, missing/duplicate IDs, alias collisions, and nested
      chapter URLs in root and non-root editions.
- [x] Run `make manual-check` and `make manual`; verify affected translations have
      no missing or fuzzy entries. Preserve all existing cross-edition checks.
- [x] Exercise browser checks for hover, movement into the popup, pinned click,
      repeated activation, outside dismissal, switching terms, and Escape.
- [x] Exercise keyboard-only use, focus restoration, accessible relationships,
      touch input, and dismissal without immediate synthetic-event reopening.
- [x] Inspect representative English, German, and Catalan chapters, including
      abbreviations, translated terms, explicit annotations, and exclusions.
- [x] Inspect narrow screens, zoom, every mdBook theme, long definitions, nested
      chapter navigation, language switching, search, and the print edition.
- [x] Check that code, links, diagrams, headings, and glossary definitions remain
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

## Verified results

`make manual-check` passes all 22 Python regression checks. Both German and
Catalan have 5,592/5,592 current messages translated, also verified with
`python3 docs/manual/tools/manual.py check --require-complete`.
`make manual` builds all three editions and retains the existing chapter,
heading-ID, example, code-span, and link comparisons, with annotation checks added.
Every edition has the same 60 unique glossary identifiers, 57 automatically
matched terms, and three explicit-only terms (filter, processor, and tap).

The standalone Playwright suite passes all 12 browser checks against the final
rebuilt manual in Chromium. It covers Unicode and identifier boundaries, longest
aliases, exclusions, explicit translated processor/tap annotations, repeated
initialization, hover, pointer movement into the popup, pinned activation,
dismissal, keyboard and focus behavior, touch and synthetic mouse suppression,
loading failure, and no-JavaScript reading. Actual edition checks follow glossary
fragments, switch languages, search, and verify print IDs and exclusions.

Viewport checks cover 320px screens, long scrolling definitions, all five mdBook
themes, enlarged fonts, Chromium page scaling, and a pinned popup whose trigger
scrolls offscreen. Screenshots of all five themes and desktop/mobile Catalan,
English, and German pages were inspected. Verification caught and fixed a long
popup covering its trigger and a German footer link splitting inside a word;
focused regressions verify their corrected behavior. Temporary QA screenshots
are removed after review.

The original bounded closure review reached `CLOSED`: the independent review found no
material implementation defect, and the one visual finding was fixed and verified
with an integrated review. No numerical performance gates or dependencies were
added. Browser verification uses Chromium with emulated touch; physical mobile
hardware and screen-reader software were not used. The local mdBook 0.5.2 tool
reports the existing warning that Gettext was built against 0.5.4; the installed
version mismatch did not prevent any checks or builds, and shared tool pins remain
unchanged.

Implementation and the verified plan were committed as `08d5c2ec`. This final
plan update records the commit task after verifying that commit succeeded.

## Requested popup simplification

The user subsequently requested a subtle shadow, then removal of the glossary
link and close button. The shadow is retained. The popup now contains only the
localized term and definition, with tooltip semantics and no additional Tab stops.
Repeat activation, outside click/tap, and Escape dismiss it. Long definitions
remain scrollable with touch/wheel input and keyboard keys on the focused term.
Control-only labels and navigation fields were removed from generated data and
language configuration. The glossary and its stable entry anchors remain intact.
The earlier footer-layout result above records the original implementation;
those controls and their associated tests have now been removed.

The simplified hints pass `make manual-check` (21 Python checks), `make manual`
for all three editions, and all 12 updated browser checks. Keyboard scrolling,
hover/tap dismissal, zero popup controls/Tab stops, localized definitions,
mobile bounds, and shadow styling are verified. Final desktop and mobile
screenshots were inspected; temporary QA artifacts are removed after review.

Dark-theme hints now use the existing theme palette for a lighter surface and
visible border, with a stronger shadow. Navy, Coal, and Ayu were checked in the
local browser and their screenshots reviewed; all language editions rebuild.

## Integration with newer main

Merged `docs/manual-term-hints` (`f6cc2345`) into local `main` after fetching
`origin/main` at `95c260e6`. Main's newer reliability documentation, tests, and
implementation were retained. The catalogs were reconciled by integrating the
63 hint annotations while preserving all other current main translations;
unwrapped translated text for the annotated entries was also verified unchanged.
The reviewed merge changes only the 17 files belonging to this manual feature.

Validation on the merged tree passes all 21 Python checks, all 12 Chromium browser
checks, `make manual-check`, and `make manual` for all three editions. Strict
translation checking confirms German and Catalan each have 5,599/5,599 current
messages translated. The browser suite covers hover, touch, keyboard interaction,
dark themes, and the actual translated editions. Formatting and staged whitespace
checks pass. The merge is local; no remote branch is published by this operation.

## Follow-up: hints throughout a chapter

Readers entering a chapter through a subsection link need definitions beside the
terms in that section. The user's request supersedes the original first-occurrence
matching policy. Apply automatic hints to every eligible occurrence, preserving
structural exclusions, boundary matching, localized definitions, and idempotent
initialization.

Recognize the manual's German `PCAP-Datei` and `PCAP-Dateien` forms through explicit
aliases, keeping the existing guards for flags, identifiers, and paths.

- [x] Remove the first-occurrence restriction and update contributor guidance.
- [x] Verify repeated terms within and across paragraphs, subsection entry, keyboard navigation, touch interaction, and repeated initialization.
- [x] Validate translations, build every edition, and format the correction.
- [x] Commit the correction and this plan update.

Validation: all 14 Chromium browser checks pass, including actual introduction
subsection links and repeated mobile hints in English, German, and Catalan.
`make manual-check manual` passes all 39 Python checks and builds every edition.
Strict translation checking confirms German and Catalan each have 5,714/5,714
current messages translated. Existing exclusions and boundary guards remain
covered, and repeated initialization preserves the chapter text without creating
nested triggers.

## Follow-up: clickable definition references

The glossary already refers to chapters and sections through Markdown links.
Preserve those links in the generated hints, keeping destinations inside the
current language edition and rendering text and anchors without raw HTML.
This adds only the references within the definition; the removed glossary shortcut
and close button remain absent. Match the German references to Core Concepts to
the chapter's translated name, `Grundbegriffe`.

- [x] Preserve localized inline reference links during glossary extraction.
- [x] Render reachable reference links with appropriate keyboard and popup behavior.
- [x] Correct German reference labels and verify unchanged English and Catalan labels.
- [x] Validate dictionaries, browser interaction, translation completeness, and every manual edition.
- [x] Format the implementation and plan.
- [x] Commit the implementation and plan.

Validation: all 44 Python checks and 15 Chromium browser checks pass. Browser
checks cover reference navigation from nested chapters, focus and Escape behavior,
rejected unsafe destinations, and keyboard/touch navigation to Core Concepts in
each language. All 60 extracted reference destinations per edition exist,
including their section anchors. Desktop and mobile screenshots confirm readable
inline links. `make manual-check manual` builds every edition, and strict checking
confirms German and Catalan each retain 5,714/5,714 translated current messages.

## Follow-up: termshark comparison and VoIP/ESP glossary entries

Extend the introduction's comparison with termshark, explaining its tshark-backed
terminal interface and distinguishing inspection over SSH from native capture-node
monitoring. Add localized glossary definitions and automatic hints for VoIP and ESP,
including the ESP-NULL alias and its unencrypted payload behavior. Align the
introduction's ESP-NULL description with that distinction.

- [x] Update the English introduction, glossary, and hint matching policy.
- [x] Translate new and changed messages in German and Catalan.
- [x] Verify termshark's comparison column and localized VoIP/ESP definitions and hints.
- [x] Run manual checks, strict translation validation, and build every edition.
- [x] Format the changes and plan.
- [x] Commit the changes and plan.

Validation: `make manual-check manual` passes all 44 Python checks and builds
English, German, and Catalan. Strict translation validation confirms 5,722/5,722
current messages translated in each catalog. All 15 existing browser checks pass;
an additional temporary smoke check verifies the six-column comparison table,
VoIP/ESP glossary entries, desktop hover, and mobile taps/reference navigation in
every edition. Termshark's capabilities were checked against its
[official user guide](https://github.com/gcla/termshark/blob/master/docs/UserGuide.md);
ESP and ESP-NULL terminology were checked against
[RFC 4303](https://www.rfc-editor.org/info/rfc4303/) and
[RFC 2410](https://www.rfc-editor.org/info/rfc2410/).
