# German manual and multilingual infrastructure

Keep English Markdown authoritative, preserve existing English URLs, and publish
German at `/de/`. Use Gettext catalogs for additional languages and formal German
address (Sie), preferring neutral phrasing where natural.

- [x] Pin and verify mdBook-compatible translation tooling.
- [x] Add translation extraction/update, build, and preview commands.
- [x] Add language navigation, stable heading links, and localized metadata.
- [x] Update deployment and CI to build and validate every configured language.
- [x] Translate all manual chapters and navigation into German.
- [x] Document translation conventions and adding another language.
- [x] Verify builds, catalog completeness, examples, links, search, and diagrams.
- [x] Format changed files.

Commit the implementation and this verified plan together after the final check.

Verification: all 5,342 current German catalog entries are translated; both
editions build successfully. Three fallback/command-preservation regression tests
pass. Generated chapters preserve heading IDs, links, inline code, and all 699
fenced examples and diagrams. Selector checks cover six navigation cases,
including a third language and subdirectory hosting; German search-index queries
find translated content. Prettier, Ruff, and whitespace checks pass.

The independent review found two fuzzy-translation defects; both are fixed and
the affected paths passed the integrated review. Live browser inspection was
unavailable because no browser was connected. GitHub Pages deployment runs on the
next qualifying push; it was not executed during local verification.
