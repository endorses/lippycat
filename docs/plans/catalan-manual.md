# Catalan manual edition

Add a complete Catalan edition on `docs/catalan-manual`, using the English source
and German catalog to preserve technical intent. Retain examples, identifiers,
links, and heading IDs shared by all editions.

- [x] Configure Catalan metadata, navigation strings, and translation conventions.
- [x] Translate every current catalog message using English and German references.
- [x] Review technical meaning, terminology, and reader-facing wording.
- [x] Validate complete coverage and build all editions; inspect generated Catalan
      navigation, search index, and diagram blocks.
- [x] Format and commit the manual changes and this completed plan on the branch.

Validation: `make manual-check manual` and the strict `--require-complete` check
pass. Catalan covers 5,549/5,549 current messages; generated navigation, all 593
search sections, and all 27 shared Mermaid diagram blocks were inspected. A live
browser preview was unavailable in this session.
