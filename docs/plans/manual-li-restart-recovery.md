# Correct LI restart recovery documentation

Update the manual to describe optional encrypted administrative persistence,
authorization after restart, and current ADMF synchronization behavior.

- [x] Correct the restart, synchronization, failure handling, and certificate
      rotation text and update the synchronization diagram.
- [x] Translate affected passages into German and Catalan and review fuzzy entries.
- [x] Format changed files, validate complete translations, build all editions,
      and inspect the updated diagram and links in the browser.

Validation: `make manual-check manual` passed, including 44 unit tests and all
three editions. Strict completeness checks found 5726/5726 translated current
messages in both catalogs. Local Chromium checks verified the revised diagram,
section links, fullscreen rendering, and mobile tap in all three editions.

Commit the corrected manual, translations, and completed plan after validation.
