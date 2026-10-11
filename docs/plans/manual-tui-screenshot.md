# Add the live capture screenshot to the TUI chapter

- [x] Add the supplied screenshot after the chapter introduction with a numbered
      caption and a reference from the details shortcut explanation.
- [x] Support images in the existing figure preprocessor and translate the new
      text into German and Catalan.
- [x] Format changed files, run manual checks, build all editions, and verify the
      screenshot, appendix link, and fullscreen viewer in the browser.

Validation: `make manual-check manual` passed all 47 tests and built every edition.
Strict translation checks passed with 5729/5729 current messages in both catalogs.
Local Chromium checks verified placement, caption, details reference, appendix
link, fullscreen viewing, mobile tap, and print visibility in all three editions.
The rendered English chapter was inspected visually.

Commit the screenshot, documentation, supporting changes, and completed plan.
