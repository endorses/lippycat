# Prevent overlapping mdBook image viewers

GitHub Pages builds with mdBook 0.5.4, which wraps ordinary images in a native
checkbox viewer. Local mdBook 0.5.2 lacks that feature, so local checks missed
the extra overlay beneath the manual's fullscreen dialog.

- [x] Remove the generated native image wrappers before enhancing their original
      images, including images added after initialization.
- [x] Add browser regression checks for single-click dismissal of screenshots
      and GIFs, keyboard activation, and mobile tap.
- [x] Format changed files, validate and build all editions with the Pages version,
      and run the browser suite against the resulting output.

Validation: the original script reproduced a checked native image checkbox and
visible overlay after closing the manual dialog on mdBook 0.5.4. With the fix,
`make manual-check manual` passed all 47 tests and built every edition using
the Pages version. The image-viewer browser suite passed against both 0.5.4 and
local 0.5.2, covering all three languages, themes, screenshots, GIFs, dynamic native
wrappers, keyboard, touch, single-action dismissal, restored scrolling/focus,
and print output. No translatable content changed.

Commit the fix, regression checks, and completed plan.
