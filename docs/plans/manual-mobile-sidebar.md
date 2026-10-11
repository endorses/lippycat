# Dismiss the manual sidebar on mobile

Below mdBook's 620-pixel layout breakpoint, clicking or tapping outside an open
sidebar should close it. Clicking inside the sidebar should leave it open, and
desktop readers should retain the existing docked-sidebar behavior.

- [x] Add mobile outside-click handling through mdBook's existing sidebar state
      handler.
- [x] Verify touch, mouse, toggle behavior, and the desktop breakpoint in every
      manual edition.
- [x] Format changed files, run manual checks and builds, and verify local and
      Pages mdBook versions before committing the changes.

Validation: `make manual-check manual` passed all 47 tests, translation checks,
and edition builds with local mdBook 0.5.2 and Pages mdBook 0.5.4. The sidebar
browser suite passed in Catalan, English, and German with both versions, covering
touch and mouse at widths 390, 619, 620, and 1440, inside clicks, toggle behavior,
viewport changes, ARIA and saved state, and the theme picker. The existing image
viewer suite passed with Pages output when run alone; a simultaneous browser run
had hit its resize/fit assertion. No translatable content changed.
