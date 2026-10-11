# Expandable manual images and unbroken figure labels

Keep localized figure labels together with their numbers in chapter references,
captions, and the appendix. Let readers open manual images and Mermaid diagrams
in a fullscreen viewer to inspect small details.

- [x] Generate nonbreaking figure labels in every edition and print output.
- [x] Add an accessible fullscreen viewer with click, tap, keyboard activation,
      zoom controls, scrolling, Escape/close, and restored focus.
- [x] Localize viewer controls in English, German, and Catalan and document the behavior.
- [x] Verify narrow figure references, images, diagrams, themes, mobile, keyboard,
      and print behavior in the browser.
- [x] Format changes and run manual checks and all edition builds.

Commit the implementation and completed plan after validation.

Validation passed: 44 Python checks, complete German/Catalan translations
(5,722 current messages each), every manual edition, 15 glossary browser checks,
and the image viewer suite across all three languages and all five themes.
Browser checks cover SVG and GIF viewing, zoom and keyboard scrolling, focus
containment/restoration, mobile taps, print visibility, and nonbreaking references.

## Fit-to-screen follow-up

- [x] Allow diagrams and images to scale above their original dimensions while
      preserving aspect ratio and fitting within the viewer.
- [x] Verify the command overview and multi-processor examples fill the available
      width or height, including after resizing and resetting zoom.
- [x] Format changes and run the manual checks and builds.

Both reported examples fill one viewport dimension at 2048×1152 without cropping;
zoom reset and mobile resize checks pass in all three editions. Manual checks,
all edition builds, and the viewer browser suite pass.
