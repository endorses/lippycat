// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

(() => {
  const darkThemes = ["ayu", "navy", "coal"];
  const classList = document.getElementsByTagName("html")[0].classList;
  const isLightTheme = () =>
    !darkThemes.some((theme) => classList.contains(theme));
  const initiallyLight = isLightTheme();

  mermaid.initialize({
    startOnLoad: true,
    theme: initiallyLight ? "default" : "dark",
    // SVG text avoids fixed-size HTML label boxes clipping on mobile browsers.
    htmlLabels: false,
    flowchart: { htmlLabels: false },
    // Keep connecting lines from showing through the SVG label backgrounds.
    themeCSS: ".edgeLabel rect { opacity: 1; }",
  });

  // Reload across light/dark themes so Mermaid picks up the new colors.
  new MutationObserver(() => {
    if (isLightTheme() !== initiallyLight) {
      window.location.reload();
    }
  }).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["class"],
  });
})();
