(() => {
  "use strict";

  function initialize() {
    const sidebar = document.getElementById("mdbook-sidebar");
    const toggle = document.getElementById("mdbook-sidebar-toggle");
    const checkbox = document.getElementById("mdbook-sidebar-toggle-anchor");
    if (!sidebar || !toggle || !checkbox) return;

    // Match mdBook's breakpoint between the sliding and docked sidebar layouts.
    const desktop = window.matchMedia("(min-width: 620px)");
    document.addEventListener("click", (event) => {
      if (
        desktop.matches ||
        !checkbox.checked ||
        sidebar.contains(event.target) ||
        toggle.contains(event.target) ||
        event.target === checkbox
      ) {
        return;
      }

      // Let mdBook update visibility, ARIA, and saved state without sending a
      // second click that could dismiss the outside control's own popup.
      checkbox.checked = false;
      checkbox.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
