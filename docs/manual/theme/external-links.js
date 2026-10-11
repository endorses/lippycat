(() => {
  "use strict";
  let languagePromise;
  let observer;

  function enhance(link, language) {
    const url = new URL(link.getAttribute("href"), window.location.href);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.origin === window.location.origin ||
      link.dataset.manualExternalLink
    ) {
      return;
    }
    link.setAttribute("target", "_blank");
    const relations = new Set(
      (link.getAttribute("rel") || "").split(/\s+/).filter(Boolean),
    );
    relations.add("noopener");
    relations.add("noreferrer");
    link.setAttribute("rel", [...relations].join(" "));

    // SVG/image-only links already have an icon; inspect only their HTML text.
    const copy = link.cloneNode(true);
    copy
      .querySelectorAll('svg, img, [aria-hidden="true"]')
      .forEach((node) => node.remove());
    const text = link.closest("svg") ? "" : copy.textContent.trim();
    const label =
      link.getAttribute("aria-label") ||
      text ||
      link.getAttribute("title") ||
      link.querySelector("img[alt]")?.getAttribute("alt");
    if (label) {
      link.setAttribute(
        "aria-label",
        `${language.ui?.[label] || label} (${language.externalLinkLabel})`,
      );
    }
    if (text) {
      const icon = document.createElement("span");
      icon.className = "manual-external-link-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = "\u00a0↗";
      link.append(icon);
    }
    link.dataset.manualExternalLink = "true";
  }

  async function initialize() {
    languagePromise ||= (async () => {
      try {
        const root = new URL(path_to_root || "./", window.location.href);
        const response = await fetch(new URL("languages.json", root));
        if (!response.ok)
          throw new Error(`Language manifest: HTTP ${response.status}`);
        const languages = await response.json();
        const current = languages.find(
          (language) => language.code === document.documentElement.lang,
        );
        if (!current?.externalLinkLabel)
          throw new Error("Missing external link label");
        return current;
      } catch (error) {
        console.error("Could not load external link translation", error);
        return { externalLinkLabel: "opens in a new tab" };
      }
    })();
    const language = await languagePromise;
    document
      .querySelectorAll("a[href]")
      .forEach((link) => enhance(link, language));
    if (observer) return;
    observer = new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches("a[href]")) enhance(node, language);
          node
            .querySelectorAll("a[href]")
            .forEach((link) => enhance(link, language));
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  window.ManualExternalLinks = { initialize };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
