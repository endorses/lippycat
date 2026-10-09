(() => {
  "use strict";

  const excluded = [
    "a",
    "code, kbd, samp",
    "pre",
    "h1, h2, h3, h4, h5, h6",
    "script",
    "style",
    "nav",
    "form, button, input, select, textarea, label, summary",
    '[role="button"], [role="link"], [contenteditable], [hidden]',
    "svg, math, canvas",
    ".mermaid, .diagram",
    "[data-no-term-hints]",
    "[data-glossary-term]",
    "[data-term]",
    ".term-hint-trigger",
    "#manual-term-hint-popup",
  ].join(", ");
  const wordCharacter = /[\p{L}\p{N}\p{M}_]/u;
  let dictionaryPromise;
  let dictionary;
  let editionRoot;
  let popup;
  let title;
  let definition;
  let glossaryLink;
  let closeButton;
  let activeTrigger;
  let pinned = false;
  let hoveredTrigger;
  let hoveredPopup = false;
  let closeTimer;
  let suppressMouseUntil = 0;
  let restoringFocus = false;
  let triggerNumber = 0;

  function insideInteraction(element) {
    return (
      element && (activeTrigger?.contains(element) || popup?.contains(element))
    );
  }

  function positionPopup() {
    if (!activeTrigger || popup.hidden) return;
    // Fixed coordinates use the visual viewport when mobile zoom has panned it.
    const viewport = window.visualViewport;
    const leftEdge = viewport?.offsetLeft || 0;
    const topEdge = viewport?.offsetTop || 0;
    const width = viewport?.width || document.documentElement.clientWidth;
    const height = viewport?.height || document.documentElement.clientHeight;
    const margin = 12;
    const gap = 8;
    const availableHeight = Math.max(0, height - margin * 2);
    // Browser zoom changes viewport dimensions. Also account for CSS zoom when
    // it is applied by a reader stylesheet: rectangles are scaled but inline
    // position/size properties remain in the popup's unscaled CSS coordinates.
    const cssWidth = Number.parseFloat(window.getComputedStyle(popup).width);
    const scale = cssWidth ? popup.getBoundingClientRect().width / cssWidth : 1;
    popup.style.maxWidth = `${Math.max(0, width - margin * 2) / scale}px`;
    popup.style.maxHeight = `${availableHeight / scale}px`;
    const anchor = activeTrigger.getBoundingClientRect();
    const below = Math.min(
      availableHeight,
      Math.max(0, topEdge + height - margin - anchor.bottom - gap),
    );
    const above = Math.min(
      availableHeight,
      Math.max(0, anchor.top - gap - topEdge - margin),
    );
    const useBelow =
      popup.getBoundingClientRect().height <= below || below >= above;
    // A long definition scrolls on the roomier side of the trigger, keeping the
    // trigger available for the reader's second click/tap to dismiss the popup.
    popup.style.maxHeight = `${(useBelow ? below : above) / scale}px`;
    const box = popup.getBoundingClientRect();
    const left = Math.max(
      leftEdge + margin,
      Math.min(anchor.left, leftEdge + width - box.width - margin),
    );
    let top = useBelow ? anchor.bottom + gap : anchor.top - box.height - gap;
    top = Math.max(
      topEdge + margin,
      Math.min(top, topEdge + height - box.height - margin),
    );
    popup.style.left = `${left / scale}px`;
    popup.style.top = `${top / scale}px`;
  }

  function dismiss(restoreFocus = false) {
    window.clearTimeout(closeTimer);
    if (!activeTrigger) return;
    const trigger = activeTrigger;
    const focusWasInPopup = popup.contains(document.activeElement);
    popup.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    trigger.removeAttribute("aria-describedby");
    activeTrigger = undefined;
    hoveredTrigger = undefined;
    hoveredPopup = false;
    pinned = false;
    if (restoreFocus && focusWasInPopup && trigger.isConnected) {
      restoringFocus = true;
      trigger.focus({ preventScroll: true });
      restoringFocus = false;
    }
  }

  function scheduleDismiss() {
    window.clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => {
      if (
        !pinned &&
        hoveredTrigger !== activeTrigger &&
        !hoveredPopup &&
        !insideInteraction(document.activeElement)
      ) {
        dismiss();
      }
    }, 180);
  }

  function show(trigger, pin = false) {
    window.clearTimeout(closeTimer);
    if (activeTrigger !== trigger) {
      dismiss();
      const term = dictionary.terms.find(
        (item) => item.id === trigger.dataset.termHint,
      );
      title.textContent = term.label;
      definition.textContent = term.definition;
      glossaryLink.href = new URL(term.href, editionRoot).href;
      popup.scrollTop = 0;
      activeTrigger = trigger;
      // Keeping the popup immediately after its trigger preserves natural Tab
      // order for its link and close button, without a modal focus trap.
      trigger.after(popup);
    }
    pinned = pin;
    popup.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    trigger.setAttribute("aria-describedby", definition.id);
    positionPopup();
  }

  function createPopup() {
    popup = document.createElement("span");
    popup.id = "manual-term-hint-popup";
    popup.setAttribute("role", "dialog");
    popup.setAttribute("aria-modal", "false");
    popup.setAttribute("aria-labelledby", "manual-term-hint-title");
    popup.setAttribute("aria-describedby", "manual-term-hint-definition");
    popup.hidden = true;
    title = document.createElement("span");
    title.id = "manual-term-hint-title";
    definition = document.createElement("span");
    definition.id = "manual-term-hint-definition";
    glossaryLink = document.createElement("a");
    glossaryLink.className = "term-hint-glossary";
    glossaryLink.textContent = dictionary.ui.glossary;
    closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "term-hint-close";
    closeButton.textContent = dictionary.ui.close;
    const actions = document.createElement("span");
    actions.className = "term-hint-actions";
    actions.append(glossaryLink, closeButton);
    popup.append(title, definition, actions);
    document.body.append(popup);
    popup.addEventListener("pointerenter", (event) => {
      if (event.pointerType !== "mouse" || Date.now() < suppressMouseUntil)
        return;
      hoveredPopup = true;
      window.clearTimeout(closeTimer);
    });
    popup.addEventListener("pointerleave", () => {
      hoveredPopup = false;
      scheduleDismiss();
    });
    popup.addEventListener("focusin", () => window.clearTimeout(closeTimer));
    popup.addEventListener("focusout", scheduleDismiss);
    popup.addEventListener("keydown", (event) => {
      // mdBook's document-level shortcuts must not navigate away when a reader
      // uses keys in the popup. Default Tab/link/button behavior is retained.
      event.stopPropagation();
      if (event.key === "Escape") {
        event.preventDefault();
        dismiss(true);
      }
    });
    closeButton.addEventListener("click", () => dismiss(true));
    document.addEventListener("pointerdown", (event) => {
      if (event.pointerType === "touch") suppressMouseUntil = Date.now() + 1000;
      if (activeTrigger && !insideInteraction(event.target)) dismiss();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || !activeTrigger) return;
      if (insideInteraction(event.target)) event.stopPropagation();
      dismiss(true);
    });
    window.addEventListener("resize", positionPopup);
    // Capture also observes scrollable chapter containers, not just the window.
    window.addEventListener("scroll", positionPopup, true);
    window.visualViewport?.addEventListener("resize", positionPopup);
    window.visualViewport?.addEventListener("scroll", positionPopup);
  }

  function makeTrigger(term, automatic) {
    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "term-hint-trigger";
    trigger.dataset.termHint = term.id;
    if (automatic) trigger.dataset.termHintAutomatic = "true";
    trigger.id = `manual-term-hint-trigger-${++triggerNumber}`;
    trigger.setAttribute("aria-haspopup", "dialog");
    trigger.setAttribute("aria-controls", popup.id);
    trigger.setAttribute("aria-expanded", "false");
    trigger.addEventListener("pointerenter", (event) => {
      if (event.pointerType !== "mouse" || Date.now() < suppressMouseUntil)
        return;
      if (pinned || popup.contains(document.activeElement)) return;
      show(trigger);
      hoveredTrigger = trigger;
    });
    trigger.addEventListener("pointerleave", () => {
      if (hoveredTrigger === trigger) hoveredTrigger = undefined;
      scheduleDismiss();
    });
    trigger.addEventListener("focus", () => {
      if (restoringFocus || Date.now() < suppressMouseUntil) return;
      if (activeTrigger === trigger && pinned) return;
      show(trigger);
    });
    trigger.addEventListener("blur", scheduleDismiss);
    trigger.addEventListener("click", () => {
      if (activeTrigger === trigger && pinned) dismiss();
      else show(trigger, true);
    });
    trigger.addEventListener("keydown", (event) => {
      if (["Enter", " ", "Escape"].includes(event.key)) event.stopPropagation();
      if (event.key === "Escape") {
        event.preventDefault();
        dismiss(true);
      }
    });
    return trigger;
  }

  function hasBoundaries(text, start, end) {
    const before = Array.from(text.slice(0, start)).at(-1) || "";
    const after = Array.from(text.slice(end))[0] || "";
    if (wordCharacter.test(before) || wordCharacter.test(after)) return false;
    // Exclude identifiers, flags, email addresses and path components. A dot
    // remains allowed as sentence punctuation but not inside a filename/name.
    if (/[-/\\@]/u.test(before) || /[-/\\@]/u.test(after)) return false;
    if (before === ".") {
      const previous = Array.from(text.slice(0, start - 1)).at(-1) || "";
      if (wordCharacter.test(previous)) return false;
    }
    if (after === ".") {
      const next = Array.from(text.slice(end + 1))[0] || "";
      if (wordCharacter.test(next)) return false;
    }
    return true;
  }

  function enhance(main) {
    const terms = new Map(dictionary.terms.map((term) => [term.id, term]));
    for (const marker of main.querySelectorAll("[data-term]")) {
      if (marker.closest(".term-hint-trigger, [data-no-term-hints]")) continue;
      // Explicit annotations still respect structural exclusions such as links,
      // code and headings. The marker itself is not an exclusion here.
      const explicitExclusions = excluded.replace("[data-term], ", "");
      if (
        marker.closest(explicitExclusions) ||
        marker.querySelector(explicitExclusions)
      ) {
        continue;
      }
      const term = terms.get(marker.dataset.term);
      if (!term) {
        console.warn(`Unknown manual glossary term: ${marker.dataset.term}`);
        continue;
      }
      const trigger = makeTrigger(term, false);
      trigger.append(...marker.childNodes);
      marker.replaceWith(trigger);
    }
    const seen = new Set(
      Array.from(main.querySelectorAll("[data-term-hint-automatic]")).map(
        (trigger) => trigger.dataset.termHint,
      ),
    );
    const aliases = dictionary.terms
      .flatMap((term) => term.aliases.map((alias) => ({ alias, term })))
      .sort((a, b) => b.alias.length - a.alias.length);
    if (!aliases.length) return;
    const pattern = new RegExp(
      aliases
        .map(({ alias }) => alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join("|"),
      "giu",
    );
    const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT, {
      acceptNode: (node) =>
        node.parentElement.closest(excluded)
          ? NodeFilter.FILTER_REJECT
          : NodeFilter.FILTER_ACCEPT,
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const node of nodes) {
      const text = node.nodeValue;
      pattern.lastIndex = 0;
      let match;
      let offset = 0;
      let fragment;
      while ((match = pattern.exec(text))) {
        const found = aliases.find(({ alias, term }) =>
          term.caseSensitive
            ? alias === match[0]
            : alias.toLowerCase() === match[0].toLowerCase(),
        );
        if (
          !found ||
          seen.has(found.term.id) ||
          !hasBoundaries(text, match.index, pattern.lastIndex)
        ) {
          continue;
        }
        fragment ||= document.createDocumentFragment();
        fragment.append(text.slice(offset, match.index));
        const trigger = makeTrigger(found.term, true);
        trigger.textContent = match[0];
        fragment.append(trigger);
        offset = pattern.lastIndex;
        seen.add(found.term.id);
      }
      if (fragment) {
        fragment.append(text.slice(offset));
        node.replaceWith(fragment);
      }
    }
  }

  async function initialize() {
    try {
      editionRoot ||= new URL(
        typeof path_to_root === "string" ? path_to_root || "./" : "./",
        window.location.href,
      );
      const chapter = window.location.pathname.slice(
        editionRoot.pathname.length,
      );
      if (chapter === "print.html" || chapter === "appendices/glossary.html") {
        return;
      }
      const main = document.querySelector("main");
      if (!main) return;
      dictionaryPromise ||= (async () => {
        const response = await fetch(new URL("term-hints.json", editionRoot));
        if (!response.ok)
          throw new Error(`Term hints: HTTP ${response.status}`);
        const data = await response.json();
        if (
          data.language !== document.documentElement.lang ||
          !Array.isArray(data.terms) ||
          typeof data.ui?.glossary !== "string" ||
          !data.ui.glossary ||
          typeof data.ui?.close !== "string" ||
          !data.ui.close ||
          !data.terms.every(
            (term) =>
              typeof term.id === "string" &&
              term.id &&
              typeof term.label === "string" &&
              term.label &&
              typeof term.definition === "string" &&
              term.definition &&
              typeof term.href === "string" &&
              term.href.startsWith("appendices/glossary.html#term-") &&
              typeof term.caseSensitive === "boolean" &&
              Array.isArray(term.aliases) &&
              term.aliases.every(
                (alias) => typeof alias === "string" && alias.length > 0,
              ),
          )
        ) {
          throw new Error("Term hints: invalid dictionary or edition language");
        }
        return data;
      })();
      dictionary = await dictionaryPromise;
      if (!popup) createPopup();
      enhance(main);
    } catch (error) {
      // Fetch/JSON errors occur before any prose is changed.
      console.error("Could not load manual term hints", error);
    }
  }

  window.ManualTermHints = { initialize };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
