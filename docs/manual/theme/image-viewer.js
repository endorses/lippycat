(() => {
  "use strict";

  const defaults = {
    open: "Open image fullscreen",
    title: "Image viewer",
    close: "Close",
    zoomIn: "Zoom in",
    zoomOut: "Zoom out",
    reset: "Fit to screen",
  };
  const enhanced = new WeakSet();
  const descriptions = new WeakMap();
  let languagePromise;
  let observer;
  let viewer;
  let labels = defaults;
  let opener;
  let objectURL;
  let previousOverflow;
  let dimensions;
  let zoom = 1;

  function button(label, symbol, action) {
    const element = document.createElement("button");
    element.type = "button";
    element.title = label;
    element.setAttribute("aria-label", label);
    element.textContent = symbol;
    element.addEventListener("click", action);
    return element;
  }

  function createViewer() {
    const dialog = document.createElement("dialog");
    dialog.className = "manual-image-viewer";
    dialog.id = "manual-image-viewer";
    const toolbar = document.createElement("div");
    toolbar.className = "manual-image-viewer-toolbar";
    const title = document.createElement("h2");
    title.id = "manual-image-viewer-title";
    dialog.setAttribute("aria-labelledby", title.id);
    const controls = document.createElement("div");
    controls.className = "manual-image-viewer-controls";
    const zoomOut = button(labels.zoomOut, "−", () => setZoom(zoom / 1.5));
    const zoomIn = button(labels.zoomIn, "+", () => setZoom(zoom * 1.5));
    const reset = button(labels.reset, "↺", () => setZoom(1));
    const close = button(labels.close, "×", () => dialog.close());
    for (const [action, control] of Object.entries({
      zoomOut,
      zoomIn,
      reset,
      close,
    })) {
      control.dataset.imageViewerAction = action;
    }
    controls.append(zoomOut, zoomIn, reset, close);
    toolbar.append(title, controls);
    const viewport = document.createElement("div");
    viewport.className = "manual-image-viewer-viewport";
    viewport.tabIndex = 0;
    viewport.setAttribute("role", "region");
    const canvas = document.createElement("div");
    canvas.className = "manual-image-viewer-canvas";
    const image = document.createElement("img");
    image.draggable = false;
    canvas.append(image);
    viewport.append(canvas);
    dialog.append(toolbar, viewport);
    document.body.append(dialog);
    dialog.addEventListener("click", (event) => {
      if ([dialog, viewport, canvas].includes(event.target)) dialog.close();
    });
    dialog.addEventListener("keydown", (event) => {
      event.stopPropagation();
      if (event.key === "Escape") {
        event.preventDefault();
        dialog.close();
        return;
      }
      if (event.key === "Tab") {
        event.preventDefault();
        const focusable = [
          ...controls.querySelectorAll("button:not(:disabled)"),
          viewport,
        ];
        const activeIndex = focusable.indexOf(document.activeElement);
        const index = activeIndex < 0 && event.shiftKey ? 0 : activeIndex;
        const next = event.shiftKey
          ? (index - 1 + focusable.length) % focusable.length
          : (index + 1) % focusable.length;
        focusable[next].focus();
        return;
      }
      if (["+", "=", "-", "0"].includes(event.key)) {
        event.preventDefault();
        if (event.key === "0") setZoom(1);
        else setZoom(event.key === "-" ? zoom / 1.5 : zoom * 1.5);
      }
    });
    for (const eventName of ["touchstart", "touchmove"]) {
      dialog.addEventListener(eventName, (event) => event.stopPropagation(), {
        passive: true,
      });
    }
    dialog.addEventListener("close", () => {
      document.body.style.overflow = previousOverflow;
      image.removeAttribute("src");
      dimensions = undefined;
      if (objectURL) URL.revokeObjectURL(objectURL);
      objectURL = undefined;
      if (opener?.isConnected) opener.focus({ preventScroll: true });
    });
    window.addEventListener("resize", () => {
      if (dialog.open && dimensions) setZoom(zoom);
    });
    return { dialog, title, viewport, canvas, image, zoomIn, zoomOut, close };
  }

  function setZoom(value) {
    if (!dimensions) return;
    zoom = Math.max(0.25, Math.min(8, value));
    const { viewport, canvas, image } = viewer;
    const centerX =
      (viewport.scrollLeft + viewport.clientWidth / 2) /
      (canvas.offsetWidth || 1);
    const centerY =
      (viewport.scrollTop + viewport.clientHeight / 2) /
      (canvas.offsetHeight || 1);
    const fit = Math.min(
      Math.max(1, viewport.clientWidth - 32) / dimensions.width,
      Math.max(1, viewport.clientHeight - 32) / dimensions.height,
    );
    const width = dimensions.width * fit * zoom;
    const height = dimensions.height * fit * zoom;
    image.style.width = `${width}px`;
    image.style.height = `${height}px`;
    canvas.style.width = `${Math.max(viewport.clientWidth, width + 32)}px`;
    canvas.style.height = `${Math.max(viewport.clientHeight, height + 32)}px`;
    viewport.scrollLeft =
      canvas.offsetWidth * centerX - viewport.clientWidth / 2;
    viewport.scrollTop =
      canvas.offsetHeight * centerY - viewport.clientHeight / 2;
    viewer.zoomOut.disabled = zoom <= 0.25;
    viewer.zoomIn.disabled = zoom >= 8;
  }

  function description(source) {
    if (descriptions.has(source)) return descriptions.get(source);
    return (
      source
        .closest("figure")
        ?.querySelector("figcaption")
        ?.textContent.trim() ||
      source.getAttribute("alt") ||
      source.getAttribute("aria-label") ||
      source.querySelector("title")?.textContent.trim() ||
      labels.title
    );
  }

  function open(source, trigger) {
    viewer ||= createViewer();
    if (viewer.dialog.open) return;
    const title = description(source);
    opener = trigger;
    previousOverflow = document.body.style.overflow;
    viewer.title.textContent = title;
    viewer.viewport.setAttribute("aria-label", title);
    viewer.image.alt = title;
    viewer.image.onload = () => {
      dimensions = {
        width: viewer.image.naturalWidth,
        height: viewer.image.naturalHeight,
      };
      setZoom(1);
    };
    viewer.image.onerror = () => {
      console.error("Could not load fullscreen image", source);
      viewer.dialog.close();
    };
    let url;
    if (source instanceof SVGElement) {
      const clone = source.cloneNode(true);
      const bounds = source.viewBox.baseVal;
      const size = source.getBoundingClientRect();
      clone.setAttribute("width", bounds.width || size.width);
      clone.setAttribute("height", bounds.height || size.height);
      clone.style.maxWidth = "none";
      clone.classList.remove("manual-image-viewer-trigger");
      clone.removeAttribute("role");
      clone.removeAttribute("tabindex");
      clone.removeAttribute("aria-label");
      clone.removeAttribute("data-image-viewer");
      objectURL = URL.createObjectURL(
        new Blob([new XMLSerializer().serializeToString(clone)], {
          type: "image/svg+xml",
        }),
      );
      url = objectURL;
    } else {
      url = source.currentSrc || source.src;
    }
    zoom = 1;
    viewer.canvas.style.width = "100%";
    viewer.canvas.style.height = "100%";
    viewer.viewport.scrollTo(0, 0);
    document.body.style.overflow = "hidden";
    viewer.dialog.showModal();
    viewer.close.focus();
    viewer.image.src = url;
  }

  function enhance(source) {
    if (enhanced.has(source)) return;
    enhanced.add(source);
    descriptions.set(source, description(source));
    source.dataset.imageViewer = "true";
    const label = `${labels.open}: ${description(source)}`;
    if (source.closest("a")) {
      const trigger = button(label, "⛶", () => open(source, trigger));
      trigger.classList.add("manual-image-viewer-open");
      trigger.setAttribute("aria-haspopup", "dialog");
      source.closest("a").after(trigger);
      return;
    }
    source.classList.add("manual-image-viewer-trigger");
    source.setAttribute("role", "button");
    source.setAttribute("tabindex", "0");
    source.setAttribute("aria-haspopup", "dialog");
    source.setAttribute("aria-label", label);
    source.addEventListener("click", () => open(source, source));
    source.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open(source, source);
      }
    });
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
        if (!current?.imageViewer)
          throw new Error("Missing image viewer translations");
        return { ...defaults, ...current.imageViewer };
      } catch (error) {
        console.error("Could not load image viewer translations", error);
        return defaults;
      }
    })();
    labels = await languagePromise;
    const main = document.querySelector(".content main");
    if (!main) return;
    const selector = "img, .mermaid svg";
    main.querySelectorAll(selector).forEach(enhance);
    if (observer) return;
    observer = new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches(selector)) enhance(node);
          node.querySelectorAll(selector).forEach(enhance);
        }
      }
    });
    observer.observe(main, { childList: true, subtree: true });
  }

  window.ManualImageViewer = { initialize };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
