(async () => {
  const editionRoot = new URL(path_to_root || "./", window.location.href);
  const response = await fetch(new URL("languages.json", editionRoot));
  if (!response.ok)
    throw new Error(`Language manifest: HTTP ${response.status}`);
  const languages = await response.json();
  const current = languages.find(
    (language) => language.code === document.documentElement.lang,
  );
  if (!current) throw new Error("Current manual language is not configured");
  for (const element of document.querySelectorAll(
    "[title], [aria-label], [placeholder]",
  )) {
    for (const attribute of ["title", "aria-label", "placeholder"]) {
      const translation = current.ui?.[element.getAttribute(attribute)];
      if (translation) element.setAttribute(attribute, translation);
    }
  }
  const siteRoot = new URL(current.path ? "../" : "./", editionRoot);
  const chapter = window.location.pathname.slice(editionRoot.pathname.length);
  const select = document.createElement("select");
  select.id = "manual-language";
  select.setAttribute("aria-label", current.selectorLabel || "Select language");
  select.title = select.getAttribute("aria-label");
  for (const language of languages) {
    const option = document.createElement("option");
    option.value = language.code;
    option.textContent = language.name;
    option.lang = language.code;
    option.selected = language.code === current.code;
    select.append(option);
  }
  select.addEventListener("change", () => {
    const language = languages.find((item) => item.code === select.value);
    const destination = new URL(language.path + chapter, siteRoot);
    destination.search = window.location.search;
    destination.hash = window.location.hash;
    window.location.assign(destination.href);
  });
  document.querySelector("#mdbook-menu-bar .right-buttons").prepend(select);
})().catch((error) =>
  console.error("Could not load the manual language selector", error),
);
