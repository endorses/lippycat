#!/usr/bin/env node
// Build the manual first, then run:
// PLAYWRIGHT_MODULE=/path/to/node_modules/playwright node docs/manual/tools/test_term_hints_browser.cjs
// Optional CHROMIUM_EXECUTABLE, TERM_HINT_SCREENSHOTS. No npm install is required.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

const manual = path.resolve(__dirname, "..");
const book = path.join(manual, "book");
const screenshots = process.env.TERM_HINT_SCREENSHOTS;
const languages = JSON.parse(
  fs.readFileSync(path.join(manual, "languages.json")),
);
const trigger = ".term-hint-trigger";
const popup = "#manual-term-hint-popup";
const fixtureText = `<h1>PCAP heading</h1>
<p id="boundaries">PCAPish éPCAP PCAPé PCAP\u0301 \u0301PCAP x_PCAP PCAP_x /PCAP/file PCAP/file --PCAP PCAP-flag pcap PCAPs é PCAP, PCAP.</p>
<p id="longest">Packet Capture and Packet. TLS TLS.</p>
<p id="explicit"><span data-term="processor">localized processor</span> <span data-term="processor">another processor</span></p>
<p id="excluded"><a href="#">PCAP</a> <code>PCAP</code> <span data-no-term-hints>PCAP <span data-term="processor">processor</span></span></p>
<pre>PCAP TLS</pre><div class="mermaid">PCAP TLS</div><script type="text/plain">PCAP</script><style>/* PCAP */</style>
<button id="outside">Outside</button><p id="new-content"></p><div aria-hidden="true" style="height:2000px"></div>`;

function fixture(url) {
  const lang = url.pathname.split("/")[2] || "en";
  const base = `<!doctype html><html lang="${lang}" class="js light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`;
  const variables = fs
    .readdirSync(path.join(book, "css"))
    .find((name) => name.startsWith("variables-"));
  const depth = url.pathname.split("/").slice(3, -1).length;
  const root = "../".repeat(depth) || "./";
  return `${base}<link rel="stylesheet" href="/book/css/${variables}"><link rel="stylesheet" href="/theme/term-hints.css"><style>body{margin:24px;background:var(--bg);color:var(--fg);font:18px/1.6 sans-serif}main{max-width:700px}button,a{font:inherit}p{margin:1em 0}#longest{margin-top:220px}</style></head><body><nav>PCAP</nav><main>${fixtureText}</main><script>var path_to_root=${JSON.stringify(root)};</script><script src="/theme/term-hints.js"></script></body></html>`;
}

const dictionary = {
  language: "en",
  ui: { glossary: "Read glossary", close: "Close definition" },
  terms: [
    {
      id: "pcap",
      label: "PCAP",
      definition: "Packet Capture, a capture file format.",
      aliases: ["PCAP"],
      caseSensitive: true,
      href: "appendices/glossary.html#term-pcap",
    },
    {
      id: "tls",
      label: "TLS",
      definition: "Transport Layer Security.",
      aliases: ["TLS"],
      caseSensitive: true,
      href: "appendices/glossary.html#term-tls",
    },
    {
      id: "capture",
      label: "Packet Capture",
      definition: "Long alias definition.",
      aliases: ["Packet Capture"],
      caseSensitive: true,
      href: "appendices/glossary.html#term-capture",
    },
    {
      id: "packet",
      label: "Packet",
      definition: "Short alias definition.",
      aliases: ["Packet"],
      caseSensitive: true,
      href: "appendices/glossary.html#term-packet",
    },
    {
      id: "processor",
      label: "Processor",
      definition: "A long localized processor definition. ".repeat(100),
      aliases: [],
      caseSensitive: false,
      href: "appendices/glossary.html#term-processor",
    },
  ],
};

let dictionaryRequests = 0;
const server = http.createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  let filename;
  if (url.pathname.startsWith("/fixture/") && url.pathname.endsWith(".html")) {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(fixture(url));
    return;
  }
  if (
    url.pathname.startsWith("/fixture/") &&
    url.pathname.endsWith("/term-hints.json")
  ) {
    response.setHeader("Content-Type", "application/json");
    dictionaryRequests += 1;
    response.end(JSON.stringify(dictionary));
    return;
  }
  if (url.pathname.startsWith("/theme/"))
    filename = path.join(manual, url.pathname);
  else if (url.pathname.startsWith("/book/"))
    filename = path.join(book, decodeURIComponent(url.pathname.slice(6)));
  if (
    !filename ||
    !fs.existsSync(filename) ||
    !fs.statSync(filename).isFile()
  ) {
    response.writeHead(404).end("Not found");
    return;
  }
  response.setHeader(
    "Content-Type",
    {
      ".js": "text/javascript",
      ".css": "text/css",
      ".html": "text/html",
      ".json": "application/json",
    }[path.extname(filename)] || "application/octet-stream",
  );
  fs.createReadStream(filename).pipe(response);
});

async function main() {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_EXECUTABLE || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox"],
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  let passed = 0;
  async function test(name, fn) {
    await fn();
    passed += 1;
    console.log(`ok ${passed} - ${name}`);
  }
  async function loadFixture(target = "nested/chapter.html") {
    await page.goto(`${origin}/fixture/en/${target}`);
    await page.waitForFunction(() => window.ManualTermHints);
    await page.evaluate(() => window.ManualTermHints.initialize());
  }
  const term = (id) =>
    page.locator(`${trigger}[data-term-hint="${id}"]`).first();
  const visible = () => page.locator(popup).isVisible();
  const waitClosed = () =>
    page.waitForFunction(
      () =>
        !document.querySelector("#manual-term-hint-popup") ||
        document.querySelector("#manual-term-hint-popup").hidden,
    );
  const waitOpen = () => page.locator(popup).waitFor({ state: "visible" });
  try {
    await test("Unicode, identifier, flag and path boundaries; first occurrence; longest aliases", async () => {
      await loadFixture();
      assert.deepEqual(
        await page.locator("#boundaries " + trigger).allTextContents(),
        ["PCAP"],
      );
      assert.deepEqual(
        await page.locator("#longest " + trigger).allTextContents(),
        ["Packet Capture", "Packet", "TLS"],
      );
      assert.equal(
        await page.locator(`${trigger}[data-term-hint="processor"]`).count(),
        2,
      );
      assert.equal(await page.locator("#excluded " + trigger).count(), 0);
      assert.equal(
        await page
          .locator(
            "h1 button, pre button, code button, a button, .mermaid button, nav button",
          )
          .count(),
        0,
      );
    });
    await test("repeated initialization preserves text and does not duplicate triggers", async () => {
      const text = await page.locator("main").innerText();
      const count = await page.locator(trigger).count();
      const requests = dictionaryRequests;
      await page.evaluate(async () => {
        await window.ManualTermHints.initialize();
        await window.ManualTermHints.initialize();
      });
      assert.equal(await page.locator(trigger).count(), count);
      assert.equal(dictionaryRequests, requests);
      assert.equal(await page.locator(`${trigger} ${trigger}`).count(), 0);
      assert.equal(await page.locator("main").innerText(), text);
    });
    await test("hover preview remains open while entering popup and closes on leaving", async () => {
      await term("pcap").hover();
      await waitOpen();
      assert.equal(await term("pcap").getAttribute("aria-expanded"), "true");
      await page.locator(popup).hover();
      await page.waitForTimeout(400);
      assert.equal(await visible(), true);
      await page.locator("#outside").hover();
      await waitClosed();
    });
    await test("pin, repeated activation, outside dismissal, switch and Escape", async () => {
      await term("pcap").click();
      await waitOpen();
      await page.locator("#outside").hover();
      assert.equal(await visible(), true);
      await term("pcap").click();
      await waitClosed();
      await term("pcap").click();
      await waitOpen();
      await term("tls").click();
      assert.equal(
        await page.locator("#manual-term-hint-title").innerText(),
        "TLS",
      );
      assert.equal(await term("pcap").getAttribute("aria-expanded"), "false");
      await page.locator("#outside").click();
      await waitClosed();
      await term("tls").click();
      await waitOpen();
      await page.keyboard.press("Escape");
      await waitClosed();
    });
    await test("keyboard preview, ARIA relationships, controls, restored focus and no focus trap", async () => {
      await term("pcap").focus();
      await waitOpen();
      assert.equal(
        await term("pcap").getAttribute("aria-describedby"),
        "manual-term-hint-definition",
      );
      assert.equal(await term("pcap").getAttribute("aria-haspopup"), "dialog");
      assert.equal(
        await term("pcap").getAttribute("aria-controls"),
        "manual-term-hint-popup",
      );
      assert.equal(await page.locator(popup).getAttribute("role"), "dialog");
      assert.equal(
        await page.locator(popup).getAttribute("aria-labelledby"),
        "manual-term-hint-title",
      );
      assert.equal(
        await page.locator(popup).getAttribute("aria-describedby"),
        "manual-term-hint-definition",
      );
      await page.locator("#outside").focus();
      await waitClosed();
      await term("pcap").focus();
      await waitOpen();
      await page.keyboard.press("Enter");
      await page.keyboard.press("Tab");
      assert.equal(
        await page
          .locator(".term-hint-glossary")
          .evaluate((el) => el === document.activeElement),
        true,
      );
      await term("tls").hover();
      assert.equal(
        await page.locator("#manual-term-hint-title").innerText(),
        "PCAP",
      );
      await page.keyboard.press("Tab");
      assert.equal(
        await page
          .locator(".term-hint-close")
          .evaluate((el) => el === document.activeElement),
        true,
      );
      await page.keyboard.press("Escape");
      await waitClosed();
      assert.equal(
        await term("pcap").evaluate((el) => el === document.activeElement),
        true,
      );
      await page.keyboard.press("Space");
      await waitOpen();
      await page.locator(".term-hint-close").click();
      await waitClosed();
      await page.keyboard.press("Tab");
      assert.equal(
        await term("pcap").evaluate((el) => el === document.activeElement),
        false,
      );
      await page.locator("#outside").focus();
      await waitClosed();
      await term("pcap").focus();
      await page.keyboard.press("Tab");
      await term("tls").hover();
      assert.equal(
        await page.locator("#manual-term-hint-title").innerText(),
        "PCAP",
      );
      assert.equal(
        await page
          .locator(".term-hint-glossary")
          .evaluate((el) => el === document.activeElement),
        true,
      );
      await page.keyboard.press("Escape");
      await waitClosed();
    });
    await test("glossary destination resolves against edition root from nested chapters", async () => {
      await term("pcap").click();
      await waitOpen();
      assert.equal(
        await page.locator(".term-hint-glossary").getAttribute("href"),
        `${origin}/fixture/en/appendices/glossary.html#term-pcap`,
      );
      await page.keyboard.press("Escape");
    });
    await test("touch tap toggles; synthetic mouse hover does not reopen dismissal", async () => {
      const touchContext = await browser.newContext({
        hasTouch: true,
        viewport: { width: 390, height: 844 },
      });
      try {
        const mobile = await touchContext.newPage();
        await mobile.goto(`${origin}/fixture/en/nested/chapter.html`);
        const button = mobile
          .locator(`${trigger}[data-term-hint="pcap"]`)
          .first();
        await button.tap();
        await mobile.locator(popup).waitFor({ state: "visible" });
        await button.tap();
        await mobile.locator(popup).waitFor({ state: "hidden" });
        await button.dispatchEvent("pointerenter", { pointerType: "mouse" });
        await button.dispatchEvent("mouseenter");
        await mobile.waitForTimeout(100);
        assert.equal(await mobile.locator(popup).isVisible(), false);
        await button.tap();
        await mobile.locator(popup).waitFor({ state: "visible" });
        await mobile.locator("#outside").tap();
        await mobile.locator(popup).waitFor({ state: "hidden" });
      } finally {
        await touchContext.close();
      }
    });
    await test("narrow viewport, long definition, resizing, scrolling, zoom and all themes", async () => {
      await page.setViewportSize({ width: 320, height: 480 });
      await term("processor").click();
      await waitOpen();
      const backgrounds = [];
      for (const theme of ["light", "rust", "coal", "navy", "ayu"]) {
        await page.evaluate((value) => {
          document.documentElement.className = `js ${value}`;
        }, theme);
        const result = await page.locator(popup).evaluate((el) => {
          const rect = el.getBoundingClientRect();
          const css = getComputedStyle(el);
          return {
            left: rect.left,
            right: rect.right,
            top: rect.top,
            bottom: rect.bottom,
            width: window.innerWidth,
            height: window.innerHeight,
            fg: css.color,
            bg: css.backgroundColor,
            scrollHeight: el.scrollHeight,
            clientHeight: el.clientHeight,
          };
        });
        assert.ok(
          result.left >= 0 &&
            result.right <= result.width + 1 &&
            result.top >= 0 &&
            result.bottom <= result.height + 1,
          JSON.stringify(result),
        );
        assert.notEqual(result.fg, result.bg);
        backgrounds.push(result.bg);
        assert.ok(result.scrollHeight >= result.clientHeight);
        if (screenshots) {
          fs.mkdirSync(screenshots, { recursive: true });
          await page.screenshot({
            path: path.join(screenshots, `fixture-mobile-${theme}.png`),
          });
        }
      }
      assert.equal(new Set(backgrounds).size, 5);
      await page.evaluate(() => {
        document.documentElement.style.fontSize = "200%";
      });
      await page.setViewportSize({ width: 640, height: 600 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.evaluate(() => window.dispatchEvent(new Event("scroll")));
      await page.waitForTimeout(100);
      const rect = await page.locator(popup).boundingBox();
      assert.ok(
        rect.x >= 0 &&
          rect.x + rect.width <= 641 &&
          rect.y >= 0 &&
          rect.y + rect.height <= 601,
        JSON.stringify(rect),
      );
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await page.waitForTimeout(100);
      const scrolled = await page.locator(popup).boundingBox();
      assert.ok(
        scrolled.x >= 0 &&
          scrolled.x + scrolled.width <= 641 &&
          scrolled.y >= 0 &&
          scrolled.y + scrolled.height <= 601,
        JSON.stringify(scrolled),
      );
      const cdp = await context.newCDPSession(page);
      await cdp.send("Emulation.setPageScaleFactor", { pageScaleFactor: 2 });
      await page.waitForTimeout(100);
      const pinched = await page.locator(popup).evaluate((el) => {
        const box = el.getBoundingClientRect();
        const viewport = window.visualViewport;
        return {
          left: box.left,
          right: box.right,
          top: box.top,
          bottom: box.bottom,
          minLeft: viewport.offsetLeft,
          maxRight: viewport.offsetLeft + viewport.width,
          minTop: viewport.offsetTop,
          maxBottom: viewport.offsetTop + viewport.height,
        };
      });
      assert.ok(
        pinched.left >= pinched.minLeft &&
          pinched.right <= pinched.maxRight + 1 &&
          pinched.top >= pinched.minTop &&
          pinched.bottom <= pinched.maxBottom + 1,
        JSON.stringify(pinched),
      );
      await cdp.send("Emulation.setPageScaleFactor", { pageScaleFactor: 1 });
      await cdp.detach();
      await page.emulateMedia({ media: "print" });
      assert.equal(await page.locator(popup).isVisible(), false);
      await page.emulateMedia({ media: "screen" });
      await page.setViewportSize({ width: 1280, height: 800 });
    });
    await test("print and glossary pages are not enhanced", async () => {
      for (const target of ["print.html", "appendices/glossary.html"]) {
        await loadFixture(target);
        assert.equal(await page.locator(trigger).count(), 0);
      }
    });
    await test("failed dictionary and no JavaScript preserve chapter and full glossary text", async () => {
      const errors = [];
      const listener = (message) => {
        if (message.type() === "error") errors.push(message.text());
      };
      page.on("console", listener);
      await page.route("**/term-hints.json", (route) =>
        route.fulfill({ status: 503, body: "unavailable" }),
      );
      await page.goto(`${origin}/fixture/en/nested/chapter.html`);
      await page.waitForFunction(() => window.ManualTermHints);
      await page.waitForTimeout(100);
      assert.equal(await page.locator(trigger).count(), 0);
      assert.ok(
        (await page.locator("main").innerText()).includes(
          "localized processor",
        ),
      );
      assert.ok(errors.some((value) => /term|hint|dictionary/i.test(value)));
      await page.unroute("**/term-hints.json");
      page.off("console", listener);
      const disabled = await browser.newContext({ javaScriptEnabled: false });
      try {
        const plain = await disabled.newPage();
        await plain.goto(`${origin}/fixture/en/nested/chapter.html`);
        assert.equal(await plain.locator(trigger).count(), 0);
        assert.ok((await plain.locator("main").innerText()).includes("PCAP"));
        await plain.goto(`${origin}/book/en/appendices/glossary.html`);
        assert.ok(
          (await plain.locator("main").innerText()).includes(
            "Berkeley Packet Filter",
          ),
        );
      } finally {
        await disabled.close();
      }
    });
    await test("built editions have localized definitions/controls, valid fragments, clean search and print", async () => {
      for (const language of languages) {
        const base = `${origin}/book/${language.path}`;
        const data = JSON.parse(
          fs.readFileSync(path.join(book, language.path, "term-hints.json")),
        );
        await page.goto(`${base}part1-foundations/core-concepts.html`);
        await page.locator(trigger).first().waitFor();
        assert.equal(
          await page.locator(`${trigger}[data-term-hint="processor"]`).count(),
          1,
        );
        assert.equal(
          await page.locator(`${trigger}[data-term-hint="tap"]`).count(),
          1,
        );
        const sourceHtml = fs.readFileSync(
          path.join(
            book,
            language.path,
            "part1-foundations/core-concepts.html",
          ),
          "utf8",
        );
        const originalLabels = await page.evaluate((html) => {
          const original = new DOMParser().parseFromString(html, "text/html");
          return ["processor", "tap"].map(
            (id) => original.querySelector(`[data-term="${id}"]`).textContent,
          );
        }, sourceHtml);
        assert.equal(await term("processor").textContent(), originalLabels[0]);
        assert.equal(await term("tap").textContent(), originalLabels[1]);
        await term("bpf").click();
        await waitOpen();
        const bpf = data.terms.find((entry) => entry.id === "bpf");
        assert.equal(
          await page.locator("#manual-term-hint-definition").innerText(),
          bpf.definition,
        );
        assert.equal(
          await page.locator(".term-hint-glossary").innerText(),
          data.ui.glossary,
        );
        assert.equal(
          await page.locator(".term-hint-close").innerText(),
          data.ui.close,
        );
        const href = await page
          .locator(".term-hint-glossary")
          .getAttribute("href");
        assert.equal(href, new URL(bpf.href, base).href);
        if (screenshots)
          await page.screenshot({
            path: path.join(screenshots, `edition-${language.code}.png`),
          });
        await page.locator(".term-hint-glossary").click();
        await page.locator("#term-bpf").waitFor();
        assert.equal(await page.locator(trigger).count(), 0);
        await page.goto(`${base}print.html`);
        assert.equal(await page.locator(trigger).count(), 0);
        const ids = await page
          .locator("[data-glossary-term]")
          .evaluateAll((elements) => elements.map((el) => el.id));
        assert.equal(ids.length, new Set(ids).size);
        assert.equal(ids.length, data.terms.length);
        const searchFile = fs
          .readdirSync(path.join(book, language.path))
          .find((name) => /^searchindex.*\.js$/.test(name));
        assert.ok(searchFile, "mdBook search index exists");
        assert.ok(
          !fs
            .readFileSync(path.join(book, language.path, searchFile), "utf8")
            .includes("manual-term-hint-popup"),
        );
        await page.goto(`${base}part1-foundations/core-concepts.html`);
        await page.locator("#manual-language").waitFor();
        const next = languages.find((item) => item.code !== language.code);
        await page.locator("#manual-language").selectOption(next.code);
        await page.waitForURL(
          `${origin}/book/${next.path}part1-foundations/core-concepts.html`,
        );
        assert.equal(
          await page.locator("html").getAttribute("lang"),
          next.code,
        );
        await page.locator(trigger).first().waitFor();
        await page.locator("#mdbook-search-toggle").click();
        await page.locator("#mdbook-searchbar").fill("PCAP");
        await page.locator("#mdbook-searchresults li").first().waitFor();
      }
    });
    await test("localized mobile footer keeps words intact and both actions usable", async () => {
      await page.setViewportSize({ width: 320, height: 720 });
      for (const language of languages) {
        await page.goto(
          `${origin}/book/${language.path}part1-foundations/core-concepts.html`,
        );
        await page.locator(trigger).first().waitFor();
        await term("bpf").click();
        await waitOpen();
        await page.locator(".term-hint-close").scrollIntoViewIfNeeded();
        const word = await page
          .locator(".term-hint-glossary")
          .evaluate((el) => {
            const text = el.firstChild;
            const firstSpace = text.textContent.search(/\s/u);
            const range = document.createRange();
            range.setStart(text, 0);
            range.setEnd(
              text,
              firstSpace < 0 ? text.textContent.length : firstSpace,
            );
            return {
              text: range.toString(),
              lines: range.getClientRects().length,
            };
          });
        assert.equal(
          word.lines,
          1,
          `${language.code}: split glossary action word ${word.text}`,
        );
        const bounds = await page.locator(popup).boundingBox();
        for (const selector of [".term-hint-glossary", ".term-hint-close"]) {
          const action = await page.locator(selector).boundingBox();
          assert.ok(
            action.x >= bounds.x &&
              action.x + action.width <= bounds.x + bounds.width + 1 &&
              action.y >= bounds.y &&
              action.y + action.height <= bounds.y + bounds.height + 1,
            `${language.code} ${selector}: ${JSON.stringify({ action, bounds })}`,
          );
        }
        if (screenshots)
          await page.screenshot({
            path: path.join(screenshots, `edition-mobile-${language.code}.png`),
          });
        await page.locator(".term-hint-close").click();
        await waitClosed();
      }
    });
    console.log(`${passed} browser checks passed`);
  } finally {
    await context.close();
    await browser.close();
  }
}
main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => server.close());
