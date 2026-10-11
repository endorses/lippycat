#!/usr/bin/env node
// Build the manual first. Set PLAYWRIGHT_MODULE and optionally CHROMIUM_EXECUTABLE.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

const manual = path.resolve(__dirname, "..");
const root = path.join(manual, "book");
const languages = JSON.parse(
  fs.readFileSync(path.join(manual, "languages.json")),
);
const dialog = "#manual-image-viewer";
const action = (name) => `${dialog} [data-image-viewer-action="${name}"]`;
const screenshots = process.env.IMAGE_VIEWER_SCREENSHOTS;
const server = http.createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  const file = path.resolve(root, `.${decodeURIComponent(url.pathname)}`);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {
    response.writeHead(404);
    response.end();
    return;
  }
  response.setHeader(
    "Content-Type",
    {
      ".html": "text/html",
      ".js": "application/javascript",
      ".css": "text/css",
      ".json": "application/json",
      ".gif": "image/gif",
    }[path.extname(file)] || "application/octet-stream",
  );
  response.end(fs.readFileSync(file));
});

async function main() {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_EXECUTABLE || "/usr/bin/chromium",
    args: ["--no-sandbox"],
  });
  try {
    const errors = [];
    const base = `http://127.0.0.1:${server.address().port}/`;
    for (const language of languages) {
      const page = await browser.newPage({
        viewport: { width: 1440, height: 1000 },
        hasTouch: true,
      });
      page.on("pageerror", (error) => errors.push(error.message));
      await page.addInitScript(() =>
        localStorage.setItem("mdbook-theme", "navy"),
      );
      await page.goto(
        `${base}${language.path}part3-distributed/architecture.html`,
      );
      const diagram = page.locator(
        "#fig-distributed-architecture svg[data-image-viewer]",
      );
      await diagram.waitFor();
      assert.equal(
        await page.locator("main .mermaid svg[data-image-viewer]").count(),
        5,
      );
      assert.equal(await diagram.getAttribute("role"), "button");
      await diagram.focus();
      await page.keyboard.press("Enter");
      await page.locator(`${dialog}[open]`).waitFor();
      const image = page.locator(`${dialog} img`);
      await page.waitForFunction((selector) => {
        const image = document.querySelector(selector);
        return image?.complete && image.naturalWidth > 0;
      }, `${dialog} img`);
      assert.match(await image.getAttribute("src"), /^blob:/);
      const initial = (await image.boundingBox()).width;
      await page.locator(action("zoomIn")).click();
      assert.ok((await image.boundingBox()).width > initial);
      await page.locator(action("zoomOut")).click();
      await page.locator(action("reset")).click();
      assert.ok(Math.abs((await image.boundingBox()).width - initial) < 1);
      assert.equal(
        await page.locator(action("close")).getAttribute("aria-label"),
        language.imageViewer.close,
      );
      const chapterURL = page.url();
      await page.locator(`${dialog} .manual-image-viewer-viewport`).focus();
      await page.keyboard.press("+");
      await page.keyboard.press("+");
      await page.keyboard.press("+");
      assert.ok(
        await page
          .locator(`${dialog} .manual-image-viewer-viewport`)
          .evaluate((node) => {
            node.scrollLeft = 0;
            return node.scrollWidth > node.clientWidth;
          }),
      );
      await page.keyboard.press("ArrowRight");
      await page.waitForFunction(
        (selector) => document.querySelector(selector).scrollLeft > 0,
        `${dialog} .manual-image-viewer-viewport`,
      );
      await page.keyboard.press("ArrowLeft");
      await page.keyboard.press("/");
      assert.equal(page.url(), chapterURL);
      assert.equal(await page.locator(`${dialog}[open]`).count(), 1);
      await page.keyboard.press("0");
      for (let i = 0; i < 8; i++) {
        await page.keyboard.press("Tab");
        assert.ok(
          await page.evaluate(
            (selector) =>
              document.querySelector(selector).contains(document.activeElement),
            dialog,
          ),
        );
      }
      for (let i = 0; i < 8; i++) {
        await page.keyboard.press("Shift+Tab");
        assert.ok(
          await page.evaluate(
            (selector) =>
              document.querySelector(selector).contains(document.activeElement),
            dialog,
          ),
        );
      }
      if (screenshots) {
        fs.mkdirSync(screenshots, { recursive: true });
        await page.screenshot({
          path: path.join(screenshots, `${language.code}-diagram.png`),
        });
      }
      await page.keyboard.press("Escape");
      await page.locator(`${dialog}[open]`).waitFor({ state: "hidden" });
      assert.equal(await page.locator(`${dialog}[open]`).count(), 0);
      assert.ok(
        await diagram.evaluate((node) => node === document.activeElement),
      );

      // Reproduce a paragraph with too little space at the end of the line.
      assert.ok(
        await page.evaluate(() => {
          const link = [
            ...document.querySelectorAll('main a[href*="#fig-"]'),
          ].find((node) => /\u00a0\d+$/.test(node.textContent));
          if (!link) return false;
          const container = document.createElement("p");
          const copy = link.cloneNode(true);
          container.append("prefix ", copy);
          document.querySelector("main").append(container);
          container.style.width = `${link.getBoundingClientRect().width + 1}px`;
          const range = document.createRange();
          range.selectNodeContents(copy);
          const intact = range.getClientRects().length === 1;
          container.remove();
          return intact;
        }),
      );
      await page.goto(`${base}${language.path}appendices/list-of-figures.html`);
      assert.ok(
        await page
          .locator(".figure-list a")
          .evaluateAll(
            (links) =>
              links.length > 0 &&
              links.every((link, index) =>
                link.textContent.includes(`\u00a0${index + 1}:`),
              ),
          ),
      );

      await page.goto(
        `${base}${language.path}part1-foundations/introduction.html`,
      );
      const gif = page.locator(
        'main img[src$="packet-stream.gif"][data-image-viewer]',
      );
      await gif.waitFor();
      await gif.focus();
      await page.keyboard.press("Space");
      await page.locator(`${dialog}[open]`).waitFor();
      assert.match(
        await page.locator(`${dialog} img`).getAttribute("src"),
        /packet-stream\.gif$/,
      );
      await page.locator(action("close")).click();
      assert.ok(await gif.evaluate((node) => node === document.activeElement));
      await page.setViewportSize({ width: 390, height: 844 });
      await gif.tap();
      await page.locator(`${dialog}[open]`).waitFor();
      const bounds = await page.locator(dialog).boundingBox();
      assert.ok(bounds.width <= 390 && bounds.height <= 844);
      for (const name of ["close", "zoomIn", "zoomOut", "reset"]) {
        const button = await page.locator(action(name)).boundingBox();
        assert.ok(button.x >= 0 && button.x + button.width <= 391);
      }
      if (screenshots)
        await page.screenshot({
          path: path.join(screenshots, `${language.code}-mobile.png`),
        });
      await page.emulateMedia({ media: "print" });
      assert.equal(await page.locator(dialog).isVisible(), false);
      assert.equal(await gif.isVisible(), true);
      await page.emulateMedia({ media: "screen" });
      await page.keyboard.press("Escape");
      await page.close();
      console.log(
        `${language.code}: keyboard, zoom, focus, GIF, mobile, print, and nonbreaking references passed`,
      );
    }
    for (const theme of ["light", "rust", "coal", "ayu"]) {
      const page = await browser.newPage({
        viewport: { width: 1280, height: 900 },
      });
      page.on("pageerror", (error) => errors.push(error.message));
      await page.addInitScript(
        (theme) => localStorage.setItem("mdbook-theme", theme),
        theme,
      );
      await page.goto(`${base}en/part3-distributed/architecture.html`);
      await page
        .locator("#fig-distributed-architecture svg[data-image-viewer]")
        .click();
      await page.locator(`${dialog}[open]`).waitFor();
      await page.waitForFunction(
        (selector) => document.querySelector(selector)?.naturalWidth > 0,
        `${dialog} img`,
      );
      if (screenshots)
        await page.screenshot({
          path: path.join(screenshots, `${theme}-diagram.png`),
        });
      await page.close();
      console.log(`${theme}: diagram viewer passed`);
    }
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => server.close());
