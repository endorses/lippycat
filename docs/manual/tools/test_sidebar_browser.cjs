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
const toggle = "#mdbook-sidebar-toggle";
const sidebar = "#mdbook-sidebar";
const checkbox = "#mdbook-sidebar-toggle-anchor";
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

async function assertOpen(page, open) {
  await page.waitForFunction(
    ({ checkbox, open }) => document.querySelector(checkbox).checked === open,
    { checkbox, open },
  );
  assert.equal(
    await page.locator(toggle).getAttribute("aria-expanded"),
    String(open),
  );
  assert.equal(
    await page.locator(sidebar).getAttribute("aria-hidden"),
    String(!open),
  );
  assert.equal(
    await page.evaluate(() => localStorage.getItem("mdbook-sidebar")),
    open ? "visible" : "hidden",
  );
  // Wait for mdBook's sliding animation before the next real pointer action.
  await page.waitForFunction(() =>
    document
      .getAnimations()
      .every((animation) => animation.playState !== "running"),
  );
}

async function clickOutside(page, touch) {
  const { width, height } = page.viewportSize();
  const point = { x: width - 5, y: height - 5 };
  assert.ok(
    await page.evaluate(({ x, y }) => {
      const target = document.elementFromPoint(x, y);
      return (
        target && !target.closest("#mdbook-sidebar, #mdbook-sidebar-toggle")
      );
    }, point),
  );
  if (touch) await page.touchscreen.tap(point.x, point.y);
  else await page.mouse.click(point.x, point.y);
}

async function main() {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_EXECUTABLE || "/usr/bin/chromium",
    args: ["--no-sandbox"],
  });
  try {
    const errors = [];
    for (const language of languages) {
      const page = await browser.newPage({
        viewport: { width: 390, height: 844 },
        hasTouch: true,
      });
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(
        `http://127.0.0.1:${server.address().port}/${language.path}part1-foundations/introduction.html`,
      );
      for (const width of [390, 619, 620, 1440]) {
        await page.setViewportSize({ width, height: 844 });
        for (const touch of [true, false]) {
          if (touch) await page.locator(toggle).tap();
          else await page.locator(toggle).click();
          await assertOpen(page, true);
          await page.locator(sidebar).click({ position: { x: 10, y: 10 } });
          await assertOpen(page, true);
          await clickOutside(page, touch);
          await assertOpen(page, width >= 620);
          if (width >= 620) await page.locator(toggle).click();
          await assertOpen(page, false);
          await clickOutside(page, touch);
          await assertOpen(page, false);

          // Clicking the toggle again closes it without an immediate reopening.
          await page.locator(toggle).click();
          await assertOpen(page, true);
          await page.locator(toggle).click();
          await assertOpen(page, false);
        }
      }
      // Changing the viewport updates dismissal behavior without a reload.
      await page.locator(toggle).click();
      await assertOpen(page, true);
      await page.setViewportSize({ width: 390, height: 844 });
      await assertOpen(page, true);
      // Other outside controls still perform their normal action.
      await page.locator("#mdbook-theme-toggle").tap();
      await assertOpen(page, false);
      assert.equal(
        await page
          .locator("#mdbook-theme-toggle")
          .getAttribute("aria-expanded"),
        "true",
      );
      await page.close();
      console.log(
        `${language.code}: mobile dismissal and desktop sidebar passed`,
      );
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
