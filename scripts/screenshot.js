// Captured the live console and its pool view for the README.
const { chromium } = require('playwright');
const [url, out] = process.argv.slice(2);

// Opened the console, waited for rows, and saved the shots.
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.goto(url);
  await page.waitForSelector('#translations table');
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${out}/console.png`, fullPage: true });
  await page.click('[data-tab="pool"]');
  await page.locator('#console').screenshot({ path: `${out}/pool.png` });
  await browser.close();
})();
