// Captured every console view and the phone layout for the README.
const { chromium } = require('playwright');
const [url, out] = process.argv.slice(2);

// Opened the console, waited for rows, and saved one shot per tab plus a phone shot.
(async () => {
  const browser = await chromium.launch();
  const open = async (width, height) => {
    const page = await (await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 2 })).newPage();
    await page.goto(url);
    await page.waitForSelector('#translations table');
    await page.waitForTimeout(500);
    return page;
  };
  const page = await open(1280, 900);
  await page.screenshot({ path: `${out}/console.png`, fullPage: true });
  for (const tab of ['translations', 'pool', 'timeouts']) {
    await page.click(`[data-tab="${tab}"]`);
    await page.locator('#console').screenshot({ path: `${out}/${tab}.png` });
  }
  await (await open(390, 844)).screenshot({ path: `${out}/mobile.png`, fullPage: true });
  await browser.close();
})();
