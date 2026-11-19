// Run with node --test and Playwright installed. CSV_LAZER_URL can target a deployed candidate.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const browsers = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const url = process.env.CSV_LAZER_URL || new URL('../../tools/csv-lazer/index.html', import.meta.url).href;

for (const engine of ['chromium', 'webkit']) {
    test(`${engine} exports only the currently parsed input`, async () => {
        const browser = await browsers[engine].launch();
        try {
            const page = await browser.newPage();
            // The fixture is browser-local. Analytics is unnecessary for this regression.
            await page.route('**/assets/fa-ga4.js', route => route.abort());
            await page.goto(url);
            const input = page.locator('#inputText');
            const parse = page.locator('.btn-parse');
            const download = page.locator('#downloadBtn');
            const first = 'item: audit-blue';
            const next = 'item: audit-green';
            async function exportedFile() {
                const [file] = await Promise.all([page.waitForEvent('download'), download.click()]);
                return readFile(await file.path(), 'utf8');
            }
            await input.fill(first);
            await parse.click();
            assert.match(await exportedFile(), /audit-blue/);
            await input.fill(next);
            assert.equal(await download.isDisabled(), true);
            assert.match(await page.locator('#warningMessage').innerText(), /Parse again/);
            assert.equal(await page.locator('#previewTable tbody tr').count(), 0);
            await input.fill(first); // Restoring old text also requires an explicit reparse.
            assert.equal(await download.isDisabled(), true);
            await input.fill(next);
            await parse.click();
            assert.match(await exportedFile(), /audit-green/);

            // A programmatic replacement need not fire an input event. The action
            // itself must still invalidate the old result before it builds a file.
            await input.evaluate((e, value) => { e.value = value; }, first);
            await download.focus();
            await page.keyboard.press('Enter');
            assert.equal(await download.isDisabled(), true);
            assert.equal(await page.locator('#previewTable tbody tr').count(), 0);

            await input.fill('@audit_example\nexample-note\nexample@example.test');
            await parse.click();
            assert.equal(await download.isDisabled(), true);
            await page.locator('#confirmBtn').click();
            assert.equal(await download.isEnabled(), true);
            await input.fill(next);
            assert.equal(await download.isDisabled(), true);
            await parse.click();
            await page.locator('.btn-clear').click();
            assert.equal(await download.isDisabled(), true);
            assert.equal(await input.inputValue(), '');
        } finally {
            await browser.close();
        }
    });
}
