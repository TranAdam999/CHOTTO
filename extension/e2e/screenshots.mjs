// @ts-check
/**
 * Chụp ảnh minh họa trải nghiệm thật của tiện ích (dùng cho slide/báo cáo): nạp tiện ích vào Chromium,
 * mở trang chat giả lập, bấm link lừa đảo và chụp màn hình "Khoan đã!", trang cảnh báo và trang tùy chọn.
 *
 * Chạy: ``node e2e/screenshots.mjs <thư mục ảnh>``
 */
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const EXTENSION_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * @param {string} outDir
 * @returns {Promise<void>}
 */
async function main(outDir) {
  await mkdir(outDir, { recursive: true });
  const demo = await readFile(path.join(EXTENSION_DIR, "e2e", "demo_zalo.html"), "utf-8");
  const profile = await mkdtemp(path.join(os.tmpdir(), "chotto-shots-"));
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 2,
    locale: "vi-VN",
    args: [`--disable-extensions-except=${EXTENSION_DIR}`, `--load-extension=${EXTENSION_DIR}`],
  });
  try {
    await context.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.protocol === "chrome-extension:") return route.continue();
      const body = url.host === "chat.zalo.me" ? demo : `<p>${url.host}</p>`;
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body });
    });
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent("serviceworker");
    const id = new URL(worker.url()).host;
    const options = await context.newPage();
    await options.goto(`chrome-extension://${id}/src/ui/options.html`);
    await options.evaluate(() => chrome.runtime.sendMessage({
      type: "settings", changes: { tier3Enabled: false, autoUpdate: false },
    }));

    const chat = await context.newPage();
    await chat.goto("https://chat.zalo.me/");
    await chat.click("#phish");
    await chat.waitForTimeout(1200);
    await chat.screenshot({ path: path.join(outDir, "1-khoan-da-dang-khoa.png") });
    await chat.waitForTimeout(8000);
    await chat.screenshot({ path: path.join(outDir, "2-khoan-da-het-khoa.png") });
    await chat.keyboard.press("Escape");
    await chat.waitForTimeout(500);
    await chat.click("#blocked");
    await chat.waitForTimeout(1200);
    await chat.screenshot({ path: path.join(outDir, "3-da-chan-danh-sach-den.png") });
    await chat.keyboard.press("Escape");

    const warn = await context.newPage();
    await warn.goto(`chrome-extension://${id}/src/ui/warn.html?u=${encodeURIComponent("https://bidv-smartbanking.com/xac-thuc")}`);
    await warn.waitForTimeout(1200);
    await warn.screenshot({ path: path.join(outDir, "4-luoi-an-toan-tab-moi.png") });

    await options.reload();
    await options.waitForTimeout(1000);
    await options.screenshot({ path: path.join(outDir, "5-trang-cai-dat.png"), fullPage: true });
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }
}

main(process.argv[2] ?? path.join(EXTENSION_DIR, "screenshots")).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
