// @ts-check
/**
 * Kiểm thử end-to-end: nạp tiện ích vào Chromium thật, mở một trang chat.zalo.me giả lập (chặn mạng bằng
 * ``context.route``) và kiểm tra toàn bộ hành trình: link an toàn mở thẳng, link lừa đảo hiện "Khoan đã!",
 * nút "vẫn mở" bị khóa, chuột giữa, window.open, lưới an toàn tab mới, trang tùy chọn và nhật ký.
 *
 * Chạy: ``npm run e2e`` (cần Chromium của Playwright; trong CI đặt ``CHROMIUM_PATH`` nếu cần).
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const EXTENSION_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FAKE_ZALO = await readFile(path.join(EXTENSION_DIR, "e2e", "fake_zalo.html"), "utf-8");

/** @type {import("playwright").BrowserContext} */
let context;
/** @type {string} */
let extensionId;
/** @type {string} */
let profileDir;
/** @type {import("playwright").Worker} */
let worker;

/**
 * Trang đích giả cho mọi tên miền bên ngoài (không bao giờ ra mạng thật).
 * @param {string} url
 * @returns {string}
 */
function destination(url) {
  return `<!doctype html><title>DEST</title><p id="dest">${new URL(url).host}</p>`;
}

before(async () => {
  profileDir = await mkdtemp(path.join(os.tmpdir(), "chotto-e2e-"));
  context = await chromium.launchPersistentContext(profileDir, {
    channel: "chromium",
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${EXTENSION_DIR}`, `--load-extension=${EXTENSION_DIR}`],
  });
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.protocol === "chrome-extension:") return route.continue();
    if (url.host === "chat.zalo.me") {
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: FAKE_ZALO });
    }
    return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: destination(url.href) });
  });
  [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker");
  extensionId = new URL(worker.url()).host;
  await trackNavigations();
  // Tắt Tầng 3 và tự cập nhật để kiểm thử không phụ thuộc mạng; khóa 3 giây cho nhanh.
  const options = await context.newPage();
  await options.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await options.evaluate(() => chrome.runtime.sendMessage({
    type: "settings", changes: { tier3Enabled: false, autoUpdate: false, frictionSeconds: 3 },
  }));
  await options.close();
  for (const page of context.pages()) if (page.url().startsWith("chrome-extension://")) await page.close();
});

after(async () => {
  await context?.close();
  if (profileDir) await rm(profileDir, { recursive: true, force: true });
});

/**
 * Ghi lại mọi điều hướng khung chính (tab do service worker mở không đi qua ``context.route`` nên được
 * kiểm tra bằng sự kiện webNavigation của chính trình duyệt).
 */
async function trackNavigations() {
  await waitFor(() => worker.evaluate(() => (typeof chrome !== "undefined" && chrome.webNavigation ? true : null)));
  await worker.evaluate(() => {
    const scope = /** @type {any} */ (globalThis);
    if (scope.__chottoNavs) return;
    scope.__chottoNavs = [];
    chrome.webNavigation.onBeforeNavigate.addListener((d) => {
      if (d.frameId === 0) scope.__chottoNavs.push(d.url);
    });
  });
}

/**
 * Chờ một tab điều hướng tới ``url``.
 * @param {string} url
 * @returns {Promise<void>}
 */
async function waitForNavigation(url) {
  await waitFor(async () => {
    const navs = await worker.evaluate(() => /** @type {any} */ (globalThis).__chottoNavs ?? []);
    return navs.includes(url) ? true : null;
  });
}

/**
 * Số lần đã điều hướng tới URL bắt đầu bằng ``prefix``.
 * @param {string} prefix
 * @returns {Promise<number>}
 */
async function navigationsTo(prefix) {
  const navs = await worker.evaluate(() => /** @type {any} */ (globalThis).__chottoNavs ?? []);
  return navs.filter((/** @type {string} */ u) => u.startsWith(prefix)).length;
}

/**
 * Mọi nút trong cây DOM (xuyên cả Shadow DOM đóng) qua Chrome DevTools Protocol.
 * @param {import("playwright").Page} page
 * @returns {Promise<{session: import("playwright").CDPSession, nodes: any[]}>}
 */
async function flatDom(page) {
  const session = await context.newCDPSession(page);
  const { root } = await session.send("DOM.getDocument", { depth: -1, pierce: true });
  /** @type {any[]} */
  const nodes = [];
  /** @param {any} node */
  const walk = (node) => {
    nodes.push(node);
    for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child);
    if (node.contentDocument) walk(node.contentDocument);
  };
  walk(root);
  return { session, nodes };
}

/**
 * Chữ của một nút (ghép các nút chữ con).
 * @param {any} node
 * @returns {string}
 */
function textOf(node) {
  if (node.nodeType === 3) return node.nodeValue;
  return [...(node.children ?? []), ...(node.shadowRoots ?? [])].map(textOf).join("");
}

/**
 * Trạng thái hộp thoại CHOTTO đang hiện (hoặc ``null``).
 * @param {import("playwright").Page} page
 */
async function friction(page) {
  try {
    return await readFriction(page);
  } catch (error) {
    if (/box model|No node|detached|closed/i.test(String(error))) return null;
    throw error;
  }
}

/**
 * @param {import("playwright").Page} page
 */
async function readFriction(page) {
  const { session, nodes } = await flatDom(page);
  const host = nodes.find((n) => n.nodeName === "CHOTTO-SHIELD" && (n.shadowRoots ?? []).some(
    (/** @type {any} */ r) => JSON.stringify(r).includes('"DIALOG"')));
  if (!host) {
    await session.detach();
    return null;
  }
  /** @type {any[]} */
  const inside = [];
  /** @param {any} node */
  const walk = (node) => {
    inside.push(node);
    for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child);
  };
  walk(host);
  const find = (/** @type {string} */ name, /** @type {string} */ cls) => inside.find((n) => n.nodeName === name
    && (n.attributes ?? []).some((/** @type {string} */ a, /** @type {number} */ i, /** @type {string[]} */ arr) => a === "class" && arr[i + 1] === cls));
  const title = inside.find((n) => n.nodeName === "H1");
  const back = find("BUTTON", "back");
  const proceed = find("BUTTON", "proceed");
  const shadowMode = (host.shadowRoots ?? [])[0]?.shadowRootType;
  /** @param {any} node */
  const center = async (node) => {
    const { model } = await session.send("DOM.getBoxModel", { backendNodeId: node.backendNodeId });
    const [x1, y1, , , x3, y3] = model.content;
    return { x: (x1 + x3) / 2, y: (y1 + y3) / 2 };
  };
  await session.send("DOM.scrollIntoViewIfNeeded", { backendNodeId: proceed.backendNodeId }).catch(() => undefined);
  return {
    title: textOf(title),
    text: textOf(host),
    proceedText: textOf(proceed),
    shadowMode,
    backAt: await center(back),
    proceedAt: await center(proceed),
    detach: () => session.detach(),
  };
}

/**
 * Chờ đến khi ``probe`` trả giá trị khác null.
 * @template T
 * @param {() => Promise<T | null>} probe
 * @param {number} [timeoutMs]
 * @returns {Promise<T>}
 */
async function waitFor(probe, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await probe();
    if (value !== null && value !== undefined) return value;
    if (Date.now() > deadline) throw new Error("Hết thời gian chờ");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/**
 * Mở trang Zalo giả lập.
 * @returns {Promise<import("playwright").Page>}
 */
async function openZalo() {
  const page = await context.newPage();
  await page.goto("https://chat.zalo.me/");
  return page;
}

test("link an toàn mở thẳng trong tab mới, handler của Zalo không thấy cú click", async () => {
  const page = await openZalo();
  const opened = context.waitForEvent("page");
  await page.click("#safe");
  const tab = await opened;
  await waitForNavigation("https://vietcombank.com.vn/");
  assert.equal(await page.textContent("#log"), "");
  assert.equal(await friction(page), null);
  await tab.close();
  await page.close();
});

test("link mạo danh hiện Khoan đã!, nút vẫn mở bị khóa rồi mới mở được", async () => {
  const page = await openZalo();
  await page.click("#phish");
  const shown = await waitFor(() => friction(page));
  assert.match(shown.title, /^Khoan đã!/);
  assert.match(shown.text, /Trang sẽ mở: vietcombank-xacthuc\.top/);
  assert.match(shown.text, /Vietcombank/);
  assert.match(shown.proceedText, /vẫn mở \(\d\)/);
  assert.equal(shown.shadowMode, "closed");

  // Bấm khi còn khóa: không có tab nào mở, hộp thoại báo đang khóa.
  await page.mouse.click(shown.proceedAt.x, shown.proceedAt.y);
  await page.waitForTimeout(400);
  assert.equal(await navigationsTo("https://vietcombank-xacthuc.top"), 0);
  assert.match((await waitFor(() => friction(page))).text, /Nút vẫn đang khóa/);
  // Đợi hết khóa (HIGH = 3 + 3 giây). Phím Enter lúc này rơi vào nút "Đóng" (nút "vẫn mở" không nhận phím).
  const unlocked = await waitFor(async () => {
    const state = await friction(page);
    return state && state.proceedText === "Tôi hiểu rủi ro, vẫn mở" ? state : null;
  }, 12000);
  const opened = context.waitForEvent("page");
  await page.mouse.click(unlocked.proceedAt.x, unlocked.proceedAt.y);
  const tab = await opened;
  await waitForNavigation("https://vietcombank-xacthuc.top/login");
  assert.equal(await friction(page), null);
  await shown.detach();
  await unlocked.detach();
  await tab.close();
  await page.close();
});

test("đóng hộp thoại thì không mở gì; Escape cũng là đóng", async () => {
  const page = await openZalo();
  await page.click("#blocked");
  const shown = await waitFor(() => friction(page));
  assert.match(shown.title, /^Đã chặn!/);
  await page.mouse.click(shown.backAt.x, shown.backAt.y);
  await waitFor(async () => ((await friction(page)) === null ? true : null));
  await page.click("#nested-inner");
  const again = await waitFor(() => friction(page));
  assert.match(again.text, /momo-hoantien\.vip/);
  await page.keyboard.press("Escape");
  await waitFor(async () => ((await friction(page)) === null ? true : null));
  assert.equal(await navigationsTo("https://vcb-digibank-xacthuc.top") + await navigationsTo("https://momo-hoantien.vip"), 0);
  await shown.detach();
  await again.detach();
  await page.close();
});

test("chuột giữa mở tab nền sau khi kiểm tra, link rủi ro vẫn bị dừng", async () => {
  const page = await openZalo();
  const before = await navigationsTo("https://vietcombank.com.vn/");
  const opened = context.waitForEvent("page");
  await page.click("#safe", { button: "middle" });
  const tab = await opened;
  await waitFor(async () => ((await navigationsTo("https://vietcombank.com.vn/")) > before ? true : null));
  assert.equal(await page.evaluate(() => document.visibilityState), "visible", "tab nền: Zalo vẫn ở trước");
  await tab.close();
  await page.click("#phish", { button: "middle" });
  const shown = await waitFor(() => friction(page));
  assert.match(shown.text, /vietcombank-xacthuc\.top/);
  await page.mouse.click(shown.backAt.x, shown.backAt.y);
  await shown.detach();
  await page.close();
});

test("window.open từ script của Zalo cũng bị thẩm định; gọi không do người dùng thì bị bỏ qua", async () => {
  const page = await openZalo();
  await page.click("#jsopen");
  const shown = await waitFor(() => friction(page));
  assert.match(shown.text, /vietc0mbank\.com\.vn/);
  await page.mouse.click(shown.backAt.x, shown.backAt.y);
  await shown.detach();
  await page.waitForTimeout(2500);
  const result = await page.evaluate(() => /** @type {any} */ (window).__autoOpen());
  assert.equal(result, null);
  await page.waitForTimeout(500);
  assert.equal(await friction(page), null);
  assert.equal(await navigationsTo("https://momo-hoantien.vip"), 0);
  await page.close();
});

test("liên kết nội bộ của Zalo không bị đụng tới", async () => {
  const page = await openZalo();
  await page.click("#internal");
  await page.waitForURL("https://chat.zalo.me/conversation/123");
  await page.close();
});

test("lưới an toàn: tab mới từ Zalo chưa qua kiểm tra bị chuyển sang trang cảnh báo", async () => {
  const page = await openZalo();
  const opened = context.waitForEvent("page");
  await page.click("#formsubmit");
  const tab = await opened;
  await tab.waitForURL(new RegExp(`^chrome-extension://${extensionId}/src/ui/warn\\.html`));
  const shown = await waitFor(() => friction(tab));
  assert.match(shown.text, /bidv-smartbanking\.com/);
  const closed = tab.waitForEvent("close");
  await tab.mouse.click(shown.backAt.x, shown.backAt.y);
  await closed;
  await page.close();
});

test("trang tùy chọn: trạng thái danh sách đen, thử link, nhật ký chỉ lưu tên miền", async () => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await page.waitForFunction(() => /mục/.test(document.getElementById("blacklist")?.textContent ?? ""));
  assert.match(await page.textContent("#version") ?? "", /^1\.4\.0$/);
  await page.fill('input[name="url"]', "https://vcb-digibank-xacthuc.top/");
  await page.click("#test button");
  await page.waitForFunction(() => /Danh sách đen/.test(document.getElementById("test-status")?.textContent ?? ""));
  const log = await page.textContent("#log");
  assert.match(log ?? "", /vietcombank-xacthuc\.top/);
  assert.match(log ?? "", /Vẫn mở/);
  assert.match(log ?? "", /Đóng \(danh sách đen\)/);
  assert.doesNotMatch(log ?? "", /\/login/, "nhật ký không được lưu đường dẫn");
  await page.close();
});
