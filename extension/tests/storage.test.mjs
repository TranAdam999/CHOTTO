// @ts-check
/** Kiểm thử kho IndexedDB, cài đặt và cập nhật danh sách đen (IndexedDB giả lập bằng fake-indexeddb). */
import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import { test } from "node:test";

import { Fingerprints } from "../src/engine/tier1.js";
import { DEFAULTS, frictionSecondsFor, loadSettings, saveSettings, validateSettings } from "../src/settings.js";
import { Store } from "../src/storage.js";
import { RETRY_INTERVAL_MS, UPDATE_INTERVAL_MS, ensureSeeded, unionSorted, updateDue, updateFromSources } from "../src/updater.js";
import { loadData } from "./helpers.mjs";

const data = await loadData();
let dbCounter = 0;

/** @returns {Store} */
function freshStore() {
  dbCounter += 1;
  return new Store(indexedDB, `chotto-test-${dbCounter}`);
}

/** Vùng lưu trữ giả cho chrome.storage.local. */
function memoryArea() {
  /** @type {Record<string, unknown>} */
  const items = {};
  return /** @type {chrome.storage.StorageArea} */ (/** @type {unknown} */ ({
    get: async (/** @type {string} */ key) => (key in items ? { [key]: items[key] } : {}),
    set: async (/** @type {Record<string, unknown>} */ values) => { Object.assign(items, values); },
  }));
}

/**
 * Máy chủ nguồn giả: mỗi URL một hàm trả Response.
 * @param {Record<string, (init: RequestInit | undefined) => Response | Promise<Response>>} routes
 * @returns {typeof fetch}
 */
function fakeFetch(routes) {
  return /** @type {typeof fetch} */ (async (input, init) => {
    const handler = routes[String(input)];
    if (!handler) throw new TypeError(`Failed to fetch ${String(input)}`);
    return handler(init);
  });
}

const RULES = {
  ...data.rules,
  blacklist_sources: [
    { name: "A", url: "https://a.example/list", min_entries: 2 },
    { name: "B", url: "https://b.example/list.json", min_entries: 1 },
  ],
};

test("Cài đặt: kiểm tra miền giá trị và thời gian khóa theo mức", async () => {
  assert.deepEqual(validateSettings(null), DEFAULTS);
  const checked = validateSettings({ frictionSeconds: 99, tier3Enabled: "có", logRetentionDays: 30, extra: 1 });
  assert.equal(checked.frictionSeconds, 5);
  assert.equal(checked.tier3Enabled, true);
  assert.equal(checked.logRetentionDays, 30);
  assert.equal("extra" in checked, false);
  assert.equal(frictionSecondsFor("WARN", 5), 5);
  assert.equal(frictionSecondsFor("HIGH", 5), 8);
  assert.equal(frictionSecondsFor("BLOCKED", 5), 10);
  const area = memoryArea();
  assert.equal((await saveSettings(area, { frictionSeconds: 7 })).frictionSeconds, 7);
  assert.equal((await loadSettings(area)).frictionSeconds, 7);
  await assert.rejects(saveSettings(area, { frictionSeconds: 2 }), RangeError);
});

test("Kho: danh sách đen, nguồn, nhật ký (dọn theo hạn)", async () => {
  const store = freshStore();
  assert.equal(await store.getBlacklist(), null);
  assert.equal(await ensureSeeded(store, data.seed, data.rules), true);
  assert.equal(await ensureSeeded(store, data.seed, data.rules), false);
  const record = await store.getBlacklist();
  assert.equal(record?.origin, "seed");
  const fp = Fingerprints.fromBuffer(/** @type {ArrayBuffer} */ (record?.fingerprints));
  assert.equal(await fp.lookup("vcb-digibank-xacthuc.top", "/"), "vcb-digibank-xacthuc.top");

  await store.addDecision({ ts: 1000, domain: "old.top", level: "WARN", score: 40, choice: "back", via: "click" });
  await store.addDecision({ ts: 5000, domain: "new.top", level: "HIGH", score: 70, choice: "proceed", via: "click" });
  assert.deepEqual((await store.listDecisions()).map((d) => d.domain), ["new.top", "old.top"]);
  assert.equal(await store.pruneDecisions(2000), 1);
  assert.deepEqual((await store.listDecisions()).map((d) => d.domain), ["new.top"]);
  await store.clearDecisions();
  assert.deepEqual(await store.listDecisions(), []);
  await store.close();
});

test("Cập nhật: hạn cập nhật và hợp tập dấu vân tay", () => {
  const now = 10 * UPDATE_INTERVAL_MS;
  assert.equal(updateDue(null, now), true);
  assert.equal(updateDue({ lastAttempt: now - 60_000, lastSuccess: 0 }, now), false);
  assert.equal(updateDue({ lastAttempt: now - RETRY_INTERVAL_MS - 1, lastSuccess: now - 1000 }, now), false);
  assert.equal(updateDue({ lastAttempt: now - RETRY_INTERVAL_MS - 1, lastSuccess: now - UPDATE_INTERVAL_MS - 1 }, now), true);
  assert.deepEqual([...unionSorted(new BigUint64Array([1n, 3n, 5n]), new BigUint64Array([2n, 3n, 9n]))], [1n, 2n, 3n, 5n, 9n]);
});

test("Cập nhật: ETag/304, nguồn lỗi dùng bản sao, chống đầu độc, chống co rút", async () => {
  const store = freshStore();
  /** @type {(string | undefined)[]} */
  const conditional = [];
  let aBody = "evil-one.top\nevil-two.top\nvietcombank.com.vn\ncom.vn\n";
  let aStatus = 200;
  const fetchImpl = fakeFetch({
    "https://a.example/list": (init) => {
      conditional.push(/** @type {Record<string, string>} */ (init?.headers ?? {})["If-None-Match"]);
      if (aStatus === 304) return new Response(null, { status: 304 });
      return new Response(aBody, { status: aStatus, headers: { etag: '"v1"' } });
    },
    "https://b.example/list.json": () => new Response(JSON.stringify({ data: [{ url: "https://bad.example.top/login" }] })),
  });
  const first = await updateFromSources({ rules: RULES, store, seed: data.seed, fetchImpl });
  assert.equal(first.replaced, true, first.log.join("\n"));
  const fp = Fingerprints.fromBuffer(/** @type {ArrayBuffer} */ ((await store.getBlacklist())?.fingerprints));
  assert.equal(await fp.lookup("evil-one.top", "/"), "evil-one.top");
  assert.equal(await fp.lookup("bad.example.top", "/login/x"), "bad.example.top/login");
  assert.equal(await fp.lookup("vietcombank.com.vn", "/"), null, "tên miền chính thức không bị đầu độc");
  assert.equal(await fp.lookup("x.com.vn", "/"), null, "hậu tố công cộng bị loại");
  assert.ok(first.log.some((line) => line.includes("Đã loại 2 mục")));

  aStatus = 304;
  const second = await updateFromSources({ rules: RULES, store, seed: data.seed, fetchImpl });
  assert.equal(conditional.at(-1), '"v1"');
  assert.ok(second.log.some((line) => line.includes("A: không đổi")));
  assert.equal(second.replaced, true);

  aStatus = 500;
  const third = await updateFromSources({ rules: RULES, store, seed: data.seed, fetchImpl });
  assert.ok(third.log.some((line) => line.includes("[LỖI] A: HTTP 500")));
  assert.ok(third.log.some((line) => line.includes("dùng lại bản sao")));
  const fp3 = Fingerprints.fromBuffer(/** @type {ArrayBuffer} */ ((await store.getBlacklist())?.fingerprints));
  assert.equal(await fp3.lookup("evil-two.top", "/"), "evil-two.top");

  const html = await updateFromSources({
    rules: { ...RULES, blacklist_sources: [{ name: "H", url: "https://h.example/", min_entries: 1 }] },
    store, seed: data.seed, fetchImpl: fakeFetch({ "https://h.example/": () => new Response("<!doctype html><p>lỗi</p>") }),
  });
  assert.equal(html.replaced, false);
  assert.equal(html.succeeded, false);

  const insecure = await updateFromSources({
    rules: { ...RULES, blacklist_sources: [{ name: "I", url: "http://i.example/", min_entries: 1 }] },
    store, seed: data.seed, fetchImpl,
  });
  assert.ok(insecure.log.some((line) => line.includes("Chỉ chấp nhận nguồn HTTPS")));

  const big = Array.from({ length: 2400 }, (_, i) => `phish-${i}.top`).join("\n");
  aBody = big;
  aStatus = 200;
  const grown = await updateFromSources({ rules: RULES, store, seed: data.seed, fetchImpl });
  assert.ok(grown.count > 2400);
  aBody = "only-one.top\nonly-two.top\n";
  const shrunk = await updateFromSources({ rules: RULES, store, seed: data.seed, fetchImpl });
  assert.equal(shrunk.replaced, false);
  assert.ok(shrunk.log.some((line) => line.includes("nhỏ bất thường")));
  await store.close();
});
