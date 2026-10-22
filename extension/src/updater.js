// @ts-check
/**
 * Cập nhật danh sách đen Tầng 1 từ các nguồn trong ``rules.json`` (bản chuyển thể của
 * ``chotto.tier1.update_from_sources``), cùng các quy tắc an toàn:
 * - chỉ nguồn HTTPS; vượt kích thước, trả HTML hoặc ít hơn ``min_entries`` mục là lỗi;
 * - nguồn trả 304 dùng lại bản sao của chính nó (ETag/Last-Modified); nguồn lỗi dùng bản sao nếu có;
 * - không nguồn nào có dữ liệu mới ⇒ giữ nguyên danh sách hiện tại;
 * - có nguồn lỗi mà không có bản sao ⇒ gộp với danh sách hiện tại để không mất dữ liệu;
 * - danh sách mới nhỏ hơn 50% danh sách cũ (≥ 1000 mục) ⇒ từ chối;
 * - mục là hậu tố công cộng hoặc trùng tên miền tin cậy/chính thức bị loại (chống đầu độc).
 * @module updater
 */

import { readLimited } from "./engine/tier3.js";
import { Fingerprints, entryKey, keysFromLines, parseSource, protectedDomains } from "./engine/tier1.js";

export const UPDATE_INTERVAL_MS = 24 * 3600 * 1000;
export const RETRY_INTERVAL_MS = 3600 * 1000;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;
const SHRINK_GUARD_RATIO = 0.5;
const SHRINK_GUARD_MIN_EXISTING = 1000;

/**
 * @typedef {object} UpdateState
 * @property {number} [lastAttempt] Mốc thử cập nhật gần nhất (ms epoch).
 * @property {number} [lastSuccess] Mốc có ít nhất một nguồn trả lời hợp lệ (ms epoch).
 */

/**
 * @typedef {object} UpdateOutcome
 * @property {number} count Số mục của danh sách mới, 0 nếu không thay.
 * @property {boolean} replaced Đã thay danh sách.
 * @property {boolean} succeeded Có ít nhất một nguồn trả lời hợp lệ (kể cả 304).
 * @property {string[]} log Nhật ký tiến độ tiếng Việt.
 */

/**
 * Đã đến lúc tự cập nhật chưa.
 * @param {UpdateState | null | undefined} state
 * @param {number} now
 * @returns {boolean}
 */
export function updateDue(state, now) {
  if (!state || typeof state !== "object") return true;
  if (typeof state.lastAttempt === "number" && now - state.lastAttempt < RETRY_INTERVAL_MS) return false;
  return !(typeof state.lastSuccess === "number" && now - state.lastSuccess < UPDATE_INTERVAL_MS);
}

/**
 * Hợp hai tập dấu vân tay đã sắp xếp.
 * @param {BigUint64Array} a
 * @param {BigUint64Array} b
 * @returns {BigUint64Array}
 */
export function unionSorted(a, b) {
  const out = new BigUint64Array(a.length + b.length);
  let i = 0;
  let j = 0;
  let k = 0;
  while (i < a.length || j < b.length) {
    /** @type {bigint} */
    let next;
    if (j >= b.length || (i < a.length && a[i] < b[j])) next = a[i++];
    else if (i >= a.length || b[j] < a[i]) next = b[j++];
    else {
      next = a[i++];
      j += 1;
    }
    if (k === 0 || out[k - 1] !== next) out[k++] = next;
  }
  return out.slice(0, k);
}

/**
 * Tải một nguồn với giới hạn kích thước và điều kiện ETag/Last-Modified.
 * @param {string} url
 * @param {{fetchImpl: typeof fetch, maxBytes: number, timeoutMs: number, etag: string, lastModified: string}} options
 * @returns {Promise<{body: string | null, etag: string, lastModified: string}>} ``body`` = ``null`` khi 304.
 * @throws {Error} URL không phải HTTPS, lỗi mạng/HTTP, vượt kích thước hoặc hết giờ.
 */
async function download(url, { fetchImpl, maxBytes, timeoutMs, etag, lastModified }) {
  if (!url.toLowerCase().startsWith("https://")) throw new Error("Chỉ chấp nhận nguồn HTTPS");
  /** @type {Record<string, string>} */
  const headers = {};
  if (etag) headers["If-None-Match"] = etag;
  if (lastModified) headers["If-Modified-Since"] = lastModified;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      headers, signal: controller.signal, credentials: "omit", cache: "no-store", redirect: "follow",
    });
    if (response.status === 304) return { body: null, etag, lastModified };
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await readLimited(response, maxBytes);
    return {
      body,
      etag: response.headers.get("etag") ?? "",
      lastModified: response.headers.get("last-modified") ?? "",
    };
  } catch (error) {
    if (controller.signal.aborted) throw new Error("Hết thời gian tải nguồn");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Tải các nguồn danh sách đen và dựng lại danh sách trong ``store``.
 * @param {object} options
 * @param {Record<string, any>} options.rules Bộ luật (``blacklist_sources``, ``blacklist_max_bytes``...).
 * @param {import("./storage.js").Store} options.store Kho IndexedDB.
 * @param {string[]} options.seed Danh sách đen khởi tạo đóng gói kèm.
 * @param {typeof fetch} [options.fetchImpl]
 * @param {() => number} [options.now]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<UpdateOutcome>}
 * @throws {Error} Không ghi được danh sách mới vào IndexedDB.
 */
export async function updateFromSources({ rules, store, seed, fetchImpl = fetch, now = Date.now, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  /** @type {string[]} */
  const log = [];
  const sources = (Array.isArray(rules.blacklist_sources) ? rules.blacklist_sources : [])
    .filter((/** @type {unknown} */ s) => s && typeof s === "object");
  const maxBytes = Number(rules.blacklist_max_bytes ?? DEFAULT_MAX_BYTES);
  /** @type {string[]} */
  const collected = [];
  let changed = 0;
  let unchanged = 0;
  let lost = 0;
  for (const source of sources) {
    const name = String(source.name ?? "?");
    const url = String(source.url ?? "");
    const minimum = Math.trunc(Number(source.min_entries ?? 1));
    const previous = await store.getSource(url);
    try {
      const fetched = await download(url, {
        fetchImpl, maxBytes, timeoutMs, etag: previous?.etag ?? "", lastModified: previous?.lastModified ?? "",
      });
      if (fetched.body === null) {
        if (!previous) throw new Error("máy chủ báo không đổi nhưng mất bản sao cục bộ");
        collected.push(...previous.entries);
        unchanged += 1;
        log.push(`[OK] ${name}: không đổi (${previous.entries.length} mục)`);
        continue;
      }
      const entries = parseSource(fetched.body).filter((entry) => entryKey(entry) !== null);
      if (entries.length < minimum) throw new Error(`chỉ có ${entries.length} mục hợp lệ (cần ít nhất ${minimum})`);
      await store.putSource({ url, entries, etag: fetched.etag, lastModified: fetched.lastModified, storedAt: now() });
      collected.push(...entries);
      changed += 1;
      log.push(`[OK] ${name}: ${entries.length} mục`);
    } catch (error) {
      log.push(`[LỖI] ${name}: ${error instanceof Error ? error.message : String(error)}`);
      if (previous) {
        collected.push(...previous.entries);
        log.push(`       dùng lại bản sao gần nhất (${previous.entries.length} mục)`);
      } else {
        lost += 1;
      }
    }
  }
  const succeeded = changed + unchanged > 0;
  if (!changed) {
    log.push("Không có dữ liệu mới, giữ nguyên danh sách hiện tại.");
    return { count: 0, replaced: false, succeeded, log };
  }
  const { keys, skipped } = keysFromLines([...collected, ...seed], protectedDomains(rules));
  if (skipped) log.push(`Đã loại ${skipped} mục trùng tên miền tin cậy/hậu tố công cộng.`);
  const existing = await store.getBlacklist();
  const existingCount = existing?.count ?? 0;
  let fingerprints = await Fingerprints.fromKeys(keys);
  if (lost && existing) {
    log.push("Có nguồn lỗi chưa có bản sao: giữ lại các mục cũ để không mất dữ liệu.");
    fingerprints = new Fingerprints(unionSorted(fingerprints.values, Fingerprints.fromBuffer(existing.fingerprints).values));
  } else if (existingCount >= SHRINK_GUARD_MIN_EXISTING && keys.size < SHRINK_GUARD_RATIO * existingCount) {
    log.push(`Danh sách mới (${keys.size} mục) nhỏ bất thường so với hiện tại (${existingCount}), giữ nguyên danh sách cũ.`);
    return { count: 0, replaced: false, succeeded, log };
  }
  await store.putBlacklist({ fingerprints: fingerprints.toBuffer(), count: fingerprints.size, builtAt: now(), origin: "update" });
  log.push(`Đã cập nhật danh sách đen: ${fingerprints.size} mục.`);
  return { count: fingerprints.size, replaced: true, succeeded, log };
}

/**
 * Dựng danh sách đen từ danh sách khởi tạo nếu chưa có (lần cài đặt đầu, hoặc IndexedDB bị xóa).
 * @param {import("./storage.js").Store} store
 * @param {string[]} seed
 * @param {Record<string, any>} rules
 * @param {() => number} [now]
 * @returns {Promise<boolean>} ``true`` nếu vừa dựng.
 */
export async function ensureSeeded(store, seed, rules, now = Date.now) {
  if (await store.getBlacklist()) return false;
  const { keys } = keysFromLines(seed, protectedDomains(rules));
  const fingerprints = await Fingerprints.fromKeys(keys);
  await store.putBlacklist({ fingerprints: fingerprints.toBuffer(), count: fingerprints.size, builtAt: now(), origin: "seed" });
  return true;
}
