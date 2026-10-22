// @ts-check
/**
 * Tầng 1 – Danh sách đen offline: tập dấu vân tay 64-bit đã sắp xếp, tra bằng tìm nhị phân.
 *
 * Mỗi khóa (``host`` hoặc ``host/path``) được băm SHA-256 (WebCrypto) lấy 8 byte đầu. Với n mục, xác suất
 * một tên miền sạch trùng dấu vân tay là n/2^64 (≈ 2·10⁻¹⁴ với 400.000 mục). Cách đọc dòng danh sách, chuẩn
 * hóa khóa và chống đầu độc giống hệt ``chotto/tier1.py``; chỉ hàm băm khác (trình duyệt không có BLAKE2b).
 * @module engine/tier1
 */

import { URLParseError, parseUrl } from "./url.js";
import { defaultPsl, inDomain, isIp, parentDomains } from "./util.js";

const MAX_PATH_SEGMENTS = 16;
const HASH_BATCH = 2048;
const ENCODER = new TextEncoder();

/**
 * Dấu vân tay 64-bit của một khóa.
 * @param {string} key
 * @returns {Promise<bigint>}
 */
export async function fingerprint(key) {
  const digest = await crypto.subtle.digest("SHA-256", ENCODER.encode(key));
  return new DataView(digest).getBigUint64(0, true);
}

/** Tập dấu vân tay đã sắp xếp tăng dần, không trùng. */
export class Fingerprints {
  /**
   * @param {BigUint64Array} values Mảng ĐÃ sắp xếp tăng dần, không trùng.
   */
  constructor(values) {
    this.values = values;
  }

  /**
   * Dựng tập từ các khóa.
   * @param {Iterable<string>} keys
   * @returns {Promise<Fingerprints>}
   */
  static async fromKeys(keys) {
    const unique = [...new Set(keys)];
    const values = new BigUint64Array(unique.length);
    for (let start = 0; start < unique.length; start += HASH_BATCH) {
      const batch = unique.slice(start, start + HASH_BATCH);
      const hashed = await Promise.all(batch.map((key) => fingerprint(key)));
      values.set(hashed, start);
    }
    values.sort();
    let write = 0;
    for (let read = 0; read < values.length; read += 1) {
      if (write === 0 || values[read] !== values[write - 1]) {
        values[write] = values[read];
        write += 1;
      }
    }
    return new Fingerprints(values.slice(0, write));
  }

  /**
   * Dựng lại từ dữ liệu đã lưu (ArrayBuffer little-endian), kiểm tra độ dài và thứ tự.
   * @param {ArrayBuffer} buffer
   * @returns {Fingerprints}
   * @throws {RangeError} Dữ liệu cụt hoặc chưa sắp xếp.
   */
  static fromBuffer(buffer) {
    if (buffer.byteLength % 8 !== 0) throw new RangeError("Dữ liệu dấu vân tay bị cụt");
    const view = new DataView(buffer);
    const values = new BigUint64Array(buffer.byteLength / 8);
    for (let i = 0; i < values.length; i += 1) {
      values[i] = view.getBigUint64(i * 8, true);
      if (i > 0 && values[i] <= values[i - 1]) throw new RangeError("Dữ liệu dấu vân tay chưa sắp xếp");
    }
    return new Fingerprints(values);
  }

  /**
   * Tuần tự hóa little-endian (độc lập kiến trúc).
   * @returns {ArrayBuffer}
   */
  toBuffer() {
    const buffer = new ArrayBuffer(this.values.length * 8);
    const view = new DataView(buffer);
    this.values.forEach((value, i) => view.setBigUint64(i * 8, value, true));
    return buffer;
  }

  /** Số dấu vân tay. */
  get size() {
    return this.values.length;
  }

  /**
   * ``true`` nếu dấu vân tay ``value`` có trong tập.
   * @param {bigint} value
   * @returns {boolean}
   */
  hasFingerprint(value) {
    let lo = 0;
    let hi = this.values.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.values[mid] < value) lo = mid + 1;
      else hi = mid;
    }
    return lo < this.values.length && this.values[lo] === value;
  }

  /**
   * ``true`` nếu khóa có trong tập.
   * @param {string} key
   * @returns {Promise<boolean>}
   */
  async has(key) {
    return this.hasFingerprint(await fingerprint(key));
  }

  /**
   * Khóa danh sách đen khớp với ``host`` (và tên miền cha) hoặc ``host`` + tiền tố ``path``.
   * @param {string} host Host ASCII chữ thường.
   * @param {string} [path]
   * @returns {Promise<string | null>}
   */
  async lookup(host, path = "") {
    for (const key of candidateKeys(host, path)) if (await this.has(key)) return key;
    return null;
  }
}

/**
 * Các khóa cần tra cho một URL: host, các tên miền cha, rồi host + từng tiền tố đường dẫn.
 * @param {string} host
 * @param {string} path
 * @returns {string[]}
 */
export function candidateKeys(host, path) {
  if (!host) return [];
  const candidates = parentDomains(host);
  const segments = (path || "").toLowerCase().split("/").filter(Boolean).slice(0, MAX_PATH_SEGMENTS);
  let prefix = "";
  for (const segment of segments) {
    prefix += `/${segment}`;
    candidates.push(host + prefix);
  }
  return candidates;
}

/**
 * Chuẩn hóa một dòng danh sách đen thành khóa (``host`` hoặc ``host/path``); dòng hỏng trả ``null``.
 * Hỗ trợ tên miền trần, URL đầy đủ và định dạng AdGuard ``||domain^``. Không bao giờ ném lỗi.
 * @param {unknown} entry
 * @returns {string | null}
 */
export function entryKey(entry) {
  if (typeof entry !== "string") return null;
  let text = entry.trim();
  if (!text || text.startsWith("#") || text.startsWith("!") || text.startsWith("//")) return null;
  if (text.startsWith("||")) text = text.slice(2).split("^", 1)[0].split("$", 1)[0];
  if (!text.includes("://")) text = `http://${text}`;
  try {
    const parsed = parseUrl(text);
    if (!isIp(parsed.host) && !parsed.host.includes(".")) return null;
    const path = parsed.path.replace(/\/+$/, "").toLowerCase();
    return path ? parsed.host + path : parsed.host;
  } catch (error) {
    if (!(error instanceof URLParseError)) console.warn("CHOTTO: dòng danh sách đen lỗi bất thường", error);
    return null;
  }
}

/**
 * Tách CSV một dòng theo RFC 4180 (đủ cho file PhishTank).
 * @param {string} text
 * @returns {string[][]}
 */
function parseCsv(text) {
  /** @type {string[][]} */
  const rows = [];
  /** @type {string[]} */
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/**
 * Đọc nội dung một nguồn: JSON (list/dict), CSV PhishTank, hoặc văn bản mỗi dòng một mục.
 * @param {string} raw
 * @returns {string[]}
 */
export function parseSource(raw) {
  const text = raw.trim().replace(/^﻿/, "");
  if (!text) return [];
  if (text[0] === "[" || text[0] === "{") {
    /** @type {unknown} */
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      return [];
    }
    if (data && typeof data === "object" && !Array.isArray(data)) {
      data = Object.values(data).find((v) => Array.isArray(v)) ?? [];
    }
    if (!Array.isArray(data)) return [];
    /** @type {string[]} */
    const out = [];
    for (const item of data) {
      if (typeof item === "string") out.push(item);
      else if (item && typeof item === "object") {
        const value = item.url || item.domain || item.host;
        if (typeof value === "string") out.push(value);
      }
    }
    return out;
  }
  const head = text.slice(0, 15).toLowerCase();
  if (head.startsWith("phish_id")) {
    const rows = parseCsv(text);
    const header = rows.shift() ?? [];
    const column = header.indexOf("url");
    if (column < 0) return [];
    return rows.map((row) => row[column]).filter((value) => Boolean(value));
  }
  if (head.startsWith("<!doctype") || head.startsWith("<html")) return [];
  return text.split(/\r\n|\r|\n/);
}

/**
 * Tên miền được bảo vệ (tin cậy + chính thức của thương hiệu): mục danh sách đen trùng sẽ bị loại.
 * @param {Record<string, any>} rules
 * @returns {string[]}
 */
export function protectedDomains(rules) {
  const domains = (rules.trusted_domains ?? []).filter((/** @type {unknown} */ d) => typeof d === "string");
  for (const brand of rules.brands ?? []) {
    for (const d of brand?.domains ?? []) if (typeof d === "string") domains.push(d);
  }
  return domains;
}

/**
 * Chuẩn hóa các dòng thành tập khóa, loại mục là hậu tố công cộng (``com.vn``, ``web.app``: sẽ chặn cả
 * nghìn trang) và mục trùng tên miền được bảo vệ (chống đầu độc danh sách).
 * @param {Iterable<unknown>} lines
 * @param {string[]} protectedList
 * @returns {{keys: Set<string>, skipped: number}}
 */
export function keysFromLines(lines, protectedList) {
  /** @type {Set<string>} */
  const keys = new Set();
  const psl = defaultPsl();
  let skipped = 0;
  for (const line of lines) {
    const key = entryKey(line);
    if (key === null) continue;
    const host = key.split("/", 1)[0];
    if ((!isIp(host) && psl.lookup(host).registrable === null)
        || protectedList.some((domain) => inDomain(host, domain))) {
      skipped += 1;
      continue;
    }
    keys.add(key);
  }
  return { keys, skipped };
}
