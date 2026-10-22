// @ts-check
/**
 * Tầng 3 – Tuổi đời tên miền qua RDAP, có cache và deadline cứng (mặc định 1,8 giây).
 *
 * Trình duyệt không mở được cổng 43 nên tiện ích chỉ dùng RDAP (bản Desktop chạy song song RDAP và WHOIS):
 * hỏi thẳng máy chủ của nhà đăng ký theo bảng IANA bootstrap (RFC 9224), TLD không có trong bảng thì dùng
 * rdap.org. Hết giờ hoặc lỗi mạng trả ``null`` để engine quay về điểm Tầng 2.
 * @module engine/tier3
 */

import { defaultPsl, isIp } from "./util.js";

export const RDAP_FALLBACK = "https://rdap.org/domain/";
export const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
export const FAILURE_TTL_MS = 3600 * 1000;
const MAX_RDAP_BYTES = 1 << 20;

/**
 * @typedef {object} AgeInfo
 * @property {number} ageDays Số ngày kể từ khi đăng ký (không âm).
 * @property {string} org Tổ chức đăng ký nếu có (chỉ ghi nhận, không dùng để giảm điểm).
 * @property {boolean} fromCache Lấy từ cache cục bộ.
 */

/**
 * @typedef {object} CacheRecord
 * @property {number | null} created Mốc đăng ký (ms epoch) hoặc ``null`` nếu lần tra trước thất bại.
 * @property {string} org
 * @property {number} fetched Mốc tra (ms epoch).
 */

/**
 * @typedef {object} AgeCache
 * @property {(domain: string) => Promise<CacheRecord | null>} get
 * @property {(domain: string, record: CacheRecord) => Promise<void>} put
 */

/**
 * @typedef {object} LookupOptions
 * @property {number} [timeoutMs] Tổng thời gian tối đa.
 * @property {number} [ttlHours] Thời hạn cache cho kết quả thành công.
 * @property {Record<string, string> | null} [bootstrap] Bảng ``{tld: URL gốc}``.
 * @property {AgeCache | null} [cache]
 * @property {typeof fetch} [fetchImpl]
 * @property {() => number} [now] Đồng hồ (ms epoch), thay được khi kiểm thử.
 */

/**
 * Đọc ngày đăng ký RDAP (ISO 8601) hoặc dạng ``YYYY-MM-DD``/``YYYY.MM.DD``/``YYYY/MM/DD``; lỗi trả ``null``.
 * Ngày không có múi giờ được coi là UTC (như bản Desktop).
 * @param {string} text
 * @returns {Date | null}
 */
export function parseRegistrationDate(text) {
  const value = String(text).trim().split(" (", 1)[0].trim();
  if (!value) return null;
  const match = /^(\d{4})[-./](\d{2})[-./](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(value);
  if (!match) return null;
  const [, y, mo, d, h = "0", mi = "0", s = "0", frac = "", zone] = match;
  const ms = frac ? Math.round(Number(`0${frac}`) * 1000) : 0;
  let time = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms);
  const check = new Date(time);
  if (check.getUTCFullYear() !== Number(y) || check.getUTCMonth() !== Number(mo) - 1 || check.getUTCDate() !== Number(d)) {
    return null;
  }
  if (zone && zone.toUpperCase() !== "Z") {
    const sign = zone[0] === "-" ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    time -= sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4))) * 60000;
  }
  return Number.isFinite(time) ? new Date(time) : null;
}

/**
 * Đọc bảng IANA RDAP bootstrap thành ``{tld: URL gốc https kết thúc bằng /}``.
 * @param {unknown} data
 * @returns {Record<string, string>}
 * @throws {TypeError} Thiếu danh sách ``services``.
 */
export function parseBootstrap(data) {
  const services = /** @type {any} */ (data)?.services;
  if (!Array.isArray(services)) throw new TypeError("Bảng RDAP bootstrap thiếu 'services'");
  /** @type {Record<string, string>} */
  const table = {};
  for (const service of services) {
    if (!Array.isArray(service) || service.length < 2 || !Array.isArray(service[0]) || !Array.isArray(service[1])) continue;
    let base = service[1].find((/** @type {unknown} */ u) => typeof u === "string" && u.toLowerCase().startsWith("https://"));
    if (typeof base !== "string") continue;
    if (!base.endsWith("/")) base += "/";
    for (const tld of service[0]) if (typeof tld === "string" && tld) table[tld.toLowerCase().replace(/^\.+|\.+$/g, "")] = base;
  }
  return table;
}

/**
 * URL RDAP cho ``domain``: máy chủ nhà đăng ký theo bảng IANA, hoặc rdap.org.
 * @param {string} domain
 * @param {Record<string, string> | null | undefined} bootstrap
 * @returns {string}
 */
export function rdapUrl(domain, bootstrap) {
  const tld = domain.slice(domain.lastIndexOf(".") + 1).toLowerCase();
  const base = bootstrap && Object.prototype.hasOwnProperty.call(bootstrap, tld) ? bootstrap[tld] : null;
  return base ? `${base}domain/${domain}` : `${RDAP_FALLBACK}${domain}`;
}

/**
 * Lấy ngày đăng ký sớm nhất và tổ chức đăng ký từ phản hồi RDAP.
 * @param {unknown} data
 * @returns {{created: Date | null, org: string}}
 * @throws {TypeError} Phản hồi không phải object.
 */
export function parseRdap(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new TypeError("Phản hồi RDAP không phải object");
  const record = /** @type {Record<string, any>} */ (data);
  /** @type {Date | null} */
  let created = null;
  for (const event of Array.isArray(record.events) ? record.events : []) {
    if (event && typeof event === "object" && event.eventAction === "registration") {
      const candidate = parseRegistrationDate(String(event.eventDate ?? ""));
      if (candidate !== null && (created === null || candidate < created)) created = candidate;
    }
  }
  let org = "";
  for (const entity of Array.isArray(record.entities) ? record.entities : []) {
    if (!entity || typeof entity !== "object" || !(Array.isArray(entity.roles) && entity.roles.includes("registrant"))) continue;
    const vcard = entity.vcardArray;
    if (Array.isArray(vcard) && vcard.length > 1 && Array.isArray(vcard[1])) {
      for (const item of vcard[1]) {
        if (Array.isArray(item) && item.length > 3 && (item[0] === "fn" || item[0] === "org")) {
          org = Array.isArray(item[3]) ? item[3].map(String).join(" ") : String(item[3]);
        }
      }
    }
  }
  return { created, org };
}

/**
 * Đọc thân phản hồi với giới hạn dung lượng.
 * @param {Response} response
 * @param {number} limit
 * @returns {Promise<string>}
 * @throws {RangeError} Phản hồi quá lớn.
 */
export async function readLimited(response, limit) {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > limit) throw new RangeError("Phản hồi quá lớn");
  if (!response.body) return "";
  const reader = response.body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new RangeError("Phản hồi quá lớn");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(merged);
}

/**
 * Tra tuổi tên miền đăng ký được của ``host``.
 * @param {string} host Host ASCII chữ thường.
 * @param {LookupOptions} [options]
 * @returns {Promise<AgeInfo | null>} ``null`` nếu host là IP/hậu tố công cộng, hết giờ hay không tra được.
 */
export async function lookupAge(host, options = {}) {
  const {
    timeoutMs = 1800, ttlHours = 48, bootstrap = null, cache = null, fetchImpl = fetch, now = Date.now,
  } = options;
  if (!host || isIp(host)) return null;
  const domain = defaultPsl().lookup(host).registrable;
  if (domain === null) return null;
  const started = now();
  if (cache) {
    try {
      const hit = await cache.get(domain);
      if (hit && typeof hit.fetched === "number") {
        const ttl = hit.created !== null ? ttlHours * 3600 * 1000 : FAILURE_TTL_MS;
        if (started - hit.fetched < ttl) {
          if (hit.created === null) return null;
          return { ageDays: Math.max(0, (started - hit.created) / 86400000), org: hit.org || "", fromCache: true };
        }
      }
    } catch (error) {
      console.warn("CHOTTO: đọc cache Tầng 3 lỗi", error);
    }
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(100, timeoutMs));
  /** @type {{created: Date | null, org: string} | null} */
  let parsed = null;
  let answered = false;
  // Máy chủ nhà đăng ký trước; lỗi mạng/CORS thì thử rdap.org trong thời gian còn lại.
  const urls = [...new Set([rdapUrl(domain, bootstrap), `${RDAP_FALLBACK}${domain}`])];
  try {
    for (const url of urls) {
      try {
        const response = await fetchImpl(url, {
          headers: { Accept: "application/rdap+json" },
          signal: controller.signal,
          credentials: "omit",
          redirect: "follow",
          cache: "no-store",
        });
        answered = true;
        if (response.ok) parsed = parseRdap(JSON.parse(await readLimited(response, MAX_RDAP_BYTES)));
        break;
      } catch (error) {
        if (controller.signal.aborted) break;
        answered = false;
        console.info("CHOTTO: Tầng 3 lỗi với", url, error);
      }
    }
  } finally {
    clearTimeout(timer);
  }
  const created = parsed?.created ?? null;
  const org = parsed?.org ?? "";
  if (cache && (created !== null || (answered && !controller.signal.aborted))) {
    try {
      await cache.put(domain, { created: created ? created.getTime() : null, org, fetched: started });
    } catch (error) {
      console.warn("CHOTTO: ghi cache Tầng 3 lỗi", error);
    }
  }
  if (created === null) return null;
  return { ageDays: Math.max(0, (started - created.getTime()) / 86400000), org, fromCache: false };
}
