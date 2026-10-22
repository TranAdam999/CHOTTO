// @ts-check
/**
 * Tiện ích dùng chung: tên miền, khoảng cách chỉnh sửa, homoglyph, chuẩn hóa tiếng Việt, entropy.
 * Tương đương ``chotto.util`` (cùng thuật toán, cùng bảng dữ liệu).
 * @module engine/util
 */

import { PublicSuffixList } from "./psl.js";

/** Cặp nhiều ký tự trông giống một ký tự (áp dụng trước bảng một-ký-tự). */
const MULTI_CHAR_HOMOGLYPHS = /** @type {const} */ ([["rn", "m"], ["vv", "w"], ["nn", "m"]]);
/** Chữ số thay chữ cái thường gặp trong tên miền giả mạo. */
const ASCII_HOMOGLYPHS = Object.freeze(/** @type {Record<string, string>} */ ({
  0: "o", 1: "l", 3: "e", 5: "s", 4: "a", 7: "t", 8: "b",
}));
const NON_ALNUM_RE = /[^a-z0-9]+/g;
const COMBINING_MARK_RE = /\p{Mn}/gu;
// eslint-disable-next-line no-control-regex
const BIDI_INVISIBLE_RE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/gu;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** @type {PublicSuffixList | null} */
let pslInstance = null;
/** @type {Map<string, string>} */
let confusables = new Map();

/**
 * Nạp dữ liệu dùng chung (gọi một lần khi khởi động service worker / kiểm thử).
 * @param {{psl: PublicSuffixList, confusables: Record<string, string>}} data
 */
export function configureUtil(data) {
  pslInstance = data.psl;
  confusables = new Map(Object.entries(data.confusables).map(([k, v]) => [String(k), String(v)]));
}

/**
 * PSL đã nạp.
 * @returns {PublicSuffixList}
 * @throws {Error} Chưa gọi ``configureUtil``.
 */
export function defaultPsl() {
  if (pslInstance === null) throw new Error("Chưa nạp Public Suffix List (configureUtil)");
  return pslInstance;
}

/**
 * ``true`` nếu ``host`` là địa chỉ IPv4 (dạng chuẩn) hoặc IPv6 (có/không ngoặc vuông).
 * @param {string} host
 * @returns {boolean}
 */
export function isIp(host) {
  const bare = host.replace(/^\[|\]$/g, "");
  if (IPV4_RE.test(bare)) return true;
  if (!bare.includes(":")) return false;
  try {
    return new URL(`http://[${bare}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/**
 * Hậu tố công cộng của ``host``.
 * @param {string} host
 * @returns {string}
 */
export function publicSuffix(host) {
  return defaultPsl().lookup(host).suffix;
}

/**
 * Tên miền đăng ký được; trả về chính ``host`` nếu là IP hoặc bản thân là hậu tố công cộng.
 * @param {string} host
 * @returns {string}
 */
export function registeredDomain(host) {
  if (!host || isIp(host)) return host;
  return defaultPsl().lookup(host).registrable || host;
}

/**
 * ``true`` nếu host nằm dưới hậu tố PRIVATE (``web.app``, ``github.io``...).
 * @param {string} host
 * @returns {boolean}
 */
export function isPrivateSuffixHost(host) {
  if (!host || isIp(host)) return false;
  return defaultPsl().lookup(host).isPrivate;
}

/**
 * Nhãn cuối cùng (TLD), chữ thường.
 * @param {string} host
 * @returns {string}
 */
export function tldOf(host) {
  const labels = host.replace(/\.+$/, "").split(".");
  return labels[labels.length - 1].toLowerCase();
}

/**
 * ``true`` nếu ``host`` bằng ``domain`` hoặc là subdomain của nó.
 * @param {string} host
 * @param {string} domain
 * @returns {boolean}
 */
export function inDomain(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

/**
 * ``host`` và các tên miền cha, dừng ở tên miền đăng ký được.
 * @param {string} host
 * @returns {string[]}
 */
export function parentDomains(host) {
  if (!host) return [];
  const out = [host];
  if (isIp(host)) return out;
  const registrable = defaultPsl().lookup(host).registrable;
  if (registrable === null || registrable === host) return out;
  const labels = host.split(".");
  const stop = registrable.split(".").length;
  for (let index = 1; index <= labels.length - stop; index += 1) out.push(labels.slice(index).join("."));
  return out;
}

/**
 * Chữ thường giống ``str.lower()`` của Python (khác JS ở vài ký tự đặc biệt như ``İ``).
 * @param {string} text
 * @returns {string}
 */
export function pyLower(text) {
  return text.replace(/İ/g, "i̇").toLowerCase();
}

/**
 * Bỏ dấu tiếng Việt: ``xác nhận`` → ``xac nhan``; ``đ``/``Đ`` → ``d``/``D``.
 * @param {string} text
 * @returns {string}
 */
export function foldVietnamese(text) {
  return text.replace(/đ/g, "d").replace(/Đ/g, "D").normalize("NFD").replace(COMBINING_MARK_RE, "").normalize("NFC");
}

/**
 * Dạng "khung xương" để so khớp mạo danh (NFKC, chữ thường, confusables, bỏ dấu, rn→m, 0→o...).
 * @param {string} text
 * @returns {string}
 */
export function skeleton(text) {
  const lowered = pyLower(text.normalize("NFKC"));
  let mapped = Array.from(lowered, (ch) => confusables.get(ch) ?? ch).join("");
  mapped = foldVietnamese(mapped);
  for (const [source, target] of MULTI_CHAR_HOMOGLYPHS) mapped = mapped.split(source).join(target);
  return Array.from(mapped, (ch) => ASCII_HOMOGLYPHS[ch] ?? ch).join("");
}

/**
 * Khoảng cách Damerau–Levenshtein dạng OSA (tính trên code point).
 * @param {string} a
 * @param {string} b
 * @param {number | null} [maxDistance] Dừng sớm, trả ``maxDistance + 1`` khi chắc chắn vượt ngưỡng.
 * @returns {number}
 */
export function damerauLevenshtein(a, b, maxDistance = null) {
  if (a === b) return 0;
  const x = Array.from(a);
  const y = Array.from(b);
  if (maxDistance !== null && Math.abs(x.length - y.length) > maxDistance) return maxDistance + 1;
  const cols = y.length + 1;
  /** @type {number[]} */
  let twoBack = [];
  let previous = Array.from({ length: cols }, (_, j) => j);
  for (let i = 1; i <= x.length; i += 1) {
    const current = new Array(cols).fill(0);
    current[0] = i;
    for (let j = 1; j < cols; j += 1) {
      const cost = x[i - 1] === y[j - 1] ? 0 : 1;
      let value = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost);
      if (i > 1 && j > 1 && x[i - 1] === y[j - 2] && x[i - 2] === y[j - 1]) value = Math.min(value, twoBack[j - 2] + 1);
      current[j] = value;
    }
    if (maxDistance !== null && Math.min(...current) > maxDistance) return maxDistance + 1;
    twoBack = previous;
    previous = current;
  }
  return previous[cols - 1];
}

/**
 * Giải mã ``%XX`` như ``urllib.parse.unquote`` (UTF-8, byte hỏng thành U+FFFD, ``%`` lẻ giữ nguyên).
 * @param {string} text
 * @returns {string}
 */
export function unquote(text) {
  if (!text.includes("%")) return text;
  const decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
  return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    return decoder.decode(bytes);
  });
}

/**
 * Chuẩn hóa văn bản URL để so từ khóa tiếng Việt: ``/X%C3%A1c_Nh%E1%BA%ADn`` → ``xac-nhan``.
 * @param {string} text
 * @param {number} [maxUnquoteRounds]
 * @returns {string} Chỉ gồm ``[a-z0-9-]``, không có ``-`` ở đầu/cuối.
 */
export function normalizeForMatching(text, maxUnquoteRounds = 3) {
  let decoded = text;
  for (let round = 0; round < maxUnquoteRounds; round += 1) {
    const next = unquote(decoded);
    if (next === decoded) break;
    decoded = next;
  }
  const folded = foldVietnamese(pyLower(decoded.normalize("NFC")));
  return folded.replace(NON_ALNUM_RE, "-").replace(/^-+|-+$/g, "");
}

/**
 * Thay ký tự điều khiển, vô hình và đảo chiều văn bản (U+202E...) bằng U+FFFD trước khi hiển thị.
 * @param {string} text
 * @returns {string}
 */
export function sanitizeForDisplay(text) {
  return String(text).replace(BIDI_INVISIBLE_RE, "�");
}

/**
 * Entropy Shannon (bit/ký tự); chuỗi rỗng cho 0.
 * @param {string} text
 * @returns {number}
 */
export function shannonEntropy(text) {
  const chars = Array.from(text);
  if (chars.length === 0) return 0;
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const ch of chars) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let total = 0;
  for (const count of counts.values()) {
    const p = count / chars.length;
    total -= p * Math.log2(p);
  }
  return total;
}

/**
 * Làm tròn kiểu ngân hàng giống ``round()`` của Python (0.5 → 0, 1.5 → 2, 2.5 → 2).
 * @param {number} value
 * @returns {number}
 */
export function roundHalfEven(value) {
  const floor = Math.floor(value);
  const diff = value - floor;
  if (diff > 0.5) return floor + 1;
  if (diff < 0.5) return floor;
  return floor % 2 === 0 ? floor : floor + 1;
}
