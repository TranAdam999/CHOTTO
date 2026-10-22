// @ts-check
/**
 * Tầng 2 – Heuristics bản địa hóa tiếng Việt, chạy hoàn toàn trong trình duyệt.
 *
 * Bản chuyển thể 1-1 của ``chotto/tier2.py``: cùng bộ luật ``rules.json``, cùng thứ tự dấu hiệu, cùng
 * điểm. Bộ test dùng chung ``tests/data/engine_vectors.json`` bảo đảm hai bản cho cùng kết quả.
 * @module engine/tier2
 */

import { domainToUnicode } from "./punycode.js";
import { ParsedURL, URLParseError, parseUrl } from "./url.js";
import {
  damerauLevenshtein,
  defaultPsl,
  foldVietnamese,
  inDomain,
  isPrivateSuffixHost,
  normalizeForMatching,
  pyLower,
  registeredDomain,
  shannonEntropy,
  skeleton,
  tldOf,
  unquote,
} from "./util.js";

const TOKEN_SPLIT_RE = /[-_]+/;
const GOVERNMENT_LABELS = new Set(["gov", "govt", "gob", "gouv", "mil"]);
const MAX_EMBEDDED = 5;
const PY_WHITESPACE = "\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_STRIP_RE = new RegExp(`^[${PY_WHITESPACE}]+|[${PY_WHITESPACE}]+$`, "g");
const PY_SPLIT_RE = new RegExp(`[${PY_WHITESPACE}]+`);
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const DIGIT_RE = /\p{Nd}/u;

/**
 * @typedef {object} Signal
 * @property {string} code Mã dấu hiệu (``combosquat``, ``lure``...).
 * @property {number} points Điểm.
 * @property {string} reason Lý do tiếng Việt hiển thị cho người dùng.
 * @property {string} brand Thương hiệu bị mạo danh (nếu có).
 */

/**
 * @typedef {object} UnwrapResult
 * @property {ParsedURL} final URL đích cuối cùng.
 * @property {ParsedURL[]} chain Chuỗi URL từ link gốc tới đích.
 * @property {boolean} exhausted Đã bóc tới giới hạn mà đích vẫn là link bọc.
 */

/**
 * @typedef {object} Tier2Result
 * @property {number} score Tổng điểm 0–100.
 * @property {Signal[]} signals Các dấu hiệu.
 * @property {ParsedURL} final URL được chấm điểm.
 * @property {ParsedURL[]} chain Chuỗi URL.
 * @property {boolean} trusted Đích thuộc tên miền tin cậy.
 */

/**
 * @typedef {{[key: string]: any, popularDomains?: Set<string>}} Rules
 */

/**
 * @param {string} code
 * @param {number} points
 * @param {string} reason
 * @param {string} [brand]
 * @returns {Signal}
 */
function signal(code, points, reason, brand = "") {
  return { code, points: Math.trunc(Number(points)), reason, brand };
}

/**
 * ``str.strip()`` của Python (khoảng trắng Unicode theo ``str.isspace``).
 * @param {string} text
 * @returns {string}
 */
export function pyStrip(text) {
  return text.replace(PY_STRIP_RE, "");
}

/**
 * ``urllib.parse.parse_qsl`` (dấu phân cách ``&``, ``+`` là khoảng trắng).
 * @param {string} query
 * @param {boolean} keepBlankValues
 * @returns {[string, string][]}
 */
export function parseQsl(query, keepBlankValues) {
  /** @type {[string, string][]} */
  const pairs = [];
  for (const nameValue of query.split("&")) {
    if (!nameValue) continue;
    const eq = nameValue.indexOf("=");
    let name;
    let value;
    if (eq < 0) {
      if (!keepBlankValues) continue;
      name = nameValue;
      value = "";
    } else {
      name = nameValue.slice(0, eq);
      value = nameValue.slice(eq + 1);
    }
    if (value.length || keepBlankValues) {
      pairs.push([unquote(name.replace(/\+/g, " ")), unquote(value.replace(/\+/g, " "))]);
    }
  }
  return pairs;
}

/**
 * Giải base64 như ``base64.b64decode(..., validate=True)`` rồi đọc UTF-8 nghiêm ngặt.
 * @param {string} text Chuỗi đã đệm ``=`` và đổi bảng chữ URL-safe sang chuẩn.
 * @returns {string | null} Chuỗi giải mã, hoặc ``null`` nếu không phải base64/UTF-8 hợp lệ.
 */
function decodeBase64Utf8(text) {
  if (!BASE64_RE.test(text)) return null;
  const data = text.replace(/=+$/, "");
  if (data.length % 4 === 1) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  /** @type {number[]} */
  const bytes = [];
  let quad = 0;
  let left = 0;
  for (const ch of data) {
    const value = alphabet.indexOf(ch);
    if (quad === 0) {
      left = value;
      quad = 1;
    } else if (quad === 1) {
      bytes.push(((left << 2) | (value >> 4)) & 0xff);
      left = value & 0x0f;
      quad = 2;
    } else if (quad === 2) {
      bytes.push(((left << 4) | (value >> 2)) & 0xff);
      left = value & 0x03;
      quad = 3;
    } else {
      bytes.push(((left << 6) | value) & 0xff);
      quad = 0;
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(new Uint8Array(bytes));
  } catch (error) {
    if (error instanceof TypeError) return null;
    throw error;
  }
}

/**
 * Phân tích ``candidate`` nếu là URL http(s) hợp lệ.
 * @param {string} candidate
 * @returns {ParsedURL | null}
 */
function tryParse(candidate) {
  let text = pyStrip(candidate);
  if (text.startsWith("//")) text = `https:${text}`;
  const lowered = pyLower(text);
  if (!lowered.startsWith("http://") && !lowered.startsWith("https://")) return null;
  try {
    return parseUrl(text);
  } catch (error) {
    if (error instanceof URLParseError) return null;
    throw error;
  }
}

/**
 * Đọc ``value`` (tham số của link bọc) thành URL http(s): nguyên bản, mã hóa ``%`` thêm 1–2 lớp, base64.
 * @param {string} value
 * @returns {ParsedURL | null}
 */
export function extractUrl(value) {
  const candidates = [value];
  for (let i = 0; i < 2; i += 1) candidates.push(unquote(candidates[candidates.length - 1]));
  const raw = pyStrip(value);
  if (raw && raw.length <= 8192) {
    const padded = raw + "=".repeat((4 - (raw.length % 4)) % 4);
    const decoded = decodeBase64Utf8(padded.replace(/-/g, "+").replace(/_/g, "/"));
    if (decoded !== null) candidates.push(decoded);
  }
  for (const candidate of candidates) {
    const parsed = tryParse(candidate);
    if (parsed !== null) return parsed;
  }
  return null;
}

/**
 * @param {ParsedURL} url
 * @param {Record<string, any>} wrapper
 * @returns {boolean}
 */
function wrapperMatches(url, wrapper) {
  const host = String(wrapper.host);
  const hostOk = wrapper.match === "suffix" ? inDomain(url.host, host) : url.host === host;
  return hostOk && url.path.startsWith(String(wrapper.path));
}

/**
 * Đích của link bọc.
 * @param {ParsedURL} url
 * @param {Rules} rules
 * @returns {[boolean, ParsedURL | null]} (url có phải link bọc không, URL đích nếu bóc được)
 */
function wrapperTarget(url, rules) {
  const queryPairs = parseQsl(url.query ?? "", true);
  let isWrapper = false;
  for (const wrapper of rules.wrappers) {
    if (!wrapperMatches(url, wrapper)) continue;
    const targetKind = wrapper.target ?? "params";
    if (targetKind === "path") {
      isWrapper = true;
      const rest = url.path.slice(String(wrapper.path).length);
      const scheme = String(wrapper.scheme ?? "https");
      const parsed = tryParse(`${scheme}://${rest}${url.query ? `?${url.query}` : ""}`);
      if (parsed !== null) return [true, parsed];
    } else if (targetKind === "query") {
      isWrapper = true;
      const parsed = extractUrl(unquote(url.query ?? ""));
      if (parsed !== null) return [true, parsed];
    } else {
      const names = (wrapper.params ?? []).map(String);
      const wildcard = names.includes("*");
      const ordered = names.filter((/** @type {string} */ n) => n !== "*");
      if (wildcard) for (const [key] of queryPairs) if (!ordered.includes(key)) ordered.push(key);
      for (const name of ordered) {
        for (const [key, value] of queryPairs) {
          if (key !== name) continue;
          if (!wildcard) isWrapper = true;
          const parsed = extractUrl(value);
          if (parsed !== null) return [true, parsed];
        }
      }
    }
  }
  return [isWrapper, null];
}

/**
 * Bóc các lớp link bọc trung gian (``l.facebook.com``, ``google.com/url``, ``zalo.me``...).
 * @param {string | ParsedURL} url
 * @param {Rules} rules
 * @param {number | null} [depth]
 * @returns {UnwrapResult}
 * @throws {URLParseError} ``url`` là chuỗi không phân tích được.
 */
export function unwrap(url, rules, depth = null) {
  let current = url instanceof ParsedURL ? url : parseUrl(url);
  const limit = Math.trunc(Number(depth ?? rules.thresholds.unwrap_depth));
  const chain = [current];
  const seen = new Set([current.href]);
  for (let i = 0; i < limit; i += 1) {
    const [, target] = wrapperTarget(current, rules);
    if (target === null || seen.has(target.href)) return { final: current, chain, exhausted: false };
    current = target;
    chain.push(current);
    seen.add(current.href);
  }
  const [stillWrapped] = wrapperTarget(current, rules);
  return { final: current, chain, exhausted: stillWrapped };
}

/**
 * URL http(s) nhúng trong tham số truy vấn (khác tên miền đăng ký với ``url``).
 * @param {ParsedURL} url
 * @param {number} [limit]
 * @returns {ParsedURL[]}
 */
export function embeddedUrls(url, limit = MAX_EMBEDDED) {
  /** @type {ParsedURL[]} */
  const found = [];
  const own = registeredDomain(url.host);
  for (const [, value] of parseQsl(url.query ?? "", false)) {
    const parsed = extractUrl(value);
    if (parsed !== null && registeredDomain(parsed.host) !== own) {
      found.push(parsed);
      if (found.length >= limit) break;
    }
  }
  return found;
}

/**
 * Host thuộc danh sách tin cậy, tên miền chính thức của thương hiệu, hoặc tên miền .vn phổ biến.
 * @param {string} host
 * @param {Rules} rules
 * @returns {boolean}
 */
export function isTrusted(host, rules) {
  if (rules.trusted_domains.some((/** @type {string} */ d) => inDomain(host, d))) return true;
  for (const brand of rules.brands) if (brand.domains.some((/** @type {string} */ d) => inDomain(host, d))) return true;
  const popular = rules.popularDomains;
  return popular instanceof Set && popular.has(registeredDomain(host));
}

/**
 * Các nhãn do người đăng ký kiểm soát (bỏ hậu tố công cộng).
 * @param {string} host
 * @returns {string[]}
 */
export function attackerLabels(host) {
  const info = defaultPsl().lookup(host);
  const labels = host.split(".");
  const suffixLen = info.suffix ? info.suffix.split(".").length : 0;
  return suffixLen < labels.length ? labels.slice(0, labels.length - suffixLen) : [];
}

/** @type {WeakMap<object, Set<string>>} */
const affixCache = new WeakMap();

/**
 * @param {Rules} rules
 * @returns {Set<string>}
 */
function affixSet(rules) {
  let cached = affixCache.get(rules.brand_affixes);
  if (!cached) {
    cached = new Set(rules.brand_affixes.map(String).filter(Boolean).map(pyLower));
    affixCache.set(rules.brand_affixes, cached);
  }
  return cached;
}

/**
 * ``text`` ghép được hoàn toàn từ các phụ tố và cụm chữ số.
 * @param {string} text
 * @param {Set<string>} affixes
 * @returns {boolean}
 */
function isAffixSequence(text, affixes) {
  if (!text) return true;
  const reachable = new Array(text.length + 1).fill(false);
  reachable[0] = true;
  for (let start = 0; start < text.length; start += 1) {
    if (!reachable[start]) continue;
    let end = start;
    while (end < text.length && DIGIT_RE.test(text[end])) {
      end += 1;
      reachable[end] = true;
    }
    for (const affix of affixes) if (text.startsWith(affix, start)) reachable[start + affix.length] = true;
  }
  return reachable[text.length];
}

/**
 * @param {string} token
 * @param {string} keyword
 * @param {Set<string>} affixes
 * @returns {boolean}
 */
function shortKeywordMatch(token, keyword, affixes) {
  if (token === keyword) return true;
  if (token.startsWith(keyword)) return isAffixSequence(token.slice(keyword.length), affixes);
  if (token.endsWith(keyword)) return isAffixSequence(token.slice(0, token.length - keyword.length), affixes);
  return false;
}

/**
 * @param {string} token
 * @param {string} keyword
 * @param {Set<string>} affixes
 * @returns {boolean}
 */
function keywordIn(token, keyword, affixes) {
  if (Array.from(keyword).length >= 5) return token.includes(keyword);
  return shortKeywordMatch(token, keyword, affixes);
}

/**
 * @param {string} label
 * @returns {string[]}
 */
function tokensOf(label) {
  return [...label.split(TOKEN_SPLIT_RE).filter(Boolean), label.replace(/-/g, "").replace(/_/g, "")];
}

/**
 * Dấu hiệu mạo danh thương hiệu mạnh nhất (combosquat / homoglyph / typosquat).
 * @param {string[]} labels
 * @param {Rules} rules
 * @returns {Signal | null}
 */
function brandSignal(labels, rules) {
  const weights = rules.weights;
  const affixes = affixSet(rules);
  /** @type {string[]} */
  const asciiTokens = [];
  /** @type {string[]} */
  const unicodeTokens = [];
  for (const label of labels) {
    asciiTokens.push(...tokensOf(label));
    unicodeTokens.push(...tokensOf(domainToUnicode(label)));
  }
  /** @type {Signal | null} */
  let best = null;
  /** @param {Signal} candidate */
  const consider = (candidate) => {
    if (best === null || candidate.points > best.points) best = candidate;
  };
  for (const brand of rules.brands) {
    const name = String(brand.name);
    for (const rawKeyword of brand.keywords) {
      const keyword = pyLower(String(rawKeyword));
      let rawHit = false;
      for (const token of asciiTokens) {
        if (!token.startsWith("xn--") && keywordIn(token, keyword, affixes)) {
          rawHit = true;
          consider(signal("combosquat", weights.combosquat,
            `Tên miền chứa tên “${name}” nhưng không phải trang chính thức`, name));
          break;
        }
      }
      if (rawHit) continue;
      for (const token of unicodeTokens) {
        const plain = foldVietnamese(pyLower(token));
        const shape = skeleton(token);
        if (shape !== plain && keywordIn(shape, keyword, affixes)) {
          consider(signal("homoglyph", weights.homoglyph,
            `Dùng ký tự đánh lừa thị giác (0/o, 1/l, rn/m, chữ Nga…) để mạo danh ${name}`, name));
          break;
        }
      }
      const keywordLength = Array.from(keyword).length;
      if (keywordLength < 5) continue;
      const threshold = keywordLength < 8 ? 1 : 2;
      for (const token of asciiTokens) {
        const tokenLength = Array.from(token).length;
        if (tokenLength < 5 || Math.abs(tokenLength - keywordLength) > 2) continue;
        const distance = damerauLevenshtein(token, keyword, threshold);
        if (distance > 0 && distance <= threshold) {
          consider(signal("typosquat", weights.typosquat,
            `Dấu hiệu mạo danh thương hiệu ${name} (sai lệch ${distance} ký tự)`, name));
          break;
        }
      }
    }
  }
  return best;
}

/**
 * Từ khóa bẫy tâm lý tiếng Việt trong tên miền, đường dẫn và truy vấn.
 * @param {string[]} labels
 * @param {ParsedURL} url
 * @param {Rules} rules
 * @returns {Signal | null}
 */
function lureSignal(labels, url, rules) {
  const weights = rules.weights;
  const hostText = normalizeForMatching(labels.map((label) => domainToUnicode(label)).join("-"));
  const hostFlat = hostText.replace(/-/g, "");
  const pathText = normalizeForMatching(url.pathAndQuery);
  const pathFlat = pathText.replace(/-/g, "");
  const paddedHost = `-${hostText}-`;
  const paddedPath = `-${pathText}-`;
  /** @type {Map<string, string>} */
  const found = new Map();
  for (const rawKeyword of rules.lure_keywords) {
    const display = String(rawKeyword).split(PY_SPLIT_RE).filter(Boolean).join(" ");
    const keyword = normalizeForMatching(display);
    if (!keyword || found.has(keyword)) continue;
    const flat = keyword.replace(/-/g, "");
    if (
      paddedHost.includes(`-${keyword}-`)
      || paddedPath.includes(`-${keyword}-`)
      || (flat.length >= 6 && hostFlat.includes(flat))
      || (flat.length >= 7 && pathFlat.includes(flat))
    ) {
      found.set(keyword, display);
    }
  }
  if (found.size === 0) return null;
  const keys = [...found.keys()];
  const distinct = keys.filter((k) => !keys.some((other) => k !== other && other.includes(k)));
  const points = Math.min(Math.trunc(weights.lure_cap), Math.trunc(weights.lure_each) * distinct.length);
  return signal("lure", points, `Chứa từ khóa gây hoang mang: “${found.get(distinct[0])}”`);
}

/**
 * @param {string} text
 * @returns {string}
 */
function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Tên miền chính thức của thương hiệu nằm trong đường dẫn/truy vấn (``evil.top/vietcombank.com.vn/``).
 * @param {ParsedURL} url
 * @param {Rules} rules
 * @returns {Signal | null}
 */
function brandDomainInPath(url, rules) {
  const text = pyLower(unquote(url.pathAndQuery));
  for (const brand of rules.brands) {
    for (const domain of brand.domains) {
      const pattern = new RegExp(`(?<![a-z0-9-])${escapeRegExp(pyLower(String(domain)))}(?![a-z0-9-])`);
      if (pattern.test(text)) {
        const name = String(brand.name);
        return signal("brand_in_path", rules.weights.brand_in_path,
          `Đường dẫn chèn địa chỉ ${domain} để giả làm trang của ${name}`, name);
      }
    }
  }
  return null;
}

/**
 * TLD rủi ro, IDN, entropy, gạch ngang, chữ số ngẫu nhiên, hosting miễn phí.
 * @param {string[]} labels
 * @param {string} host
 * @param {Rules} rules
 * @returns {Signal[]}
 */
function lexicalSignals(labels, host, rules) {
  const { weights, thresholds } = rules;
  /** @type {Signal[]} */
  const signals = [];
  const tld = tldOf(host);
  if (rules.high_risk_tlds.includes(tld)) {
    signals.push(signal("tld", weights.high_risk_tld, `Đuôi .${tld} thường bị lạm dụng để lừa đảo`));
  }
  if (labels.some((label) => label.startsWith("xn--"))) {
    signals.push(signal("idn", weights.idn, "Tên miền dùng ký tự Unicode dễ giả mạo"));
  }
  const plainLabels = labels.filter((label) => !label.startsWith("xn--"));
  const joined = plainLabels.map((label) => label.replace(/-/g, "")).join("");
  const joinedLength = Array.from(joined).length;
  if (joinedLength >= 8 && shannonEntropy(joined) > Number(thresholds.entropy)) {
    signals.push(signal("entropy", weights.entropy, "Tên miền trông như chuỗi ký tự ngẫu nhiên"));
  }
  const hyphens = plainLabels.reduce((sum, label) => sum + (label.match(/-/g)?.length ?? 0), 0);
  if (hyphens >= Math.trunc(thresholds.hyphens)) {
    signals.push(signal("hyphens", weights.hyphens, "Tên miền có nhiều dấu gạch ngang bất thường"));
  }
  const digits = Array.from(joined).filter((ch) => DIGIT_RE.test(ch)).length;
  if (digits >= 3 && digits / Math.max(joinedLength, 1) > 0.3) {
    signals.push(signal("digits", weights.random_digits, "Tên miền chứa nhiều chữ số ngẫu nhiên"));
  }
  if (isPrivateSuffixHost(host)
      && !defaultPsl().lookup(host).suffix.split(".").some((label) => GOVERNMENT_LABELS.has(label))) {
    signals.push(signal("free_hosting", weights.free_hosting,
      "Trang nằm trên nền tảng tạo web miễn phí, ai cũng lập được trong vài phút"));
  }
  return signals;
}

/**
 * Chấm điểm một URL không thuộc tên miền tin cậy.
 * @param {ParsedURL} url
 * @param {ParsedURL[]} chain
 * @param {boolean} exhausted
 * @param {Rules} rules
 * @returns {Signal[]}
 */
function scoreUrl(url, chain, exhausted, rules) {
  const weights = rules.weights;
  /** @type {Signal[]} */
  const signals = [];
  if (exhausted) {
    signals.push(signal("nested_redirect", weights.nested_redirect,
      "Liên kết bị bọc qua quá nhiều lớp chuyển hướng để che đích thật"));
  }
  if (url.scheme === "http") signals.push(signal("http", weights.http, "Liên kết không mã hóa (http://)"));
  if (chain.some((item) => item.hasCredentials)) {
    signals.push(signal("at_sign", weights.at_sign, "Chứa ký tự @ để che giấu tên miền thật"));
  }
  if (url.port !== null) signals.push(signal("port", weights.port, `Dùng cổng mạng bất thường (:${url.port})`));
  if (rules.shorteners.includes(registeredDomain(url.host)) || rules.shorteners.includes(url.host)) {
    signals.push(signal("shortener", weights.shortener, "Link rút gọn che giấu địa chỉ đích thật"));
  }
  /** @type {string[]} */
  let labels = [];
  if (url.isIp) {
    signals.push(signal("raw_ip", weights.raw_ip, "Dùng địa chỉ IP thay cho tên miền"));
  } else {
    labels = attackerLabels(url.host);
    const brand = brandSignal(labels, rules);
    if (brand !== null) signals.push(brand);
    signals.push(...lexicalSignals(labels, url.host, rules));
  }
  const lure = lureSignal(labels, url, rules);
  if (lure !== null) signals.push(lure);
  const decoy = brandDomainInPath(url, rules);
  if (decoy !== null) signals.push(decoy);
  return signals;
}

/**
 * Tổng điểm kẹp trong 0–100.
 * @param {Signal[]} signals
 * @returns {number}
 */
function total(signals) {
  return Math.max(0, Math.min(100, signals.reduce((sum, s) => sum + s.points, 0)));
}

/**
 * Chấm điểm rủi ro Tầng 2 cho một URL.
 * @param {string | ParsedURL} url
 * @param {Rules} rules
 * @param {UnwrapResult | null} [unwrapped] Kết quả ``unwrap`` đã tính sẵn.
 * @returns {Tier2Result}
 * @throws {URLParseError} ``url`` là chuỗi không phân tích được.
 */
export function analyze(url, rules, unwrapped = null) {
  const result = unwrapped ?? unwrap(url, rules);
  const { final, chain } = result;
  const credentials = chain.some((item) => item.hasCredentials);
  if (!final.isIp && isTrusted(final.host, rules)) {
    for (const embedded of embeddedUrls(final)) {
      if (embedded.isIp || !isTrusted(embedded.host, rules)) {
        const fullChain = [...chain, embedded];
        const signals = scoreUrl(embedded, fullChain, false, rules);
        signals.push(signal("redirect_via_trusted", rules.weights.redirect_via_trusted,
          `Đi qua ${final.host} để chuyển hướng sang ${embedded.host}`));
        return { score: total(signals), signals, final: embedded, chain: fullChain, trusted: false };
      }
    }
    /** @type {Signal[]} */
    const trustedSignals = [];
    if (credentials) trustedSignals.push(signal("at_sign", rules.weights.at_sign, "Chứa ký tự @ để che giấu tên miền thật"));
    if (result.exhausted) {
      trustedSignals.push(signal("nested_redirect", rules.weights.nested_redirect,
        "Liên kết bị bọc qua quá nhiều lớp chuyển hướng để che đích thật"));
    }
    return { score: total(trustedSignals), signals: trustedSignals, final, chain, trusted: true };
  }
  const signals = scoreUrl(final, chain, result.exhausted, rules);
  return { score: total(signals), signals, final, chain, trusted: false };
}
