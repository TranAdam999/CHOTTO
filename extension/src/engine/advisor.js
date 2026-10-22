// @ts-check
/**
 * AI's Advices (riêng tư 100%): lời khuyên sinh cục bộ từ các dấu hiệu, KHÔNG gửi dữ liệu ra ngoài.
 * Văn bản lời khuyên lấy từ ``data/advice.json`` (sinh từ ``chotto/advisor.py``), thuật toán chọn
 * lời khuyên giống hệt bản Desktop: tổ hợp dấu hiệu trước, rồi tới dấu hiệu riêng lẻ mạnh nhất.
 * @module engine/advisor
 */

const BRAND_PLACEHOLDER = /\{brand\}/g;
const DEFAULT_BRAND = "thương hiệu này";
const MAX_TIPS = 2;

/**
 * @typedef {object} AdviceData
 * @property {Record<string, string>} tips Lời khuyên theo mã dấu hiệu.
 * @property {{groups: string[][], text: string}[]} combos Tổ hợp theo thứ tự ưu tiên.
 * @property {string} general Lời khuyên chung luôn được thêm vào cuối.
 */

/**
 * @typedef {{code?: string, points?: number, brand?: string}} SignalLike
 */

/**
 * Kiểm tra cấu trúc ``advice.json``.
 * @param {unknown} data
 * @returns {AdviceData}
 * @throws {TypeError} Sai cấu trúc.
 */
export function validateAdvice(data) {
  const value = /** @type {Record<string, unknown>} */ (data);
  if (!value || typeof value !== "object" || typeof value.general !== "string"
      || !value.tips || typeof value.tips !== "object" || !Array.isArray(value.combos)) {
    throw new TypeError("advice.json sai cấu trúc");
  }
  for (const combo of value.combos) {
    if (!combo || typeof combo.text !== "string" || !Array.isArray(combo.groups)
        || !combo.groups.every((/** @type {unknown} */ g) => Array.isArray(g))) {
      throw new TypeError("advice.json: tổ hợp sai cấu trúc");
    }
  }
  return /** @type {AdviceData} */ (value);
}

/**
 * Thương hiệu của dấu hiệu mạnh nhất thuộc ``codes``.
 * @param {SignalLike[]} ordered
 * @param {Set<string>} codes
 * @returns {string}
 */
function brandOf(ordered, codes) {
  for (const s of ordered) if (codes.has(String(s.code ?? "")) && s.brand) return String(s.brand);
  return DEFAULT_BRAND;
}

/**
 * Ghép tối đa 2 lời khuyên: tổ hợp dấu hiệu khớp trước, rồi tới dấu hiệu riêng lẻ mạnh nhất.
 * @param {SignalLike[]} signals
 * @param {AdviceData} data
 * @returns {string} Đoạn lời khuyên tiếng Việt, luôn kết thúc bằng lời khuyên chung.
 */
export function adviseSignals(signals, data) {
  const ordered = signals
    .filter((s) => Math.trunc(Number(s.points ?? 0)) > 0)
    .map((s, index) => ({ s, index }))
    .sort((a, b) => Math.trunc(Number(b.s.points ?? 0)) - Math.trunc(Number(a.s.points ?? 0)) || a.index - b.index)
    .map(({ s }) => s);
  const present = new Set(ordered.map((s) => String(s.code ?? "")));
  /** @type {Set<string>} */
  const covered = new Set();
  /** @type {string[]} */
  const parts = [];
  for (const { groups, text } of data.combos) {
    if (parts.length === MAX_TIPS) break;
    const hits = groups.map((group) => group.filter((code) => present.has(code)));
    if (hits.every((hit) => hit.length > 0) && !hits.every((hit) => hit.every((code) => covered.has(code)))) {
      const matched = new Set(hits.flat());
      const brand = brandOf(ordered, matched);
      parts.push(text.replace(BRAND_PLACEHOLDER, () => brand));
      for (const code of matched) covered.add(code);
    }
  }
  for (const s of ordered) {
    if (parts.length === MAX_TIPS) break;
    const code = String(s.code ?? "");
    const tip = Object.prototype.hasOwnProperty.call(data.tips, code) ? data.tips[code] : undefined;
    if (tip === undefined || covered.has(code)) continue;
    covered.add(code);
    const brand = String(s.brand || "") || DEFAULT_BRAND;
    parts.push(tip.replace(BRAND_PLACEHOLDER, () => brand));
  }
  parts.push(data.general);
  return parts.join(" ");
}
