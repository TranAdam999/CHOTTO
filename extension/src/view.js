// @ts-check
/**
 * Chuẩn bị nội dung hiển thị của màn hình "Khoan đã!" từ kết quả thẩm định (cùng chữ với ``chotto/ui.py``).
 * Mọi chuỗi đều đã lọc ký tự điều khiển/đảo chiều; giao diện chỉ gán bằng ``textContent``.
 * @module view
 */

import { domainToUnicode } from "./engine/punycode.js";
import { sanitizeForDisplay } from "./engine/util.js";

export const TITLES = Object.freeze({
  WARN: "Khoan đã! Liên kết này đáng ngờ",
  HIGH: "Khoan đã! Liên kết này rất nguy hiểm",
  BLOCKED: "Đã chặn! Liên kết nằm trong danh sách lừa đảo",
});
export const UNPARSEABLE_TITLE = "Khoan đã! CHOTTO không đọc được liên kết này";
const URL_DISPLAY_LIMIT = 300;

/**
 * @typedef {object} FrictionView
 * @property {string} level
 * @property {string} title
 * @property {string} domainLine Dòng "Trang sẽ mở: ..." với tên miền thật.
 * @property {string} url URL đích (đã lọc, cắt ngắn).
 * @property {number} score
 * @property {string} tierText
 * @property {string[]} reasons
 * @property {string} advice
 */

/**
 * Mô tả tầng đã phát hiện rủi ro.
 * @param {import("./engine/engine.js").Result} result
 * @returns {string}
 */
export function tierText(result) {
  const tier = result.tierReached;
  if (tier === 0) return "Không phân tích được liên kết";
  if (tier === 1) return "Tầng 1 – Danh sách đen lừa đảo";
  if (tier === 3 && result.domainAgeDays !== null) return "Tầng 3 – Tuổi tên miền (sau khi chấm điểm ở Tầng 2)";
  if (tier === 3) return "Tầng 2 – Phân tích tên miền (Tầng 3 đã thử nhưng không tra được)";
  return "Tầng 2 – Phân tích tên miền";
}

/**
 * Dòng "Trang sẽ mở" với tên miền thật; IDN hiển thị cả dạng Unicode và punycode.
 * @param {import("./engine/engine.js").Result} result
 * @returns {string}
 */
export function domainLine(result) {
  const domain = result.displayDomain || result.host;
  if (!domain) return "Trang sẽ mở: (không xác định)";
  const readable = domainToUnicode(domain);
  if (readable !== domain) return `Trang sẽ mở: ${sanitizeForDisplay(readable)}  (${domain})`;
  return `Trang sẽ mở: ${domain}`;
}

/**
 * Nội dung màn hình friction.
 * @param {import("./engine/engine.js").Result} result
 * @returns {FrictionView}
 */
export function buildView(result) {
  const titles = /** @type {Record<string, string>} */ (TITLES);
  const shown = sanitizeForDisplay(result.finalUrl || result.url);
  return {
    level: result.level,
    title: result.tierReached === 0 ? UNPARSEABLE_TITLE : titles[result.level] ?? TITLES.WARN,
    domainLine: domainLine(result),
    url: shown.length > URL_DISPLAY_LIMIT ? `${shown.slice(0, URL_DISPLAY_LIMIT)}…` : shown,
    score: result.score,
    tierText: tierText(result),
    reasons: result.reasons.map(sanitizeForDisplay),
    advice: sanitizeForDisplay(result.advice),
  };
}
