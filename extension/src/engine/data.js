// @ts-check
/**
 * Nạp dữ liệu đóng gói kèm tiện ích (``data/*.json``) và cấu hình các module engine.
 * Dùng chung cho service worker (đọc qua ``fetch``) và kiểm thử Node (đọc file).
 * @module engine/data
 */

import { validateAdvice } from "./advisor.js";
import { PublicSuffixList } from "./psl.js";
import { configureUtil } from "./util.js";

const REQUIRED_RULE_KEYS = Object.freeze({
  thresholds: "object", weights: "object", high_risk_tlds: "array", lure_keywords: "array", shorteners: "array",
  wrappers: "array", trusted_domains: "array", brands: "array", brand_affixes: "array", age_curve: "array",
});
const REQUIRED_THRESHOLDS = ["friction", "high", "tier3_low", "tier3_high", "entropy", "hyphens", "unwrap_depth"];
const REQUIRED_WEIGHTS = [
  "typosquat", "homoglyph", "combosquat", "lure_each", "lure_cap", "high_risk_tld", "entropy", "hyphens",
  "random_digits", "raw_ip", "at_sign", "http", "idn", "shortener", "nested_redirect", "port", "free_hosting",
  "unparseable", "redirect_via_trusted", "brand_in_path",
];

export class RulesError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "RulesError";
  }
}

/**
 * Kiểm tra ``rules.json`` giống ``config.load_rules`` của bản Desktop.
 * @param {unknown} data
 * @returns {import("./tier2.js").Rules}
 * @throws {RulesError}
 */
export function validateRules(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new RulesError("rules.json phải là JSON object");
  const rules = /** @type {Record<string, any>} */ (data);
  for (const [key, kind] of Object.entries(REQUIRED_RULE_KEYS)) {
    const value = rules[key];
    const ok = kind === "array" ? Array.isArray(value) : Boolean(value) && typeof value === "object" && !Array.isArray(value);
    if (!ok) throw new RulesError(`rules.json thiếu hoặc sai kiểu khóa '${key}'`);
  }
  for (const key of REQUIRED_THRESHOLDS) {
    if (typeof rules.thresholds[key] !== "number") throw new RulesError(`rules.json thiếu ngưỡng thresholds.${key}`);
  }
  for (const key of REQUIRED_WEIGHTS) {
    if (typeof rules.weights[key] !== "number") throw new RulesError(`rules.json thiếu trọng số weights.${key}`);
  }
  for (const brand of rules.brands) {
    const strings = (/** @type {unknown} */ v) => Array.isArray(v) && v.every((x) => typeof x === "string");
    if (!brand || typeof brand.name !== "string" || !strings(brand.keywords) || !strings(brand.domains)) {
      throw new RulesError(`Thương hiệu không hợp lệ trong rules.json: ${JSON.stringify(brand)}`);
    }
  }
  for (const wrapper of rules.wrappers) {
    if (!wrapper || typeof wrapper.host !== "string" || typeof wrapper.path !== "string") {
      throw new RulesError(`Wrapper không hợp lệ trong rules.json: ${JSON.stringify(wrapper)}`);
    }
  }
  const curve = rules.age_curve;
  let previous = -1;
  const curveOk = curve.length >= 2 && curve.every((/** @type {unknown} */ knot) => {
    if (!Array.isArray(knot) || knot.length !== 2 || !knot.every((v) => typeof v === "number")) return false;
    if (knot[0] <= previous) return false;
    previous = knot[0];
    return true;
  }) && curve[0][0] === 0;
  if (!curveOk) throw new RulesError("rules.json: age_curve phải là các điểm [ngày, điểm] tăng dần, bắt đầu từ ngày 0");
  return rules;
}

/**
 * @typedef {object} EngineData
 * @property {import("./tier2.js").Rules} rules Bộ luật đã gắn ``popularDomains``.
 * @property {import("./advisor.js").AdviceData} advice
 * @property {PublicSuffixList} psl
 * @property {string[]} seed Danh sách đen khởi tạo.
 * @property {{chotto_version: string, sources: Record<string, string>}} sync Thông tin đồng bộ dữ liệu.
 */

/**
 * Nạp toàn bộ dữ liệu engine và cấu hình module ``util``.
 * @param {(name: string) => Promise<string>} readText Đọc một file trong ``data/`` theo tên.
 * @returns {Promise<EngineData>}
 * @throws {RulesError | TypeError | SyntaxError} Dữ liệu đóng gói hỏng.
 */
export async function loadEngineData(readText) {
  const [rulesText, pslText, confusablesText, popularText, adviceText, seedText, syncText] = await Promise.all([
    readText("rules.json"), readText("psl.json"), readText("confusables.json"), readText("popular.json"),
    readText("advice.json"), readText("blacklist.seed.txt"), readText("sync.json"),
  ]);
  const rules = validateRules(JSON.parse(rulesText));
  const psl = new PublicSuffixList(JSON.parse(pslText));
  const confusables = JSON.parse(confusablesText);
  if (!confusables || typeof confusables !== "object") throw new TypeError("confusables.json sai cấu trúc");
  const popular = JSON.parse(popularText);
  if (!Array.isArray(popular)) throw new TypeError("popular.json phải là mảng");
  rules.popularDomains = new Set(popular.filter((d) => typeof d === "string"));
  configureUtil({ psl, confusables });
  return {
    rules,
    advice: validateAdvice(JSON.parse(adviceText)),
    psl,
    seed: seedText.split(/\r?\n/),
    sync: JSON.parse(syncText),
  };
}
