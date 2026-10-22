// @ts-check
/**
 * Pipeline thẩm định 3 tầng (bản chuyển thể của ``chotto/engine.py``).
 *
 * Thứ tự: phân tích URL như trình duyệt → bóc link bọc → Tầng 1 (mọi mắt xích và URL nhúng) → Tầng 2 →
 * Tầng 3 (chỉ vùng nghi vấn) → mức rủi ro, tối đa 4 lý do, lời khuyên cục bộ. URL không phân tích được
 * không bao giờ được coi là an toàn: kết quả là WARN (fail-safe có friction).
 * @module engine/engine
 */

import { adviseSignals } from "./advisor.js";
import * as tier2 from "./tier2.js";
import { URLParseError, parseUrl, safeOpenUrl } from "./url.js";
import { isPrivateSuffixHost, registeredDomain, roundHalfEven, sanitizeForDisplay } from "./util.js";

export const Level = Object.freeze({ SAFE: "SAFE", WARN: "WARN", HIGH: "HIGH", BLOCKED: "BLOCKED" });
const MAX_REASONS = 4;
const IMPERSONATION = new Set(["combosquat", "homoglyph", "typosquat"]);

/**
 * @typedef {import("./tier2.js").Signal} Signal
 * @typedef {import("./tier2.js").Rules} Rules
 * @typedef {import("./tier3.js").AgeInfo} AgeInfo
 * @typedef {import("./advisor.js").AdviceData} AdviceData
 * @typedef {import("./url.js").ParsedURL} ParsedURL
 */

/**
 * @typedef {object} Result
 * @property {string} url Liên kết gốc.
 * @property {string} finalUrl Đích đã chuẩn hóa sau khi bóc link bọc.
 * @property {string} host Host của đích (ASCII).
 * @property {number} score Điểm rủi ro 0–100.
 * @property {string} level ``SAFE``/``WARN``/``HIGH``/``BLOCKED``.
 * @property {string[]} reasons Tối đa 4 lý do.
 * @property {Signal[]} signals Toàn bộ dấu hiệu.
 * @property {number} tierReached Tầng cuối đã chạy (0 = không phân tích được).
 * @property {number | null} domainAgeDays Tuổi tên miền nếu Tầng 3 tra được.
 * @property {string} advice Lời khuyên cục bộ.
 * @property {number} elapsedMs Thời gian thẩm định.
 * @property {string} openUrl URL an toàn để mở (link gốc đã chuẩn hóa).
 * @property {string} displayDomain Tên miền thật để hiển thị nổi bật.
 * @property {string[]} degraded Thành phần bị bỏ qua do lỗi.
 */

/**
 * @typedef {object} Tier3Job
 * @property {string} url
 * @property {string} openUrl
 * @property {ParsedURL} scored
 * @property {number} score
 * @property {Signal[]} signals
 * @property {string[]} degraded
 * @property {number} started
 */

/**
 * @typedef {object} EngineSettings
 * @property {boolean} tier3Enabled Bật tra tuổi tên miền qua mạng.
 * @property {boolean} aiAdvice Lời khuyên cục bộ khi Tầng 3 tắt/không tra được.
 */

/**
 * @typedef {object} BlacklistLike
 * @property {(host: string, path: string) => Promise<string | null>} lookup
 */

/** @returns {number} */
function nowMs() {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

/**
 * @param {number} started
 * @returns {number}
 */
function msSince(started) {
  return Math.trunc(nowMs() - started);
}

/**
 * Điểm cộng/trừ theo tuổi tên miền: nội suy tuyến tính trên ``age_curve``; mạo danh thì không được trừ.
 * @param {number} ageDays
 * @param {number[][]} curve
 * @param {boolean} impersonatesBrand
 * @returns {[number, string]} (điểm điều chỉnh, lý do hoặc chuỗi rỗng khi điểm không dương)
 */
export function ageAdjustment(ageDays, curve, impersonatesBrand) {
  const age = Math.max(0, Number(ageDays));
  let points = Number(curve[curve.length - 1][1]);
  for (let i = 0; i + 1 < curve.length; i += 1) {
    const [day0, value0] = curve[i].map(Number);
    const [day1, value1] = curve[i + 1].map(Number);
    if (age <= day1) {
      const span = day1 - day0;
      const ratio = span > 0 ? (age - day0) / span : 1;
      points = value0 + (value1 - value0) * ratio;
      break;
    }
  }
  let adjust = roundHalfEven(points);
  if (adjust < 0 && impersonatesBrand) adjust = 0;
  if (adjust > 0) return [adjust, `Tên miền mới đăng ký cách đây ${Math.trunc(age)} ngày`];
  return [adjust, ""];
}

/**
 * Kết quả fail-safe khi không phân tích được liên kết: luôn WARN.
 * @param {string} url
 * @param {Rules} rules
 * @param {AdviceData} advice
 * @param {number} [elapsedMs]
 * @returns {Result}
 */
export function analysisFailedResult(url, rules, advice, elapsedMs = 0) {
  const points = Math.trunc(Number(rules?.weights?.unparseable ?? 50));
  const reason = "CHOTTO không phân tích được liên kết này, hãy kiểm tra kỹ trước khi mở";
  return {
    url,
    finalUrl: sanitizeForDisplay(String(url).slice(0, 2048)),
    host: "",
    score: points,
    level: Level.WARN,
    reasons: [reason],
    signals: [{ code: "unparseable", points, reason, brand: "" }],
    tierReached: 0,
    domainAgeDays: null,
    advice: advice.general,
    elapsedMs,
    openUrl: safeOpenUrl(String(url)),
    displayDomain: "",
    degraded: [],
  };
}

/** Bộ thẩm định 3 tầng. */
export class Engine {
  /**
   * @param {object} options
   * @param {Rules} options.rules Bộ luật (đã gắn ``popularDomains``).
   * @param {AdviceData} options.advice Dữ liệu lời khuyên.
   * @param {EngineSettings} options.settings Cấu hình người dùng.
   * @param {(() => Promise<BlacklistLike>) | null} [options.blacklist] Mở danh sách đen (lười).
   * @param {((host: string) => Promise<AgeInfo | null>) | null} [options.ageLookup] Tra tuổi tên miền.
   */
  constructor({ rules, advice, settings, blacklist = null, ageLookup = null }) {
    this.rules = rules;
    this.advice = advice;
    this.settings = settings;
    this.openBlacklist = blacklist;
    this.ageLookup = ageLookup;
  }

  /**
   * Thẩm định một liên kết (chạy cả Tầng 3 nếu cần).
   * @param {string} url
   * @returns {Promise<Result>}
   */
  async inspect(url) {
    const { result, job } = await this.inspectFast(url);
    return job === null ? result : this.complete(job);
  }

  /**
   * Tra Tầng 1 cho mọi URL.
   * @param {ParsedURL[]} urls
   * @returns {Promise<string | null>} Host khớp đầu tiên.
   * @throws {Error} Danh sách đen không dùng được.
   */
  async tier1(urls) {
    if (this.openBlacklist === null) return null;
    const blacklist = await this.openBlacklist();
    for (const item of urls) if ((await blacklist.lookup(item.host, item.path)) !== null) return item.host;
    return null;
  }

  /**
   * Phần cục bộ (phân tích, Tầng 1, Tầng 2), vài mili-giây.
   * @param {string} url
   * @returns {Promise<{result: Result, job: Tier3Job | null}>} ``job`` khác ``null`` khi cần chạy Tầng 3.
   */
  async inspectFast(url) {
    const started = nowMs();
    const { thresholds } = this.rules;
    /** @type {ParsedURL} */
    let original;
    /** @type {import("./tier2.js").UnwrapResult} */
    let unwrapped;
    try {
      original = parseUrl(url);
      unwrapped = tier2.unwrap(original, this.rules);
    } catch (error) {
      if (!(error instanceof URLParseError)) throw error;
      return { result: analysisFailedResult(url, this.rules, this.advice, msSince(started)), job: null };
    }
    /** @type {string[]} */
    const degraded = [];
    const final = unwrapped.final;

    const toCheck = [...unwrapped.chain];
    for (const item of unwrapped.chain) toCheck.push(...tier2.embeddedUrls(item));
    /** @type {string | null} */
    let hitHost = null;
    try {
      hitHost = await this.tier1(toCheck);
    } catch (error) {
      console.error("CHOTTO: Tầng 1 không dùng được, tiếp tục với Tầng 2", error);
      degraded.push("tier1");
    }
    if (hitHost !== null) {
      const reason = "Tên miền nằm trong danh sách lừa đảo đã được cộng đồng báo cáo";
      return {
        result: {
          url,
          finalUrl: final.href,
          host: hitHost,
          score: 100,
          level: Level.BLOCKED,
          reasons: [reason],
          signals: [{ code: "blacklist", points: 100, reason, brand: "" }],
          tierReached: 1,
          domainAgeDays: null,
          advice: this.settings.aiAdvice ? adviseSignals([{ code: "blacklist", points: 100 }], this.advice) : "",
          elapsedMs: msSince(started),
          openUrl: original.href,
          displayDomain: registeredDomain(hitHost),
          degraded,
        },
        job: null,
      };
    }

    const t2 = tier2.analyze(original, this.rules, unwrapped);
    /** @type {Tier3Job} */
    const job = {
      url,
      openUrl: original.href,
      scored: t2.final,
      score: t2.score,
      signals: t2.signals.map((s) => ({ ...s })),
      degraded: [...degraded],
      started,
    };
    const eligible = Boolean(this.settings.tier3Enabled)
      && this.ageLookup !== null
      && !t2.trusted
      && !t2.final.isIp
      && !isPrivateSuffixHost(t2.final.host)
      && !t2.signals.some((s) => s.code === "shortener")
      && Number(thresholds.tier3_low) <= t2.score && t2.score <= Number(thresholds.tier3_high);
    const result = this.finalize(job, 2, null, null, [...degraded]);
    return { result, job: eligible ? job : null };
  }

  /**
   * Chạy Tầng 3 cho ``job`` và trả kết quả cuối. Không bao giờ ném lỗi.
   * @param {Tier3Job} job
   * @returns {Promise<Result>}
   */
  async complete(job) {
    const degraded = [...job.degraded];
    /** @type {AgeInfo | null} */
    let info = null;
    try {
      info = this.ageLookup ? await this.ageLookup(job.scored.host) : null;
    } catch (error) {
      console.error("CHOTTO: Tầng 3 lỗi, quay về điểm Tầng 2", error);
      degraded.push("tier3");
      info = null;
    }
    if (info === null) return this.finalize(job, 3, null, null, degraded);
    const impersonates = job.signals.some((s) => IMPERSONATION.has(s.code));
    const [adjust, why] = ageAdjustment(info.ageDays, this.rules.age_curve, impersonates);
    const extra = adjust ? { code: "age", points: adjust, reason: why, brand: "" } : null;
    return this.finalize(job, 3, extra, info.ageDays, degraded);
  }

  /**
   * Mức rủi ro, lý do và lời khuyên từ điểm Tầng 2 (và điều chỉnh Tầng 3 nếu có).
   * @param {Tier3Job} job
   * @param {number} tier
   * @param {Signal | null} extra
   * @param {number | null} ageDays
   * @param {string[]} degraded
   * @returns {Result}
   */
  finalize(job, tier, extra, ageDays, degraded) {
    const { thresholds } = this.rules;
    const signals = job.signals.map((s) => ({ ...s }));
    let score = job.score;
    if (extra !== null) {
      signals.push(extra);
      score = Math.max(0, Math.min(100, score + Math.trunc(extra.points)));
    }
    /** @type {string} */
    let level = Level.SAFE;
    if (score >= Number(thresholds.high)) level = Level.HIGH;
    else if (score >= Number(thresholds.friction)) level = Level.WARN;
    signals.sort((a, b) => b.points - a.points);
    const reasons = signals.filter((s) => s.points > 0 && s.reason).map((s) => s.reason).slice(0, MAX_REASONS);
    /** @type {Result} */
    const result = {
      url: job.url,
      finalUrl: job.scored.href,
      host: job.scored.host,
      score,
      level,
      reasons,
      signals,
      tierReached: tier,
      domainAgeDays: ageDays,
      advice: "",
      elapsedMs: 0,
      openUrl: job.openUrl,
      displayDomain: registeredDomain(job.scored.host),
      degraded,
    };
    if (level !== Level.SAFE && this.settings.aiAdvice && ageDays === null) {
      result.advice = adviseSignals(signals, this.advice);
    }
    result.elapsedMs = msSince(job.started);
    return result;
  }
}
