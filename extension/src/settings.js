// @ts-check
/**
 * Cài đặt người dùng của tiện ích (``chrome.storage.local``), cùng ý nghĩa và miền giá trị với
 * ``chotto/config.py`` của bản Desktop.
 * @module settings
 */

/**
 * @typedef {object} Settings
 * @property {boolean} tier3Enabled Tra tuổi tên miền qua mạng (tắt = AI's Advices, 100% offline).
 * @property {boolean} aiAdvice Lời khuyên cục bộ khi Tầng 3 tắt/không khả dụng.
 * @property {number} frictionSeconds Thời gian khóa nút "vẫn mở" ở mức WARN (HIGH +3 giây, BLOCKED +5 giây).
 * @property {number} tier3TimeoutMs Tổng thời gian tối đa của Tầng 3.
 * @property {number} cacheTtlHours Thời hạn cache tuổi tên miền.
 * @property {boolean} logDecisions Nhật ký cục bộ (chỉ tên miền) phục vụ đánh giá nghiên cứu.
 * @property {number} logRetentionDays Số ngày giữ nhật ký.
 * @property {boolean} autoUpdate Tự cập nhật danh sách đen mỗi ngày.
 */

/** @type {Readonly<Settings>} */
export const DEFAULTS = Object.freeze({
  tier3Enabled: true,
  aiAdvice: true,
  frictionSeconds: 5,
  tier3TimeoutMs: 1800,
  cacheTtlHours: 48,
  logDecisions: true,
  logRetentionDays: 90,
  autoUpdate: true,
});

/** Miền giá trị hợp lệ (nhỏ nhất, lớn nhất) cho các khóa số. */
export const RANGES = Object.freeze({
  frictionSeconds: [3, 15],
  tier3TimeoutMs: [500, 3000],
  cacheTtlHours: [24, 72],
  logRetentionDays: [1, 3650],
});

const EXTRA_FRICTION = Object.freeze({ HIGH: 3, BLOCKED: 5 });
const KEY = "settings";

/**
 * Kiểm tra và chuẩn hóa cài đặt: khóa lạ bị bỏ, giá trị sai kiểu/ngoài miền dùng mặc định.
 * @param {unknown} raw
 * @returns {Settings}
 */
export function validateSettings(raw) {
  const input = raw && typeof raw === "object" ? /** @type {Record<string, unknown>} */ (raw) : {};
  /** @type {Record<string, unknown>} */
  const out = { ...DEFAULTS };
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    const value = input[key];
    if (typeof fallback === "boolean") {
      if (typeof value === "boolean") out[key] = value;
    } else if (typeof value === "number" && Number.isFinite(value)) {
      const [lo, hi] = /** @type {Record<string, number[]>} */ (RANGES)[key];
      const integer = key === "frictionSeconds" || key === "logRetentionDays" || key === "tier3TimeoutMs";
      if (value >= lo && value <= hi && (!integer || Number.isInteger(value))) out[key] = value;
    }
  }
  return /** @type {Settings} */ (out);
}

/**
 * Thời gian khóa nút "vẫn mở" theo mức rủi ro.
 * @param {string} level
 * @param {number} baseSeconds
 * @returns {number}
 */
export function frictionSecondsFor(level, baseSeconds) {
  return baseSeconds + (/** @type {Record<string, number>} */ (EXTRA_FRICTION)[level] ?? 0);
}

/**
 * Đọc cài đặt; lỗi đọc cho mặc định.
 * @param {chrome.storage.StorageArea} area
 * @returns {Promise<Settings>}
 */
export async function loadSettings(area) {
  try {
    const stored = await area.get(KEY);
    return validateSettings(stored[KEY]);
  } catch (error) {
    console.error("CHOTTO: không đọc được cài đặt, dùng mặc định", error);
    return { ...DEFAULTS };
  }
}

/**
 * Ghi cài đặt (đã kiểm tra) và trả về bản đã lưu.
 * @param {chrome.storage.StorageArea} area
 * @param {Partial<Settings>} changes
 * @returns {Promise<Settings>}
 * @throws {RangeError} Có giá trị không hợp lệ.
 */
export async function saveSettings(area, changes) {
  const current = await loadSettings(area);
  const merged = { ...current, ...changes };
  const validated = validateSettings(merged);
  for (const key of Object.keys(changes)) {
    if (/** @type {Record<string, unknown>} */ (validated)[key] !== /** @type {Record<string, unknown>} */ (merged)[key]) {
      throw new RangeError(`Giá trị không hợp lệ cho ${key}`);
    }
  }
  await area.set({ [KEY]: validated });
  return validated;
}
