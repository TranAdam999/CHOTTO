// @ts-check
/**
 * Punycode (RFC 3492) cho nhãn tên miền IDN: giải mã ``xn--`` để hiển thị/so khớp homoglyph.
 *
 * ``new URL()`` của trình duyệt đã tự mã hóa host sang ASCII, nên tiện ích chỉ cần chiều giải mã;
 * chiều mã hóa có ở đây để công cụ kiểm thử và trang tùy chọn dùng chung một cài đặt.
 * @module engine/punycode
 */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = "-";
const MAX_INT = 0x7fffffff;

export class PunycodeError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "PunycodeError";
  }
}

/**
 * Điều chỉnh bias theo RFC 3492 mục 6.1.
 * @param {number} delta
 * @param {number} numPoints
 * @param {boolean} firstTime
 * @returns {number}
 */
function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

/**
 * Giá trị của một ký tự mã hóa (a–z = 0–25, 0–9 = 26–35).
 * @param {number} code
 * @returns {number}
 */
function digitValue(code) {
  if (code >= 0x30 && code <= 0x39) return code - 22;
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61;
  return BASE;
}

/**
 * Ký tự mã hóa của một chữ số (chữ thường).
 * @param {number} digit
 * @returns {string}
 */
function digitChar(digit) {
  return String.fromCharCode(digit + 22 + 75 * Number(digit < 26));
}

/**
 * Giải mã phần sau ``xn--`` của một nhãn.
 * @param {string} input Chuỗi ASCII punycode (không gồm tiền tố ``xn--``).
 * @returns {string} Nhãn Unicode.
 * @throws {PunycodeError} Dữ liệu punycode không hợp lệ.
 */
export function decode(input) {
  /** @type {number[]} */
  const output = [];
  const basic = input.lastIndexOf(DELIMITER);
  const basicEnd = basic < 0 ? 0 : basic;
  for (let j = 0; j < basicEnd; j += 1) {
    const code = input.charCodeAt(j);
    if (code >= 0x80) throw new PunycodeError("Ký tự không phải ASCII trong phần cơ bản");
    output.push(code);
  }
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new PunycodeError("Punycode bị cụt");
      const digit = digitValue(input.charCodeAt(index));
      index += 1;
      if (digit >= BASE) throw new PunycodeError("Ký tự punycode không hợp lệ");
      if (digit > Math.floor((MAX_INT - i) / w)) throw new PunycodeError("Tràn số punycode");
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) throw new PunycodeError("Tràn số punycode");
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > MAX_INT - n) throw new PunycodeError("Tràn số punycode");
    n += Math.floor(i / out);
    i %= out;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) throw new PunycodeError("Code point không hợp lệ");
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

/**
 * Mã hóa một nhãn Unicode sang punycode (không gồm tiền tố ``xn--``).
 * @param {string} input
 * @returns {string}
 * @throws {PunycodeError} Tràn số.
 */
export function encode(input) {
  const codePoints = Array.from(input, (ch) => /** @type {number} */ (ch.codePointAt(0)));
  let output = codePoints.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join("");
  const basicLength = output.length;
  let handled = basicLength;
  if (basicLength) output += DELIMITER;
  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  while (handled < codePoints.length) {
    let m = MAX_INT;
    for (const c of codePoints) if (c >= n && c < m) m = c;
    if (m - n > Math.floor((MAX_INT - delta) / (handled + 1))) throw new PunycodeError("Tràn số punycode");
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of codePoints) {
      if (c < n) {
        delta += 1;
        if (delta > MAX_INT) throw new PunycodeError("Tràn số punycode");
      }
      if (c === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
          if (q < t) break;
          output += digitChar(t + ((q - t) % (BASE - t)));
          q = Math.floor((q - t) / (BASE - t));
        }
        output += digitChar(q);
        bias = adapt(delta, handled + 1, handled === basicLength);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }
  return output;
}

/**
 * Giải mã các nhãn ``xn--`` của một tên miền ASCII để hiển thị; nhãn hỏng giữ nguyên.
 * Tương đương ``chotto.core.url.domain_to_unicode``.
 * @param {string} asciiDomain
 * @returns {string}
 */
export function domainToUnicode(asciiDomain) {
  return asciiDomain
    .split(".")
    .map((label) => {
      if (!label.startsWith("xn--")) return label;
      try {
        return decode(label.slice(4));
      } catch (error) {
        if (error instanceof PunycodeError) return label;
        throw error;
      }
    })
    .join(".");
}
