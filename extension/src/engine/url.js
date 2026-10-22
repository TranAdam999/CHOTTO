// @ts-check
/**
 * Phân tích URL http/https đúng như trình duyệt: dùng chính bộ phân tích WHATWG ``URL`` của trình duyệt,
 * nên tiện ích nhìn URL y hệt trang sẽ mở (``https://evil.top\@vietcombank.com.vn/`` → host ``evil.top``).
 * Tương đương ``chotto.core.url.parse_url`` ở bản Desktop.
 * @module engine/url
 */

import { domainToUnicode } from "./punycode.js";

export const MAX_URL_LENGTH = 32768;
export const SUPPORTED_SCHEMES = Object.freeze(["http", "https"]);

const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+\-.]*):/;
// eslint-disable-next-line no-control-regex
const EDGE_C0_RE = /^[\u0000- ]+|[\u0000- ]+$/g;
const TAB_NEWLINE_RE = /[\t\n\r]/g;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export class URLParseError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "URLParseError";
  }
}

/**
 * @typedef {"domain" | "ipv4" | "ipv6"} HostKind
 */

/**
 * URL đã chuẩn hóa, mô tả đúng trang mà trình duyệt sẽ mở (bất biến).
 */
export class ParsedURL {
  /**
   * @param {object} parts
   * @param {string} parts.raw Chuỗi đầu vào nguyên bản.
   * @param {string} parts.scheme ``http`` hoặc ``https``.
   * @param {string} parts.username Tên người dùng (đã percent-encode).
   * @param {string} parts.password Mật khẩu (đã percent-encode).
   * @param {string} parts.host Host ASCII chữ thường; IPv6 trong ngoặc vuông.
   * @param {HostKind} parts.hostKind Loại host.
   * @param {number | null} parts.port Cổng nếu khác cổng mặc định.
   * @param {string} parts.path Đường dẫn, luôn bắt đầu bằng ``/``.
   * @param {string | null} parts.query Truy vấn (không gồm ``?``) hoặc ``null``.
   * @param {string | null} parts.fragment Phân mảnh (không gồm ``#``) hoặc ``null``.
   * @param {string} parts.unicodeHost Host dạng Unicode để hiển thị.
   * @param {string} parts.href Chuỗi URL chuẩn hóa.
   */
  constructor(parts) {
    this.raw = parts.raw;
    this.scheme = parts.scheme;
    this.username = parts.username;
    this.password = parts.password;
    this.host = parts.host;
    this.hostKind = parts.hostKind;
    this.port = parts.port;
    this.path = parts.path;
    this.query = parts.query;
    this.fragment = parts.fragment;
    this.unicodeHost = parts.unicodeHost;
    this.href = parts.href;
    Object.freeze(this);
  }

  /** ``true`` nếu URL chứa phần ``user[:pass]@`` (thủ thuật che tên miền thật). */
  get hasCredentials() {
    return Boolean(this.username || this.password);
  }

  /** ``true`` nếu host là địa chỉ IP thay vì tên miền. */
  get isIp() {
    return this.hostKind !== "domain";
  }

  /** Đường dẫn kèm truy vấn (nếu có). */
  get pathAndQuery() {
    return this.query === null ? this.path : `${this.path}?${this.query}`;
  }
}

/**
 * Scheme (chữ thường) của chuỗi URL như trình duyệt đọc, hoặc ``null``.
 * @param {string} raw
 * @returns {string | null}
 */
export function getScheme(raw) {
  const cleaned = String(raw).replace(EDGE_C0_RE, "").replace(TAB_NEWLINE_RE, "");
  const match = SCHEME_RE.exec(cleaned);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Phân tích một URL http/https đúng như trình duyệt.
 * @param {string} raw Chuỗi URL (từ thẻ ``<a>``, ``window.open`` hoặc tham số của link bọc).
 * @returns {ParsedURL}
 * @throws {URLParseError} URL quá dài, không phải http/https, hoặc trình duyệt sẽ từ chối nó.
 */
export function parseUrl(raw) {
  if (typeof raw !== "string") throw new URLParseError("URL phải là chuỗi");
  if (raw.length > MAX_URL_LENGTH) throw new URLParseError(`URL dài hơn ${MAX_URL_LENGTH} ký tự`);
  const scheme = getScheme(raw);
  if (scheme === null) throw new URLParseError("URL không có scheme");
  if (!SUPPORTED_SCHEMES.includes(scheme)) throw new URLParseError(`Scheme không được hỗ trợ: ${scheme}`);
  /** @type {URL} */
  let url;
  try {
    url = new URL(raw);
  } catch (error) {
    throw new URLParseError(`Trình duyệt từ chối URL: ${error instanceof Error ? error.message : String(error)}`);
  }
  const host = url.hostname.endsWith(".") ? url.hostname.slice(0, -1) : url.hostname;
  if (!host) throw new URLParseError("URL http/https phải có host");
  /** @type {HostKind} */
  let hostKind = "domain";
  if (host.startsWith("[")) hostKind = "ipv6";
  else if (IPV4_RE.test(host)) hostKind = "ipv4";
  const href = url.href;
  const beforeFragment = url.hash || href.endsWith("#") ? href.slice(0, href.lastIndexOf("#")) : href;
  const hasQuery = url.search !== "" || beforeFragment.endsWith("?");
  const hasFragment = url.hash !== "" || href.endsWith("#");
  return new ParsedURL({
    raw,
    scheme,
    username: url.username,
    password: url.password,
    host,
    hostKind,
    port: url.port === "" ? null : Number(url.port),
    path: url.pathname || "/",
    query: hasQuery ? url.search.slice(1) : null,
    fragment: hasFragment ? url.hash.slice(1) : null,
    unicodeHost: hostKind === "domain" ? domainToUnicode(host) : host,
    href,
  });
}

/**
 * Chuỗi URL an toàn để mở: dạng chuẩn hóa nếu phân tích được; ngược lại bỏ ký tự điều khiển và
 * percent-encode các ký tự có thể chèn tham số. Tương đương ``engine.safe_open_url``.
 * @param {string} raw
 * @returns {string}
 */
export function safeOpenUrl(raw) {
  try {
    return parseUrl(raw).href;
  } catch (error) {
    if (!(error instanceof URLParseError)) throw error;
    // eslint-disable-next-line no-control-regex
    const cleaned = String(raw).trim().replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
    return cleaned.replace(/[ "<>`{}|\\^]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`);
  }
}
