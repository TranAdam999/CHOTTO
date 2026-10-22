// @ts-check
/**
 * Public Suffix List: xác định tên miền đăng ký được (``a.b.vietcombank.com.vn`` → ``vietcombank.com.vn``).
 * Bảng luật đã được ``tools/sync_extension_data.py`` tách sẵn từ đúng file PSL của bản Desktop.
 * Tương đương ``chotto.core.psl``.
 * @module engine/psl
 */

/**
 * @typedef {object} SuffixInfo
 * @property {string} suffix Hậu tố công cộng dài nhất khớp (``com.vn``, ``web.app``...).
 * @property {boolean} isPrivate Luật khớp thuộc mục PRIVATE (nền tảng hosting/dịch vụ).
 * @property {string | null} registrable Tên miền đăng ký được, ``null`` nếu host là hậu tố công cộng.
 */

/**
 * @typedef {object} PslTables
 * @property {Record<string, number>} exact
 * @property {Record<string, number>} wildcard
 * @property {Record<string, number>} exception
 */

export class PublicSuffixList {
  /**
   * @param {PslTables} tables Ba bảng luật ``{luật: 1 nếu PRIVATE}`` (từ ``data/psl.json``).
   * @throws {TypeError} Dữ liệu sai cấu trúc hoặc rỗng.
   */
  constructor(tables) {
    if (!tables || typeof tables !== "object") throw new TypeError("psl.json phải là object");
    /** @type {Map<string, boolean>[]} */
    const maps = ["exact", "wildcard", "exception"].map((name) => {
      const table = /** @type {Record<string, unknown>} */ (tables)[name];
      if (!table || typeof table !== "object") throw new TypeError(`psl.json thiếu bảng '${name}'`);
      return new Map(Object.entries(table).map(([rule, flag]) => [rule, Boolean(flag)]));
    });
    /** @type {Map<string, boolean>} */
    this.exact = maps[0];
    /** @type {Map<string, boolean>} */
    this.wildcard = maps[1];
    /** @type {Map<string, boolean>} */
    this.exception = maps[2];
    if (this.exact.size === 0 && this.wildcard.size === 0) throw new TypeError("Public Suffix List rỗng hoặc hỏng");
  }

  /**
   * Tra hậu tố công cộng của ``host`` (ASCII chữ thường; dấu chấm cuối được bỏ).
   * @param {string} host
   * @returns {SuffixInfo}
   */
  lookup(host) {
    const labels = host.toLowerCase().replace(/\.+$/, "").split(".").filter(Boolean);
    const count = labels.length;
    if (count === 0) return { suffix: "", isPrivate: false, registrable: null };
    for (let index = 0; index < count; index += 1) {
      const candidate = labels.slice(index).join(".");
      const flag = this.exception.get(candidate);
      if (flag !== undefined) return PublicSuffixList.info(labels, count - index - 1, flag);
    }
    let suffixLen = 1;
    let isPrivate = false;
    for (let index = 0; index < count; index += 1) {
      const candidate = labels.slice(index).join(".");
      const exact = this.exact.get(candidate);
      if (exact !== undefined) {
        suffixLen = count - index;
        isPrivate = exact;
        break;
      }
      if (index + 1 < count) {
        const wildcard = this.wildcard.get(labels.slice(index + 1).join("."));
        if (wildcard !== undefined) {
          suffixLen = count - index;
          isPrivate = wildcard;
          break;
        }
      }
    }
    return PublicSuffixList.info(labels, suffixLen, isPrivate);
  }

  /**
   * @param {string[]} labels
   * @param {number} suffixLen
   * @param {boolean} isPrivate
   * @returns {SuffixInfo}
   */
  static info(labels, suffixLen, isPrivate) {
    const suffix = suffixLen ? labels.slice(labels.length - suffixLen).join(".") : "";
    const registrable = labels.length > suffixLen ? labels.slice(-(suffixLen + 1)).join(".") : null;
    return { suffix, isPrivate, registrable };
  }
}
