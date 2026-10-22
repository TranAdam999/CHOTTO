// @ts-check
/**
 * Lưu trữ cục bộ của tiện ích trong IndexedDB:
 * - ``blacklist``: tập dấu vân tay Tầng 1 (một ArrayBuffer) và thông tin dựng;
 * - ``sources``: bản sao mục hợp lệ gần nhất + ETag/Last-Modified của từng nguồn danh sách đen;
 * - ``decisions``: nhật ký quyết định tối giản (chỉ tên miền đăng ký, mức, điểm, lựa chọn, thời điểm).
 *
 * Service worker MV3 có thể bị dừng bất cứ lúc nào, nên mọi trạng thái bền đều nằm ở đây (không giữ
 * trong biến toàn cục ngoài vai trò cache).
 * @module storage
 */

export const DB_NAME = "chotto";
export const DB_VERSION = 1;
const BLACKLIST = "blacklist";
const SOURCES = "sources";
const DECISIONS = "decisions";

/**
 * @typedef {object} BlacklistRecord
 * @property {ArrayBuffer} fingerprints Mảng dấu vân tay little-endian đã sắp xếp.
 * @property {number} count Số mục.
 * @property {number} builtAt Mốc dựng (ms epoch).
 * @property {string} origin ``seed`` hoặc ``update``.
 */

/**
 * @typedef {object} SourceRecord
 * @property {string} url
 * @property {string[]} entries Các mục hợp lệ gần nhất.
 * @property {string} etag
 * @property {string} lastModified
 * @property {number} storedAt
 */

/**
 * @typedef {object} Decision
 * @property {number} ts Mốc thời gian (ms epoch).
 * @property {string} domain Tên miền đăng ký (không lưu đường dẫn hay URL đầy đủ).
 * @property {string} level
 * @property {number} score
 * @property {"back" | "proceed" | "blocked_back"} choice
 * @property {string} via Kênh phát hiện: ``click``, ``window.open``, ``tab-moi``.
 */

/**
 * Bọc một IDBRequest thành Promise.
 * @template T
 * @param {IDBRequest<T>} request
 * @returns {Promise<T>}
 */
function settle(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Lỗi IndexedDB"));
  });
}

/**
 * Chờ một transaction hoàn tất.
 * @param {IDBTransaction} tx
 * @returns {Promise<void>}
 */
function done(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("Lỗi IndexedDB"));
    tx.onabort = () => reject(tx.error ?? new Error("Giao dịch IndexedDB bị hủy"));
  });
}

/** Kho IndexedDB của CHOTTO (mở lười, dùng lại kết nối). */
export class Store {
  /**
   * @param {IDBFactory} [factory] ``indexedDB`` (thay được khi kiểm thử).
   * @param {string} [name]
   */
  constructor(factory = globalThis.indexedDB, name = DB_NAME) {
    this.factory = factory;
    this.name = name;
    /** @type {Promise<IDBDatabase> | null} */
    this.dbPromise = null;
  }

  /**
   * Kết nối (tạo bảng ở lần đầu).
   * @returns {Promise<IDBDatabase>}
   * @throws {Error} Trình duyệt chặn IndexedDB.
   */
  db() {
    if (this.dbPromise === null) {
      this.dbPromise = new Promise((resolve, reject) => {
        const request = this.factory.open(this.name, DB_VERSION);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(BLACKLIST)) db.createObjectStore(BLACKLIST);
          if (!db.objectStoreNames.contains(SOURCES)) db.createObjectStore(SOURCES, { keyPath: "url" });
          if (!db.objectStoreNames.contains(DECISIONS)) {
            const decisions = db.createObjectStore(DECISIONS, { autoIncrement: true });
            decisions.createIndex("ts", "ts");
          }
        };
        request.onsuccess = () => {
          const db = request.result;
          db.onversionchange = () => {
            db.close();
            this.dbPromise = null;
          };
          resolve(db);
        };
        request.onerror = () => {
          this.dbPromise = null;
          reject(request.error ?? new Error("Không mở được IndexedDB"));
        };
        request.onblocked = () => console.warn("CHOTTO: IndexedDB đang bị một kết nối cũ giữ");
      });
    }
    return this.dbPromise;
  }

  /** Đóng kết nối (kiểm thử). */
  async close() {
    if (this.dbPromise !== null) {
      const db = await this.dbPromise;
      db.close();
      this.dbPromise = null;
    }
  }

  /**
   * Danh sách đen hiện tại.
   * @returns {Promise<BlacklistRecord | null>}
   */
  async getBlacklist() {
    const db = await this.db();
    const record = await settle(db.transaction(BLACKLIST, "readonly").objectStore(BLACKLIST).get("current"));
    return record ?? null;
  }

  /**
   * Thay danh sách đen (nguyên tử trong một transaction).
   * @param {BlacklistRecord} record
   * @returns {Promise<void>}
   */
  async putBlacklist(record) {
    const db = await this.db();
    const tx = db.transaction(BLACKLIST, "readwrite");
    tx.objectStore(BLACKLIST).put(record, "current");
    await done(tx);
  }

  /**
   * Bản sao của một nguồn.
   * @param {string} url
   * @returns {Promise<SourceRecord | null>}
   */
  async getSource(url) {
    const db = await this.db();
    return (await settle(db.transaction(SOURCES, "readonly").objectStore(SOURCES).get(url))) ?? null;
  }

  /**
   * Lưu bản sao của một nguồn.
   * @param {SourceRecord} record
   * @returns {Promise<void>}
   */
  async putSource(record) {
    const db = await this.db();
    const tx = db.transaction(SOURCES, "readwrite");
    tx.objectStore(SOURCES).put(record);
    await done(tx);
  }

  /**
   * Ghi một quyết định.
   * @param {Decision} decision
   * @returns {Promise<void>}
   */
  async addDecision(decision) {
    const db = await this.db();
    const tx = db.transaction(DECISIONS, "readwrite");
    tx.objectStore(DECISIONS).add(decision);
    await done(tx);
  }

  /**
   * Các quyết định mới nhất trước.
   * @param {number} [limit]
   * @returns {Promise<Decision[]>}
   */
  async listDecisions(limit = 500) {
    const db = await this.db();
    const index = db.transaction(DECISIONS, "readonly").objectStore(DECISIONS).index("ts");
    /** @type {Decision[]} */
    const out = [];
    await new Promise((resolve, reject) => {
      const request = index.openCursor(null, "prev");
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor || out.length >= limit) {
          resolve(undefined);
          return;
        }
        out.push(cursor.value);
        cursor.continue();
      };
      request.onerror = () => reject(request.error ?? new Error("Lỗi đọc nhật ký"));
    });
    return out;
  }

  /**
   * Xóa quyết định cũ hơn ``cutoff``.
   * @param {number} cutoff Mốc ms epoch.
   * @returns {Promise<number>} Số dòng đã xóa.
   */
  async pruneDecisions(cutoff) {
    const db = await this.db();
    const tx = db.transaction(DECISIONS, "readwrite");
    const index = tx.objectStore(DECISIONS).index("ts");
    let removed = 0;
    const request = index.openCursor(IDBKeyRange.upperBound(cutoff, true));
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      cursor.delete();
      removed += 1;
      cursor.continue();
    };
    await done(tx);
    return removed;
  }

  /**
   * Xóa toàn bộ nhật ký.
   * @returns {Promise<void>}
   */
  async clearDecisions() {
    const db = await this.db();
    const tx = db.transaction(DECISIONS, "readwrite");
    tx.objectStore(DECISIONS).clear();
    await done(tx);
  }
}
