// @ts-check
/**
 * Chạy trong "main world" của chat.zalo.me (cùng môi trường với script của Zalo) từ ``document_start``.
 *
 * Bọc ``window.open``: liên kết http(s) ra ngoài Zalo không được mở trực tiếp mà được chuyển cho
 * content script của CHOTTO qua sự kiện ``chotto:open`` để thẩm định trước. Các lời gọi khác (cùng origin,
 * ``about:blank``, không tham số) đi thẳng tới hàm gốc; tab trống mở kiểu đó vẫn được lưới an toàn của
 * service worker theo dõi khi nó điều hướng ra ngoài.
 */
(() => {
  const FLAG = "__chottoMainWorldLoaded";
  if (/** @type {any} */ (window)[FLAG]) return;
  Object.defineProperty(window, FLAG, { value: true });

  const nativeOpen = window.open;
  const ownOrigin = location.origin;

  /**
   * @param {string | URL} [url]
   * @param {string} [target]
   * @param {string} [features]
   * @returns {Window | null}
   */
  function chottoOpen(url, target, features) {
    if (url !== undefined && url !== null && String(url) !== "") {
      try {
        const parsed = new URL(String(url), document.baseURI);
        if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.origin !== ownOrigin) {
          window.dispatchEvent(new CustomEvent("chotto:open", { detail: parsed.href }));
          return null;
        }
      } catch (error) {
        console.warn("CHOTTO: URL window.open không đọc được, để trình duyệt xử lý", error);
      }
    }
    return nativeOpen.call(window, url, target, features);
  }

  Object.defineProperty(chottoOpen, "toString", { value: () => nativeOpen.toString() });
  Object.defineProperty(window, "open", { value: chottoOpen, writable: true, configurable: true, enumerable: true });
})();
