// @ts-check
/**
 * Content script trên chat.zalo.me (isolated world, chạy từ ``document_start`` trong mọi frame).
 *
 * Chặn ở pha capture trên ``window`` (trước mọi handler của Zalo) ba cách mở liên kết bằng thao tác:
 * click trái (kể cả Ctrl/⌘/Shift), click chuột giữa (``auxclick``) và Enter trên liên kết đang focus;
 * cộng với ``window.open`` (được ``main_world.js`` chuyển sang qua sự kiện ``chotto:open``). Liên kết
 * được gửi cho service worker thẩm định; an toàn thì service worker tự mở, rủi ro thì hiện "Khoan đã!".
 * Liên kết nội bộ của Zalo (cùng origin) và scheme khác http(s) không bị đụng tới.
 */
(() => {
  const FLAG = "__chottoContentLoaded";
  if (/** @type {any} */ (window)[FLAG]) return;
  /** @type {any} */ (window)[FLAG] = true;

  const TOAST_DELAY_MS = 350;
  const GESTURE_WINDOW_MS = 2000;
  const OWN_ORIGIN = location.origin;
  /** @type {Set<string>} */
  const inFlight = new Set();
  let lastGestureAt = -Infinity;

  /**
   * @typedef {{kind: "tab", active: boolean} | {kind: "window"}} Disposition
   */

  /**
   * URL http(s) ra ngoài Zalo cần kiểm tra, hoặc ``null``.
   * @param {string} raw
   * @returns {string | null}
   */
  function externalUrl(raw) {
    try {
      const url = new URL(raw, document.baseURI);
      if (url.protocol !== "http:" && url.protocol !== "https:") return null;
      if (url.origin === OWN_ORIGIN) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  /**
   * Liên kết nằm trên đường đi của sự kiện (xuyên cả Shadow DOM mở).
   * @param {Event} event
   * @returns {string | null}
   */
  function anchorHref(event) {
    for (const node of event.composedPath()) {
      if (node instanceof HTMLAnchorElement || node instanceof HTMLAreaElement) {
        return node.hasAttribute("href") ? node.href : null;
      }
      if (typeof SVGAElement !== "undefined" && node instanceof SVGAElement) {
        const href = node.href.baseVal || node.getAttribute("xlink:href") || "";
        return href ? new URL(href, document.baseURI).href : null;
      }
    }
    return null;
  }

  /**
   * Gửi thông điệp cho service worker.
   * @param {Record<string, unknown>} message
   * @returns {Promise<any>}
   * @throws {Error} Service worker trả lỗi hoặc tiện ích vừa được cập nhật/gỡ.
   */
  async function ask(message) {
    const reply = await chrome.runtime.sendMessage(message);
    if (!reply || reply.ok !== true) throw new Error(reply?.error ?? "Không có phản hồi từ CHOTTO");
    return reply.value;
  }

  /**
   * Phương án dự phòng khi không liên lạc được service worker (ví dụ tiện ích vừa được cập nhật):
   * vẫn bắt người dùng dừng lại, rồi tự mở bằng cú bấm thật của họ.
   * @param {string} url
   */
  function fallbackFriction(url) {
    /** @type {any} */ (globalThis).ChottoFriction.show({
      view: {
        level: "WARN",
        title: "Khoan đã! CHOTTO chưa kiểm tra được liên kết này",
        domainLine: `Trang sẽ mở: ${new URL(url).hostname}`,
        url,
        score: 0,
        tierText: "Không kết nối được bộ kiểm tra (hãy tải lại trang Zalo)",
        reasons: ["Tiện ích vừa được cập nhật hoặc tạm dừng, chưa thẩm định được liên kết."],
        advice: "",
      },
      lockMs: 5000,
      decide: async (/** @type {string} */ choice) => {
        if (choice === "proceed") window.open(url, "_blank", "noopener,noreferrer");
        return { ok: true };
      },
    });
  }

  /**
   * Thẩm định và xử lý một liên kết.
   * @param {string} url
   * @param {Disposition} disposition
   * @param {"click" | "window.open"} via
   */
  async function inspect(url, disposition, via) {
    if (inFlight.has(url)) return;
    inFlight.add(url);
    const friction = /** @type {any} */ (globalThis).ChottoFriction;
    /** @type {{remove: () => void} | null} */
    let toast = null;
    const toastTimer = setTimeout(() => {
      toast = friction.toast("CHOTTO đang kiểm tra liên kết…");
    }, TOAST_DELAY_MS);
    try {
      const answer = await ask({ type: "inspect", url, disposition, via });
      if (answer.action === "friction") {
        friction.show({
          view: answer.view,
          lockMs: answer.lockMs,
          decide: (/** @type {string} */ choice, /** @type {boolean} */ trusted) =>
            ask({ type: "decide", token: answer.token, choice, trusted }),
        });
      }
    } catch (error) {
      console.warn("CHOTTO: không thẩm định được, chuyển sang chế độ dự phòng", error);
      fallbackFriction(url);
    } finally {
      clearTimeout(toastTimer);
      /** @type {{remove: () => void} | null} */ (toast)?.remove();
      inFlight.delete(url);
    }
  }

  /**
   * Cách mở theo phím bổ trợ/nút chuột (giống hành vi mặc định của trình duyệt).
   * @param {MouseEvent | KeyboardEvent} event
   * @param {boolean} middle
   * @returns {Disposition}
   */
  function dispositionOf(event, middle) {
    if (event.shiftKey && !middle && !(event.ctrlKey || event.metaKey)) return { kind: "window" };
    if (middle || event.ctrlKey || event.metaKey) return { kind: "tab", active: event.shiftKey };
    return { kind: "tab", active: true };
  }

  /**
   * Chặn một sự kiện mở liên kết.
   * @param {Event} event
   * @param {Disposition} disposition
   */
  function intercept(event, disposition) {
    const href = anchorHref(event);
    if (href === null) return;
    const url = externalUrl(href);
    if (url === null) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    inspect(url, disposition, "click");
  }

  window.addEventListener("click", (event) => {
    if (event.button !== 0) return;
    intercept(event, dispositionOf(event, false));
  }, true);

  window.addEventListener("auxclick", (event) => {
    if (event.button !== 1) return;
    intercept(event, dispositionOf(event, true));
  }, true);

  window.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.isComposing) return;
    const target = event.composedPath()[0];
    if (!(target instanceof HTMLAnchorElement || target instanceof HTMLAreaElement)) return;
    intercept(event, dispositionOf(event, false));
  }, true);

  for (const type of ["pointerdown", "keydown", "touchstart"]) {
    window.addEventListener(type, (event) => {
      if (event.isTrusted) lastGestureAt = performance.now();
    }, true);
  }

  // window.open từ script của trang: chỉ nhận khi vừa có thao tác thật của người dùng (chống bật tab hàng loạt).
  window.addEventListener("chotto:open", (event) => {
    const detail = /** @type {CustomEvent} */ (event).detail;
    if (typeof detail !== "string") return;
    if (performance.now() - lastGestureAt > GESTURE_WINDOW_MS) {
      console.warn("CHOTTO: bỏ qua window.open không do người dùng bấm", detail);
      return;
    }
    const url = externalUrl(detail);
    if (url !== null) inspect(url, { kind: "tab", active: true }, "window.open");
  });
})();
