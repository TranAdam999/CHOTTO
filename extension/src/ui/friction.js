// @ts-check
/**
 * Màn hình "Khoan đã!" (Intentional Friction) dùng chung cho content script trên Zalo Web và trang cảnh báo.
 *
 * Chống bấm theo phản xạ và chống tự động bấm:
 * - giao diện nằm trong Shadow DOM ở chế độ ``closed`` (script của trang không đọc/sửa/bấm hộ được) và
 *   trong ``<dialog>`` modal ở top layer (không bị phần tử nào của trang che, phần còn lại bị vô hiệu);
 * - nút "vẫn mở" bị khóa đếm ngược, không nhận phím (Enter/Space cho ``click`` có ``detail = 0``), chỉ
 *   nhận cú bấm chuột/chạm thật (``isTrusted``) mà lúc nhấn xuống đã qua thời gian khóa;
 * - service worker kiểm tra lại vé và thời gian khóa trước khi mở, nên kể cả khi bị vượt mặt ở đây
 *   thì liên kết cũng không mở sớm được.
 *
 * File này là script thường (không phải module) vì content script không nạp được ES module; nó gắn
 * ``globalThis.ChottoFriction``.
 */
(() => {
  if (/** @type {any} */ (globalThis).ChottoFriction) return;

  const COLORS = { WARN: "#f5a623", HIGH: "#ff4d4f", BLOCKED: "#ff4d4f", SAFE: "#3ecf8e" };
  const TICK_MS = 200;
  const REASON_TEXT = {
    locked: "Nút vẫn đang khóa, vui lòng đợi hết thời gian đếm ngược.",
    expired: "Phiên kiểm tra đã hết hạn. Hãy đóng lại và bấm vào liên kết lần nữa.",
    "wrong-tab": "Phiên kiểm tra không thuộc tab này. Hãy bấm vào liên kết lần nữa.",
    untrusted: "Chỉ chấp nhận cú bấm chuột thật.",
    unavailable: "CHOTTO đang khởi động lại. Hãy đóng và bấm vào liên kết lần nữa.",
  };

  const STYLE = `
    :host { all: initial; }
    dialog {
      box-sizing: border-box; width: min(560px, calc(100vw - 32px)); max-height: calc(100vh - 32px); overflow: auto;
      margin: auto; padding: 0; border: 1px solid #2b2f3b; border-radius: 14px; background: #14161c; color: #e8eaf0;
      font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      box-shadow: 0 24px 64px rgba(0,0,0,.55);
    }
    dialog::backdrop { background: rgba(8, 9, 12, .72); }
    .bar { height: 6px; background: var(--accent); }
    .body { padding: 20px 22px 18px; }
    .brand { font-weight: 800; letter-spacing: .06em; color: #f5a623; font-size: 12px; }
    h1 { margin: 4px 0 10px; font-size: 19px; line-height: 1.3; color: var(--accent); }
    .domain { font-weight: 700; font-size: 15px; margin: 0 0 6px; word-break: break-all; }
    .url { background: #1d2029; border-radius: 8px; padding: 8px 10px; font: 12px/1.45 ui-monospace, SFMono-Regular,
      Menlo, Consolas, monospace; word-break: break-all; color: #c9ccd6; max-height: 92px; overflow: auto; }
    .meta { color: #8b90a0; font-size: 12px; margin-top: 8px; }
    h2 { font-size: 14px; margin: 14px 0 6px; }
    ul { margin: 0; padding-left: 20px; }
    li { margin: 2px 0; }
    .advice { background: #1d2029; border-radius: 10px; padding: 10px 12px; margin-top: 12px; color: #d6d9e2; }
    .advice strong { display: block; margin-bottom: 4px; color: #e8eaf0; }
    .note { min-height: 18px; color: #ffb4a8; font-size: 12px; margin-top: 10px; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    button { font: inherit; border: 0; border-radius: 10px; padding: 10px 16px; cursor: pointer; }
    .back { background: #3ecf8e; color: #08130d; font-weight: 700; }
    .back:focus-visible { outline: 3px solid #b5f5d8; outline-offset: 2px; }
    .proceed { background: transparent; color: #8b90a0; border: 1px solid #3a3e4b; }
    .proceed[aria-disabled="true"] { cursor: not-allowed; color: #7a7f90; background: #20232c; }
    .proceed[aria-disabled="false"] { color: #e8eaf0; border-color: var(--accent); }
    .toast { position: fixed; top: 16px; right: 16px; z-index: 2147483647; background: #14161c; color: #e8eaf0;
      border: 1px solid #f5a623; border-radius: 10px; padding: 10px 14px;
      font: 13px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; box-shadow: 0 8px 24px rgba(0,0,0,.4); }
  `;

  /**
   * Thay ký tự điều khiển/vô hình/đảo chiều bằng U+FFFD (phòng khi dữ liệu chưa được lọc).
   * @param {unknown} text
   * @returns {string}
   */
  function clean(text) {
    return String(text ?? "").replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/gu, "�");
  }

  /**
   * Tạo phần tử với nội dung chữ (không bao giờ dùng innerHTML với dữ liệu).
   * @param {string} tag
   * @param {string} [className]
   * @param {string} [text]
   * @returns {HTMLElement}
   */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /**
   * Tạo host + shadow root đóng.
   * @param {Element} parent
   * @returns {{host: HTMLElement, root: ShadowRoot}}
   */
  function mountHost(parent) {
    const host = document.createElement("chotto-shield");
    host.style.setProperty("all", "initial", "important");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.append(style);
    parent.append(host);
    return { host, root };
  }

  /**
   * @typedef {object} FrictionView
   * @property {string} level
   * @property {string} title
   * @property {string} domainLine
   * @property {string} url
   * @property {number} score
   * @property {string} tierText
   * @property {string[]} reasons
   * @property {string} advice
   */

  /**
   * Hiện màn hình friction.
   * @param {object} options
   * @param {FrictionView} options.view Nội dung đã chuẩn bị bởi service worker.
   * @param {number} options.lockMs Thời gian khóa nút "vẫn mở".
   * @param {(choice: "proceed" | "back", trusted: boolean) => Promise<{ok: boolean, reason?: string}>} options.decide
   * @param {Element} [options.parent] Nơi gắn (mặc định ``document.documentElement``).
   * @returns {{close: () => void}}
   */
  function show({ view, lockMs, decide, parent }) {
    const { host, root } = mountHost(parent ?? document.documentElement);
    const accent = /** @type {Record<string, string>} */ (COLORS)[view.level] ?? COLORS.WARN;
    const dialog = /** @type {HTMLDialogElement} */ (el("dialog"));
    dialog.style.setProperty("--accent", accent);
    dialog.setAttribute("aria-labelledby", "chotto-title");
    const body = el("div", "body");
    const title = el("h1", "", clean(view.title));
    title.id = "chotto-title";
    body.append(el("div", "brand", "CHOTTO"), title, el("p", "domain", clean(view.domainLine)), el("div", "url", clean(view.url)),
      el("div", "meta", `Điểm rủi ro: ${Number(view.score) || 0}/100 · Phát hiện ở: ${clean(view.tierText)}`));
    if (view.reasons.length) {
      body.append(el("h2", "", "Vì sao CHOTTO cảnh báo:"));
      const list = el("ul");
      for (const reason of view.reasons) list.append(el("li", "", clean(reason)));
      body.append(list);
    }
    if (view.advice) {
      const advice = el("div", "advice");
      advice.append(el("strong", "", "Lời khuyên (AI chạy cục bộ)"), document.createTextNode(clean(view.advice)));
      body.append(advice);
    }
    const note = el("div", "note");
    note.setAttribute("role", "status");
    const actions = el("div", "actions");
    const back = /** @type {HTMLButtonElement} */ (el("button", "back", "Đóng, không mở"));
    back.type = "button";
    back.autofocus = true;
    const proceed = /** @type {HTMLButtonElement} */ (el("button", "proceed"));
    proceed.type = "button";
    proceed.tabIndex = -1;
    proceed.setAttribute("aria-disabled", "true");
    actions.append(back, proceed);
    body.append(note, actions);
    dialog.append(el("div", "bar"), body);
    root.append(dialog);

    const unlockAt = performance.now() + Math.max(0, lockMs);
    let pointerDownAt = -Infinity;
    let busy = false;
    let closed = false;

    const render = () => {
      const remaining = Math.ceil((unlockAt - performance.now()) / 1000);
      if (remaining > 0) {
        proceed.textContent = `Tôi hiểu rủi ro, vẫn mở (${remaining})`;
        proceed.setAttribute("aria-disabled", "true");
      } else {
        proceed.textContent = "Tôi hiểu rủi ro, vẫn mở";
        proceed.setAttribute("aria-disabled", "false");
      }
    };
    render();
    const timer = setInterval(render, TICK_MS);

    const close = () => {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      try {
        if (dialog.open) dialog.close();
      } catch (error) {
        console.warn("CHOTTO: không đóng được hộp thoại", error);
      }
      host.remove();
    };

    /**
     * @param {"proceed" | "back"} choice
     * @param {boolean} trusted
     */
    const submit = async (choice, trusted) => {
      if (busy || closed) return;
      busy = true;
      try {
        const answer = await decide(choice, trusted);
        if (answer.ok || choice === "back") close();
        else note.textContent = /** @type {Record<string, string>} */ (REASON_TEXT)[answer.reason ?? ""] ?? REASON_TEXT.unavailable;
      } catch (error) {
        console.error("CHOTTO: lỗi gửi quyết định", error);
        if (choice === "back") close();
        else note.textContent = REASON_TEXT.unavailable;
      } finally {
        busy = false;
      }
    };

    back.addEventListener("click", () => submit("back", true));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      submit("back", true);
    });
    proceed.addEventListener("pointerdown", (event) => {
      if (event.isTrusted) pointerDownAt = performance.now();
    });
    proceed.addEventListener("keydown", (event) => event.preventDefault());
    proceed.addEventListener("click", (event) => {
      // detail = 0: click sinh từ bàn phím hoặc từ script; isTrusted = false: click giả.
      if (!event.isTrusted || event.detail === 0) return;
      const now = performance.now();
      if (now < unlockAt || pointerDownAt < unlockAt) {
        note.textContent = REASON_TEXT.locked;
        return;
      }
      submit("proceed", true);
    });

    try {
      dialog.showModal();
    } catch (error) {
      console.warn("CHOTTO: showModal lỗi, hiện dạng thường", error);
      dialog.setAttribute("open", "");
    }
    back.focus();
    return { close };
  }

  /**
   * Thông báo nhỏ "đang kiểm tra" (cũng trong Shadow DOM đóng).
   * @param {string} text
   * @returns {{remove: () => void}}
   */
  function toast(text) {
    const { host, root } = mountHost(document.documentElement);
    const box = el("div", "toast", text);
    box.setAttribute("role", "status");
    root.append(box);
    return { remove: () => host.remove() };
  }

  /** @type {any} */ (globalThis).ChottoFriction = Object.freeze({ show, toast });
})();
