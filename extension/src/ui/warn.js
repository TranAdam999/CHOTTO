// @ts-check
/**
 * Trang cảnh báo của lưới an toàn: tab mới mở từ Zalo mà chưa qua kiểm tra được chuyển tới đây.
 * Trang thẩm định liên kết (``?u=``); an toàn thì service worker điều hướng tab tới đích, rủi ro thì hiện
 * "Khoan đã!" như trên Zalo ("Đóng" sẽ đóng tab này).
 */

const statusLine = /** @type {HTMLElement} */ (document.getElementById("status"));

/**
 * @param {Record<string, unknown>} message
 * @returns {Promise<any>}
 * @throws {Error} Service worker trả lỗi.
 */
async function ask(message) {
  const reply = await chrome.runtime.sendMessage(message);
  if (!reply || reply.ok !== true) throw new Error(reply?.error ?? "Không có phản hồi từ CHOTTO");
  return reply.value;
}

/** Thẩm định liên kết trong tham số ``u``. */
async function main() {
  const target = new URLSearchParams(location.search).get("u");
  if (!target) {
    statusLine.textContent = "Không có liên kết để kiểm tra.";
    return;
  }
  document.title = "CHOTTO – Đang kiểm tra liên kết";
  const answer = await ask({ type: "inspect", url: target, disposition: { kind: "current" }, via: "tab-moi" });
  if (answer.action !== "friction") {
    statusLine.textContent = "Liên kết an toàn, đang mở…";
    return;
  }
  document.title = "CHOTTO – Khoan đã!";
  statusLine.textContent = "CHOTTO đã dừng liên kết này lại để bạn kiểm tra.";
  /** @type {any} */ (globalThis).ChottoFriction.show({
    view: answer.view,
    lockMs: answer.lockMs,
    parent: document.body,
    decide: (/** @type {string} */ choice, /** @type {boolean} */ trusted) =>
      ask({ type: "decide", token: answer.token, choice, trusted }),
  });
}

main().catch((error) => {
  console.error("CHOTTO: trang cảnh báo lỗi", error);
  statusLine.textContent = `CHOTTO không kiểm tra được liên kết này (${error instanceof Error ? error.message : String(error)}). `
    + "Hãy đóng tab và hỏi lại người gửi.";
});
