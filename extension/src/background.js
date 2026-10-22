// @ts-check
/**
 * Service worker của CHOTTO (Manifest V3).
 *
 * - Thẩm định liên kết do content script chặn được trên chat.zalo.me (engine 3 tầng, chạy cục bộ).
 * - Liên kết an toàn: service worker tự mở tab (đánh dấu "đã kiểm tra" để lưới an toàn không chặn lại).
 * - Liên kết rủi ro: cấp một "vé" dùng một lần kèm thời điểm mở khóa; nút "vẫn mở" chỉ có hiệu lực khi
 *   service worker xác nhận vé hợp lệ, đúng tab và đã hết thời gian khóa (trang web không giả được).
 * - Lưới an toàn: tab mới sinh ra từ tab Zalo mà chưa qua kiểm tra bị chuyển sang trang cảnh báo.
 * - Không giữ trạng thái quan trọng trong biến toàn cục: vé và danh sách "đã kiểm tra" nằm trong
 *   ``chrome.storage.session``, danh sách đen và nhật ký trong IndexedDB.
 */

import { loadEngineData } from "./engine/data.js";
import { Engine, Level } from "./engine/engine.js";
import { Fingerprints } from "./engine/tier1.js";
import { BOOTSTRAP_URL, lookupAge, parseBootstrap, readLimited } from "./engine/tier3.js";
import { URLParseError, parseUrl } from "./engine/url.js";
import { DEFAULTS, frictionSecondsFor, loadSettings, saveSettings } from "./settings.js";
import { Store } from "./storage.js";
import { ensureSeeded, updateDue, updateFromSources } from "./updater.js";
import { buildView } from "./view.js";

const ZALO_ORIGIN = "https://chat.zalo.me";
const TOKEN_TTL_MS = 15 * 60 * 1000;
const VETTED_TTL_MS = 30 * 1000;
const WATCH_TTL_MS = 20 * 1000;
const UNLOCK_TOLERANCE_MS = 150;
const ALARM = "chotto-hourly";
const BOOTSTRAP_MAX_AGE_MS = 7 * 86400 * 1000;
const DAY_MS = 86400 * 1000;
const AGE_PREFIX = "age:";

const store = new Store();
/** @type {Promise<import("./engine/data.js").EngineData> | null} */
let dataPromise = null;
/** @type {Promise<Engine> | null} */
let enginePromise = null;
/** @type {Fingerprints | null} */
let fingerprintCache = null;
/** @type {Promise<import("./updater.js").UpdateOutcome> | null} */
let updating = null;

/**
 * @typedef {{kind: "tab", active: boolean} | {kind: "window"} | {kind: "current"}} Disposition
 */

/**
 * @typedef {object} Ticket
 * @property {string} url URL sẽ mở.
 * @property {number} unlockAt Mốc được phép "vẫn mở".
 * @property {number} expires Mốc hết hạn.
 * @property {number} tabId Tab đã nhận vé.
 * @property {Disposition} disposition
 * @property {string} domain
 * @property {string} level
 * @property {number} score
 * @property {string} via
 */

// ---------------------------------------------------------------- dữ liệu & engine

/** @returns {Promise<import("./engine/data.js").EngineData>} */
function getData() {
  if (dataPromise === null) {
    dataPromise = loadEngineData(async (name) => {
      const response = await fetch(chrome.runtime.getURL(`data/${name}`));
      if (!response.ok) throw new Error(`Không đọc được data/${name}`);
      return response.text();
    }).catch((error) => {
      dataPromise = null;
      throw error;
    });
  }
  return dataPromise;
}

/**
 * Danh sách đen trong RAM (nạp lười từ IndexedDB; dựng từ danh sách khởi tạo nếu trống).
 * @returns {Promise<Fingerprints>}
 */
async function openBlacklist() {
  if (fingerprintCache === null) {
    let record = await store.getBlacklist();
    if (record === null) {
      const data = await getData();
      await ensureSeeded(store, data.seed, data.rules);
      record = await store.getBlacklist();
    }
    if (record === null) throw new Error("Không dựng được danh sách đen");
    fingerprintCache = Fingerprints.fromBuffer(record.fingerprints);
  }
  return fingerprintCache;
}

/**
 * Cache tuổi tên miền trong ``chrome.storage.local`` (khóa ``age:<tên miền>``).
 * @type {import("./engine/tier3.js").AgeCache}
 */
const ageCache = {
  /** @param {string} domain */
  async get(domain) {
    const key = AGE_PREFIX + domain;
    const stored = await chrome.storage.local.get(key);
    return /** @type {import("./engine/tier3.js").CacheRecord | undefined} */ (stored[key]) ?? null;
  },
  /**
   * @param {string} domain
   * @param {import("./engine/tier3.js").CacheRecord} record
   */
  async put(domain, record) {
    await chrome.storage.local.set({ [AGE_PREFIX + domain]: record });
  },
};

/** @returns {Promise<Record<string, string> | null>} Bảng RDAP bootstrap đã lưu (làm mới nền nếu cũ). */
async function rdapBootstrap() {
  const saved = /** @type {{table?: Record<string, string>, fetchedAt?: number} | undefined} */ (
    (await chrome.storage.local.get("rdapBootstrap")).rdapBootstrap);
  if (!saved || typeof saved.fetchedAt !== "number" || Date.now() - saved.fetchedAt > BOOTSTRAP_MAX_AGE_MS) {
    refreshBootstrap().catch((error) => console.info("CHOTTO: chưa làm mới được RDAP bootstrap", error));
  }
  return saved?.table ?? null;
}

/** Tải bảng IANA RDAP bootstrap (tối đa một lần mỗi 6 giờ khi lỗi). */
async function refreshBootstrap() {
  const rdapBootstrapAttempt = Number((await chrome.storage.session.get("rdapBootstrapAttempt")).rdapBootstrapAttempt ?? 0);
  if (Date.now() - rdapBootstrapAttempt < 6 * 3600 * 1000) return;
  await chrome.storage.session.set({ rdapBootstrapAttempt: Date.now() });
  const response = await fetch(BOOTSTRAP_URL, { credentials: "omit", cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const table = parseBootstrap(JSON.parse(await readLimited(response, 2 << 20)));
  if (Object.keys(table).length === 0) throw new Error("Bảng RDAP bootstrap rỗng");
  await chrome.storage.local.set({ rdapBootstrap: { table, fetchedAt: Date.now() } });
}

/** @returns {Promise<Engine>} */
function getEngine() {
  if (enginePromise === null) {
    enginePromise = (async () => {
      const [data, settings] = await Promise.all([getData(), loadSettings(chrome.storage.local)]);
      return new Engine({
        rules: data.rules,
        advice: data.advice,
        settings: { tier3Enabled: settings.tier3Enabled, aiAdvice: settings.aiAdvice },
        blacklist: openBlacklist,
        ageLookup: async (host) => lookupAge(host, {
          timeoutMs: settings.tier3TimeoutMs,
          ttlHours: settings.cacheTtlHours,
          bootstrap: await rdapBootstrap(),
          cache: ageCache,
        }),
      });
    })().catch((error) => {
      enginePromise = null;
      throw error;
    });
  }
  return enginePromise;
}

// ---------------------------------------------------------------- vé, "đã kiểm tra", tab theo dõi

/**
 * Đọc một bảng trong ``storage.session`` và bỏ mục hết hạn.
 * @template T
 * @param {string} key
 * @param {(value: T) => number} expiryOf
 * @returns {Promise<Record<string, T>>}
 */
async function sessionTable(key, expiryOf) {
  const stored = (await chrome.storage.session.get(key))[key] ?? {};
  const now = Date.now();
  /** @type {Record<string, T>} */
  const fresh = {};
  for (const [k, v] of Object.entries(stored)) if (expiryOf(/** @type {T} */ (v)) > now) fresh[k] = /** @type {T} */ (v);
  return fresh;
}

/**
 * Dạng chuẩn để so khớp URL.
 * @param {string} url
 * @returns {string}
 */
function canonical(url) {
  try {
    return new URL(url).href;
  } catch {
    return url;
  }
}

/** @type {Promise<unknown>} */
let sessionQueue = Promise.resolve();

/**
 * Chạy ``task`` tuần tự với các thao tác đọc-sửa-ghi ``storage.session`` khác (tránh mất cập nhật).
 * @template T
 * @param {() => Promise<T>} task
 * @returns {Promise<T>}
 */
function serialized(task) {
  const run = sessionQueue.then(task, task);
  sessionQueue = run.catch(() => undefined);
  return run;
}

/** @param {string} url */
function markVetted(url) {
  return serialized(async () => {
    const vetted = await sessionTable("vetted", (/** @type {number} */ v) => v);
    vetted[canonical(url)] = Date.now() + VETTED_TTL_MS;
    await chrome.storage.session.set({ vetted });
  });
}

/**
 * Dùng (và xóa) dấu "đã kiểm tra" của ``url``.
 * @param {string} url
 * @returns {Promise<boolean>}
 */
function consumeVetted(url) {
  return serialized(async () => {
    const vetted = await sessionTable("vetted", (/** @type {number} */ v) => v);
    const key = canonical(url);
    const hit = key in vetted;
    delete vetted[key];
    await chrome.storage.session.set({ vetted });
    return hit;
  });
}

/**
 * Mở URL theo cách người dùng đã bấm.
 * @param {string} url
 * @param {Disposition} disposition
 * @param {chrome.tabs.Tab | undefined} sourceTab
 * @returns {Promise<void>}
 */
async function openTarget(url, disposition, sourceTab) {
  await markVetted(url);
  if (disposition.kind === "current" && sourceTab?.id !== undefined) {
    await chrome.tabs.update(sourceTab.id, { url });
  } else if (disposition.kind === "window") {
    await chrome.windows.create({ url });
  } else {
    /** @type {chrome.tabs.CreateProperties} */
    const props = { url, active: disposition.kind === "tab" ? disposition.active : true };
    if (sourceTab?.id !== undefined) {
      props.openerTabId = sourceTab.id;
      props.index = sourceTab.index + 1;
      props.windowId = sourceTab.windowId;
    }
    await chrome.tabs.create(props);
  }
}

/**
 * Ghi nhật ký quyết định (chỉ tên miền đăng ký) nếu người dùng bật.
 * @param {Ticket} ticket
 * @param {import("./storage.js").Decision["choice"]} choice
 */
async function recordDecision(ticket, choice) {
  const settings = await loadSettings(chrome.storage.local);
  if (!settings.logDecisions) return;
  try {
    await store.addDecision({
      ts: Date.now(), domain: ticket.domain, level: ticket.level, score: ticket.score, choice, via: ticket.via,
    });
  } catch (error) {
    console.error("CHOTTO: không ghi được nhật ký", error);
  }
}

// ---------------------------------------------------------------- xử lý thông điệp

/**
 * Nguồn gửi thông điệp: content script trên Zalo, trang của tiện ích, hoặc không hợp lệ.
 * @param {chrome.runtime.MessageSender} sender
 * @returns {"zalo" | "extension" | null}
 */
function senderKind(sender) {
  if (sender.id !== chrome.runtime.id) return null;
  const url = sender.url ?? "";
  if (url.startsWith(chrome.runtime.getURL(""))) return "extension";
  if (sender.tab && (sender.origin === ZALO_ORIGIN || url.startsWith(`${ZALO_ORIGIN}/`))) return "zalo";
  return null;
}

/**
 * @param {unknown} value
 * @returns {Disposition}
 */
function parseDisposition(value) {
  const d = /** @type {Record<string, unknown>} */ (value ?? {});
  if (d.kind === "window") return { kind: "window" };
  if (d.kind === "current") return { kind: "current" };
  return { kind: "tab", active: d.active !== false };
}

/**
 * Thẩm định rồi mở ngay (an toàn) hoặc cấp vé friction.
 * @param {Record<string, any>} message
 * @param {chrome.runtime.MessageSender} sender
 */
async function handleInspect(message, sender) {
  if (typeof message.url !== "string") throw new TypeError("Thiếu url");
  const disposition = parseDisposition(message.disposition);
  const via = ["click", "window.open", "tab-moi"].includes(message.via) ? message.via : "click";
  const engine = await getEngine();
  const result = await engine.inspect(message.url);
  if (result.level === Level.SAFE) {
    await openTarget(result.openUrl, disposition, sender.tab);
    return { action: "opened", elapsedMs: result.elapsedMs };
  }
  const settings = await loadSettings(chrome.storage.local);
  const lockMs = frictionSecondsFor(result.level, settings.frictionSeconds) * 1000;
  const now = Date.now();
  const token = crypto.randomUUID();
  await serialized(async () => {
    const tickets = await sessionTable("tickets", (/** @type {Ticket} */ t) => t.expires);
    tickets[token] = {
      url: result.openUrl,
      unlockAt: now + lockMs,
      expires: now + TOKEN_TTL_MS,
      tabId: sender.tab?.id ?? -1,
      disposition,
      domain: result.displayDomain || result.host,
      level: result.level,
      score: result.score,
      via,
    };
    await chrome.storage.session.set({ tickets });
  });
  return { action: "friction", token, lockMs, view: buildView(result) };
}

/**
 * Quyết định của người dùng trên màn hình friction.
 * @param {Record<string, any>} message
 * @param {chrome.runtime.MessageSender} sender
 */
async function handleDecide(message, sender) {
  /** @type {{ok: false, reason: string} | Ticket} */
  const claimed = await serialized(async () => {
    const tickets = await sessionTable("tickets", (/** @type {Ticket} */ t) => t.expires);
    const found = tickets[String(message.token)];
    if (!found) return { ok: false, reason: "expired" };
    if (found.tabId !== (sender.tab?.id ?? -1)) return { ok: false, reason: "wrong-tab" };
    if (message.choice === "proceed") {
      if (message.trusted !== true) return { ok: false, reason: "untrusted" };
      if (Date.now() + UNLOCK_TOLERANCE_MS < found.unlockAt) return { ok: false, reason: "locked" };
    }
    delete tickets[String(message.token)];
    await chrome.storage.session.set({ tickets });
    return found;
  });
  if ("ok" in claimed) return claimed;
  const ticket = claimed;
  if (message.choice === "proceed") {
    await recordDecision(ticket, "proceed");
    await openTarget(ticket.url, ticket.disposition, sender.tab);
  } else {
    await recordDecision(ticket, ticket.level === Level.BLOCKED ? "blocked_back" : "back");
    if (ticket.disposition.kind === "current" && sender.tab?.id !== undefined) {
      await chrome.tabs.remove(sender.tab.id);
    }
  }
  return { ok: true };
}

/** Trạng thái cho trang tùy chọn. */
async function handleStatus() {
  const [data, settings, blacklist, state] = await Promise.all([
    getData(), loadSettings(chrome.storage.local), openBlacklist().then(() => store.getBlacklist()),
    updateState(),
  ]);
  return {
    version: chrome.runtime.getManifest().version,
    dataVersion: data.sync.chotto_version,
    settings,
    defaults: DEFAULTS,
    blacklist: blacklist ? { count: blacklist.count, builtAt: blacklist.builtAt, origin: blacklist.origin } : null,
    update: state,
    sources: (data.rules.blacklist_sources ?? []).map((/** @type {any} */ s) => String(s.name ?? "?")),
  };
}

/**
 * Trạng thái cập nhật danh sách đen đã lưu.
 * @returns {Promise<import("./updater.js").UpdateState & {log?: string[]}>}
 */
async function updateState() {
  const value = (await chrome.storage.local.get("blacklistUpdate")).blacklistUpdate;
  return value && typeof value === "object" ? value : {};
}

/**
 * Chạy cập nhật danh sách đen (tối đa một lần cùng lúc).
 * @returns {Promise<import("./updater.js").UpdateOutcome>}
 */
function runUpdate() {
  if (updating === null) {
    updating = (async () => {
      const data = await getData();
      const attempt = Date.now();
      try {
        const outcome = await updateFromSources({ rules: data.rules, store, seed: data.seed });
        const previous = await updateState();
        await chrome.storage.local.set({
          blacklistUpdate: {
            ...previous, lastAttempt: attempt, ...(outcome.succeeded ? { lastSuccess: attempt } : {}), log: outcome.log,
          },
        });
        if (outcome.replaced) fingerprintCache = null;
        return outcome;
      } catch (error) {
        const previous = await updateState();
        const log = [`[LỖI] ${error instanceof Error ? error.message : String(error)}`];
        await chrome.storage.local.set({ blacklistUpdate: { ...previous, lastAttempt: attempt, log } });
        throw error;
      }
    })().finally(() => {
      updating = null;
    });
  }
  return updating;
}

/**
 * Bộ định tuyến thông điệp.
 * @param {Record<string, any>} message
 * @param {chrome.runtime.MessageSender} sender
 */
async function route(message, sender) {
  const kind = senderKind(sender);
  if (kind === null) throw new Error("Nguồn thông điệp không hợp lệ");
  switch (message?.type) {
    case "inspect":
      return handleInspect(message, sender);
    case "decide":
      return handleDecide(message, sender);
    default:
      break;
  }
  if (kind !== "extension") throw new Error("Thông điệp chỉ dành cho trang của tiện ích");
  switch (message.type) {
    case "status":
      return handleStatus();
    case "settings": {
      const saved = await saveSettings(chrome.storage.local, message.changes ?? {});
      enginePromise = null;
      return { settings: saved };
    }
    case "update-now":
      return runUpdate();
    case "test": {
      const engine = await getEngine();
      const result = await engine.inspect(String(message.url ?? ""));
      return { view: buildView(result), level: result.level, elapsedMs: result.elapsedMs, signals: result.signals };
    }
    case "log":
      return { decisions: await store.listDecisions(Number(message.limit ?? 500)) };
    case "log-clear":
      await store.clearDecisions();
      return { ok: true };
    default:
      throw new Error(`Thông điệp không hỗ trợ: ${String(message.type)}`);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  route(message, sender)
    .then((value) => sendResponse({ ok: true, value }))
    .catch((error) => {
      console.error("CHOTTO: lỗi xử lý thông điệp", message?.type, error);
      sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
    });
  return true;
});

// ---------------------------------------------------------------- lưới an toàn tab mới

/**
 * ``true`` nếu tab là chat.zalo.me.
 * @param {number} tabId
 * @returns {Promise<boolean>}
 */
async function isZaloTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url || tab.pendingUrl || "";
    return url.startsWith(`${ZALO_ORIGIN}/`);
  } catch {
    return false;
  }
}

/**
 * URL http(s) không thuộc Zalo (cần kiểm tra)?
 * @param {string} url
 * @returns {boolean}
 */
function needsInspection(url) {
  try {
    const parsed = parseUrl(url);
    return `${parsed.scheme}://${parsed.host}` !== ZALO_ORIGIN;
  } catch (error) {
    if (error instanceof URLParseError) return false;
    throw error;
  }
}

/**
 * Chuyển tab sang trang cảnh báo của tiện ích (trang đó tự thẩm định và hiện friction).
 * @param {number} tabId
 * @param {string} url
 */
async function divert(tabId, url) {
  const warn = `${chrome.runtime.getURL("src/ui/warn.html")}?u=${encodeURIComponent(url)}`;
  try {
    await chrome.tabs.update(tabId, { url: warn });
  } catch (error) {
    console.error("CHOTTO: không chuyển được tab mới sang trang cảnh báo", error);
  }
}

chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
  (async () => {
    if (!(await isZaloTab(details.sourceTabId))) return;
    const url = details.url || "";
    if (!/^https?:/i.test(url)) {
      await serialized(async () => {
        const watched = await sessionTable("watched", (/** @type {number} */ v) => v);
        watched[String(details.tabId)] = Date.now() + WATCH_TTL_MS;
        await chrome.storage.session.set({ watched });
      });
      return;
    }
    if (!needsInspection(url) || (await consumeVetted(url))) return;
    await divert(details.tabId, url);
  })().catch((error) => console.error("CHOTTO: lỗi lưới an toàn", error));
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  (async () => {
    const wasWatched = await serialized(async () => {
      const watched = await sessionTable("watched", (/** @type {number} */ v) => v);
      const key = String(details.tabId);
      if (!(key in watched)) return false;
      delete watched[key];
      await chrome.storage.session.set({ watched });
      return true;
    });
    if (!wasWatched) return;
    if (!needsInspection(details.url) || (await consumeVetted(details.url))) return;
    await divert(details.tabId, details.url);
  })().catch((error) => console.error("CHOTTO: lỗi lưới an toàn", error));
});

// ---------------------------------------------------------------- bảo trì định kỳ

/** Cập nhật danh sách đen nếu đến hạn, dọn nhật ký và cache tuổi tên miền quá hạn. */
async function maintenance() {
  const settings = await loadSettings(chrome.storage.local);
  if (settings.autoUpdate && updateDue(await updateState(), Date.now())) {
    await runUpdate().catch((error) => console.error("CHOTTO: cập nhật danh sách đen lỗi", error));
  }
  const lastPrune = Number((await chrome.storage.local.get("lastPrune")).lastPrune ?? 0);
  if (Date.now() - lastPrune < DAY_MS) return;
  await store.pruneDecisions(Date.now() - settings.logRetentionDays * DAY_MS);
  const everything = await chrome.storage.local.get(null);
  const stale = Object.entries(everything)
    .filter(([key, value]) => {
      const fetched = /** @type {{fetched?: unknown} | undefined} */ (value)?.fetched;
      return key.startsWith(AGE_PREFIX)
        && (typeof fetched !== "number" || Date.now() - fetched > settings.cacheTtlHours * 3600 * 1000);
    })
    .map(([key]) => key);
  if (stale.length) await chrome.storage.local.remove(stale);
  await chrome.storage.local.set({ lastPrune: Date.now() });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) maintenance().catch((error) => console.error("CHOTTO: bảo trì lỗi", error));
});

/** Bảo đảm lịch bảo trì tồn tại (alarms có thể mất khi trình duyệt cập nhật). */
async function ensureAlarm() {
  if (!(await chrome.alarms.get(ALARM))) await chrome.alarms.create(ALARM, { delayInMinutes: 1, periodInMinutes: 60 });
}

chrome.runtime.onInstalled.addListener((details) => {
  (async () => {
    await ensureAlarm();
    await openBlacklist();
    if (details.reason === "install") await chrome.runtime.openOptionsPage();
  })().catch((error) => console.error("CHOTTO: lỗi khi cài đặt", error));
});

chrome.runtime.onStartup.addListener(() => {
  ensureAlarm().catch((error) => console.error("CHOTTO: không đặt được lịch bảo trì", error));
});

chrome.action.onClicked.addListener(() => {
  chrome.runtime.openOptionsPage().catch((error) => console.error("CHOTTO: không mở được trang tùy chọn", error));
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && "settings" in changes) enginePromise = null;
});
