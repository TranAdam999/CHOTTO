// @ts-check
/** Kiểm thử đơn vị cho engine JavaScript (punycode, URL, Tầng 1, Tầng 3, lời khuyên, pipeline). */
import assert from "node:assert/strict";
import { test } from "node:test";

import { adviseSignals } from "../src/engine/advisor.js";
import { ageAdjustment } from "../src/engine/engine.js";
import { decode, domainToUnicode, encode } from "../src/engine/punycode.js";
import { extractUrl, parseQsl } from "../src/engine/tier2.js";
import { Fingerprints, candidateKeys, entryKey, keysFromLines, parseSource } from "../src/engine/tier1.js";
import { lookupAge, parseBootstrap, parseRdap, parseRegistrationDate, rdapUrl } from "../src/engine/tier3.js";
import { URLParseError, parseUrl, safeOpenUrl } from "../src/engine/url.js";
import { damerauLevenshtein, roundHalfEven, skeleton, unquote } from "../src/engine/util.js";
import { loadData, makeEngine } from "./helpers.mjs";

const data = await loadData();

test("punycode khớp RFC 3492 và Python", () => {
  for (const [unicode, ascii] of [["vietcombank-thương", "vietcombank-thng-19d3y"], ["мбанк", "80ab2afh"],
    ["ví-điện-tử", "v-in-t-3va30ap47u7ka"]]) {
    assert.equal(encode(unicode), ascii);
    assert.equal(decode(ascii), unicode);
  }
  assert.equal(domainToUnicode("xn--80ab2afh.com.xn--zz"), "мбанк.com.xn--zz");
  assert.throws(() => decode("zz~"));
});

test("parseUrl nhìn URL như trình duyệt", () => {
  const tricky = parseUrl("https://evil.top\\@vietcombank.com.vn/");
  assert.equal(tricky.host, "evil.top");
  assert.equal(tricky.hasCredentials, false);
  const creds = parseUrl("https://vietcombank.com.vn@evil.top/");
  assert.equal(creds.host, "evil.top");
  assert.equal(creds.hasCredentials, true);
  assert.equal(parseUrl("http://3232235777/").host, "192.168.1.1");
  assert.equal(parseUrl("http://3232235777/").isIp, true);
  assert.equal(parseUrl("HTTPS://MoMo.VN.:443/a/../b").href, "https://momo.vn./b");
  assert.equal(parseUrl("HTTPS://MoMo.VN.:443/a/../b").host, "momo.vn");
  assert.equal(parseUrl("https://a.com/?").query, "");
  assert.equal(parseUrl("https://a.com/").query, null);
  assert.equal(parseUrl("https://xn--80ab2afh.com/").unicodeHost, "мбанк.com");
  for (const bad of ["javascript:alert(1)", "https://", "mailto:a@b.c", "https://exa mple.com/", "no-scheme"]) {
    assert.throws(() => parseUrl(bad), URLParseError, bad);
  }
  assert.equal(safeOpenUrl('bad url "x"\u0000'), "bad%20url%20%22x%22");
});

test("unquote/parseQsl/extractUrl giống urllib.parse", () => {
  assert.equal(unquote("X%C3%A1c_Nh%E1%BA%ADn%zz%"), "Xác_Nhận%zz%");
  assert.equal(unquote("%E1%BA"), "�");
  assert.deepEqual(parseQsl("a=1&b&c=&d=x+y%20z", true), [["a", "1"], ["b", ""], ["c", ""], ["d", "x y z"]]);
  assert.deepEqual(parseQsl("a=1&b&c=", false), [["a", "1"]]);
  assert.equal(extractUrl("aHR0cHM6Ly92Y2Itc2VjdXJlLnRvcC8")?.host, "vcb-secure.top");
  assert.equal(extractUrl("https%253A%252F%252Fvcb.top%252F")?.host, "vcb.top");
  assert.equal(extractUrl("//momo.top/x")?.host, "momo.top");
  assert.equal(extractUrl("not a url"), null);
});

test("skeleton và Damerau–Levenshtein", () => {
  assert.equal(skeleton("vietc0mbank"), "vietcombank");
  assert.equal(skeleton("rnomo"), "momo");
  assert.equal(damerauLevenshtein("mbbnak", "mbbank"), 1);
  assert.equal(damerauLevenshtein("abcdef", "uvwxyz", 1), 2);
  assert.equal(roundHalfEven(2.5), 2);
  assert.equal(roundHalfEven(3.5), 4);
  assert.equal(roundHalfEven(-0.5), 0);
  assert.equal(roundHalfEven(-1.5), -2);
});

test("ageAdjustment khớp bản Python (nội suy + làm tròn kiểu ngân hàng)", () => {
  const cases = [[0, false, 50], [0.5, false, 49], [7, false, 40], [18.5, false, 31], [29, false, 23],
    [31, false, 22], [90, false, 10], [135, false, 5], [180, false, 0], [400, false, -1], [400, true, 0],
    [730, false, -10], [5000, true, 0], [-3, false, 50]];
  for (const [days, impersonates, points] of cases) {
    const [adjust, reason] = ageAdjustment(Number(days), data.rules.age_curve, Boolean(impersonates));
    assert.equal(adjust, points, `ngày ${days}`);
    assert.equal(reason === "", adjust <= 0);
  }
  assert.equal(ageAdjustment(18.5, data.rules.age_curve, false)[1], "Tên miền mới đăng ký cách đây 18 ngày");
});

test("Tầng 1: dấu vân tay, khóa, nguồn và chống đầu độc", async () => {
  const fp = await Fingerprints.fromKeys(["evil.top", "bad.vn/login", "evil.top"]);
  assert.equal(fp.size, 2);
  assert.equal(await fp.lookup("a.b.evil.top", "/"), "evil.top");
  assert.equal(await fp.lookup("bad.vn", "/LOGIN/step2"), "bad.vn/login");
  assert.equal(await fp.lookup("bad.vn", "/"), null);
  const restored = Fingerprints.fromBuffer(fp.toBuffer());
  assert.equal(await restored.has("evil.top"), true);
  assert.throws(() => Fingerprints.fromBuffer(new ArrayBuffer(12)), RangeError);
  assert.deepEqual(candidateKeys("a.b.com.vn", "/x/y"), ["a.b.com.vn", "b.com.vn", "a.b.com.vn/x", "a.b.com.vn/x/y"]);
  assert.equal(entryKey("||Evil.TOP^$third-party"), "evil.top");
  assert.equal(entryKey("https://bad.vn/Login/"), "bad.vn/login");
  assert.equal(entryKey("# chú thích"), null);
  assert.equal(entryKey("localhost"), null);
  const { keys, skipped } = keysFromLines(["evil.top", "com.vn", "vietcombank.com.vn", "x.web.app"],
    ["vietcombank.com.vn"]);
  assert.deepEqual([...keys], ["evil.top", "x.web.app"]);
  assert.equal(skipped, 2);
  assert.deepEqual(parseSource('{"data": [{"url": "https://a.top/"}, "b.top", {"domain": "c.top"}]}'),
    ["https://a.top/", "b.top", "c.top"]);
  assert.deepEqual(parseSource('phish_id,url,phish_detail_url\n1,"https://x.top/a,b",y\n2,https://z.top/,y\n'),
    ["https://x.top/a,b", "https://z.top/"]);
  assert.deepEqual(parseSource("<!DOCTYPE html><html></html>"), []);
  assert.deepEqual(parseSource("﻿a.top\r\nb.top"), ["a.top", "b.top"]);
});

test("Tầng 3: ngày đăng ký, bootstrap, RDAP", () => {
  assert.equal(parseRegistrationDate("2024-01-05T10:20:30Z")?.toISOString(), "2024-01-05T10:20:30.000Z");
  assert.equal(parseRegistrationDate("2024-01-05T10:20:30.123+07:00")?.toISOString(), "2024-01-05T03:20:30.123Z");
  assert.equal(parseRegistrationDate("1997-09-15T04:00:00Z (UTC)")?.toISOString(), "1997-09-15T04:00:00.000Z");
  assert.equal(parseRegistrationDate("2024.01.05")?.toISOString(), "2024-01-05T00:00:00.000Z");
  assert.equal(parseRegistrationDate("2023-02-30"), null);
  assert.equal(parseRegistrationDate("x"), null);
  const table = parseBootstrap({ services: [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
    [["top"], ["http://insecure.example/", "https://rdap.nic.top"]], [["bad"], ["http://only-http/"]], "rác", [["xyz"]]] });
  assert.deepEqual(table, { com: "https://rdap.verisign.com/com/v1/", net: "https://rdap.verisign.com/com/v1/",
    top: "https://rdap.nic.top/" });
  assert.equal(rdapUrl("evil.top", table), "https://rdap.nic.top/domain/evil.top");
  assert.equal(rdapUrl("evil.vn", table), "https://rdap.org/domain/evil.vn");
  assert.throws(() => parseBootstrap({}), TypeError);
  const parsed = parseRdap({
    events: [{ eventAction: "registration", eventDate: "2024-03-01T00:00:00Z" },
      { eventAction: "registration", eventDate: "2024-02-01T00:00:00Z" }, { eventAction: "expiration", eventDate: "2020-01-01" }],
    entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["org", {}, "text", "ACME"]]] }],
  });
  assert.equal(parsed.created?.toISOString(), "2024-02-01T00:00:00.000Z");
  assert.equal(parsed.org, "ACME");
});

/**
 * @param {object} body
 * @param {number} [status]
 * @returns {Response}
 */
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/rdap+json" } });
}

test("Tầng 3: lookupAge dùng cache, nhớ thất bại 1 giờ, bỏ cuộc đúng hạn", async () => {
  /** @type {Map<string, any>} */
  const store = new Map();
  const cache = { get: async (/** @type {string} */ d) => store.get(d) ?? null,
    put: async (/** @type {string} */ d, /** @type {any} */ r) => { store.set(d, r); } };
  const now = Date.UTC(2026, 9, 22);
  let calls = 0;
  const fetchImpl = /** @type {typeof fetch} */ (async (url) => {
    calls += 1;
    assert.equal(String(url), "https://rdap.org/domain/evil.top");
    return jsonResponse({ events: [{ eventAction: "registration", eventDate: "2026-10-12T00:00:00Z" }] });
  });
  const info = await lookupAge("a.b.evil.top", { cache, fetchImpl, now: () => now });
  assert.equal(info?.ageDays, 10);
  assert.equal(info?.fromCache, false);
  const again = await lookupAge("evil.top", { cache, fetchImpl, now: () => now + 1000 });
  assert.equal(again?.fromCache, true);
  assert.equal(calls, 1);
  assert.equal(await lookupAge("1.2.3.4", { cache, fetchImpl }), null);
  assert.equal(await lookupAge("com.vn", { cache, fetchImpl }), null);

  const notFound = /** @type {typeof fetch} */ (async () => jsonResponse({ errorCode: 404 }, 404));
  assert.equal(await lookupAge("missing.top", { cache, fetchImpl: notFound, now: () => now }), null);
  assert.equal(store.get("missing.top")?.created, null);

  const hanging = /** @type {typeof fetch} */ ((_url, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  }));
  const started = Date.now();
  assert.equal(await lookupAge("slow.top", { cache, fetchImpl: hanging, timeoutMs: 200 }), null);
  assert.ok(Date.now() - started < 1000);
  assert.equal(store.has("slow.top"), false, "hết giờ thì không nhớ thất bại");
});

test("Pipeline: Tầng 3 cộng điểm tên miền mới, lời khuyên tắt khi đã có tuổi", async () => {
  const { engine } = await makeEngine({ tier3Enabled: true }, async () => ({ ageDays: 3, org: "", fromCache: false }));
  const result = await engine.inspect("https://vietcombsnk.com/");
  assert.equal(result.tierReached, 3);
  assert.equal(result.domainAgeDays, 3);
  assert.ok(result.signals.some((s) => s.code === "age" && s.points === 46));
  assert.equal(result.level, "HIGH");
  assert.equal(result.advice, "");

  const failing = await makeEngine({ tier3Enabled: true }, async () => { throw new Error("mạng hỏng"); });
  const degraded = await failing.engine.inspect("https://vietcombsnk.com/");
  assert.deepEqual(degraded.degraded, ["tier3"]);
  assert.equal(degraded.tierReached, 3);
  assert.notEqual(degraded.advice, "");

  const brokenBlacklist = new (await import("../src/engine/engine.js")).Engine({
    rules: data.rules, advice: data.advice, settings: { tier3Enabled: false, aiAdvice: true },
    blacklist: async () => { throw new Error("IndexedDB hỏng"); },
  });
  const fallback = await brokenBlacklist.inspect("https://vcb-digibank-xacthuc.top/");
  assert.deepEqual(fallback.degraded, ["tier1"]);
  assert.notEqual(fallback.level, "SAFE");

  const unparseable = await engine.inspect("https://exa mple.com/");
  assert.equal(unparseable.level, "WARN");
  assert.equal(unparseable.tierReached, 0);
});

test("Lời khuyên ưu tiên tổ hợp dấu hiệu", () => {
  const text = adviseSignals([{ code: "combosquat", points: 40, brand: "MoMo" }, { code: "lure", points: 24 }], data.advice);
  assert.ok(text.startsWith("Đây là kịch bản quen thuộc: giả danh MoMo"));
  assert.ok(text.endsWith(data.advice.general));
  assert.equal(adviseSignals([], data.advice), data.advice.general);
});

test("Tầng 3: máy chủ nhà đăng ký lỗi CORS thì thử rdap.org", async () => {
  /** @type {string[]} */
  const seen = [];
  const fetchImpl = /** @type {typeof fetch} */ (async (url) => {
    seen.push(String(url));
    if (String(url).startsWith("https://rdap.nic.top/")) throw new TypeError("Failed to fetch");
    return jsonResponse({ events: [{ eventAction: "registration", eventDate: "2026-10-01T00:00:00Z" }] });
  });
  const info = await lookupAge("x.top", { fetchImpl, bootstrap: { top: "https://rdap.nic.top/" },
    now: () => Date.UTC(2026, 9, 21) });
  assert.equal(info?.ageDays, 20);
  assert.deepEqual(seen, ["https://rdap.nic.top/domain/x.top", "https://rdap.org/domain/x.top"]);
});
