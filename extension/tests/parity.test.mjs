// @ts-check
/**
 * Bộ test dùng chung: engine JavaScript phải cho đúng kết quả của engine Python trên mọi vector trong
 * ``tests/data/engine_vectors.json`` (sinh bởi ``tools/gen_engine_vectors.py``).
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";

import { REPO_DIR, makeEngine } from "./helpers.mjs";

test("engine JS khớp engine Python trên toàn bộ vector dùng chung", async () => {
  const payload = JSON.parse(await readFile(path.join(REPO_DIR, "tests", "data", "engine_vectors.json"), "utf-8"));
  const { engine } = await makeEngine();
  const mismatches = [];
  for (const expected of payload.vectors) {
    const result = await engine.inspect(expected.url);
    const actual = {
      url: expected.url,
      score: result.score,
      level: result.level,
      tier: result.tierReached,
      host: result.host,
      display_domain: result.displayDomain,
      reasons: result.reasons,
      signals: result.signals.map((s) => [s.code, s.points, s.brand ?? ""]),
      advice: result.advice,
    };
    try {
      assert.deepStrictEqual(actual, expected);
    } catch {
      mismatches.push({ expected, actual });
    }
  }
  if (mismatches.length) {
    for (const { expected, actual } of mismatches.slice(0, 15)) {
      console.error("URL:", expected.url);
      for (const key of Object.keys(expected)) {
        if (JSON.stringify(expected[key]) !== JSON.stringify(/** @type {any} */ (actual)[key])) {
          console.error(`  ${key}: py=${JSON.stringify(expected[key])}\n  ${" ".repeat(key.length)}  js=${JSON.stringify(/** @type {any} */ (actual)[key])}`);
        }
      }
    }
  }
  assert.equal(mismatches.length, 0, `${mismatches.length}/${payload.vectors.length} vector lệch`);
  assert.ok(payload.vectors.length > 100);
});
