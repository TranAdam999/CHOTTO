// @ts-check
/** Dựng engine cho kiểm thử Node từ đúng dữ liệu đóng gói trong ``extension/data``. */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { loadEngineData } from "../src/engine/data.js";
import { Engine } from "../src/engine/engine.js";
import { Fingerprints, keysFromLines, protectedDomains } from "../src/engine/tier1.js";

export const EXTENSION_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_DIR = path.resolve(EXTENSION_DIR, "..");

/**
 * Nạp dữ liệu engine từ đĩa.
 * @returns {Promise<import("../src/engine/data.js").EngineData>}
 */
export async function loadData() {
  return loadEngineData((name) => readFile(path.join(EXTENSION_DIR, "data", name), "utf-8"));
}

/**
 * Engine với Tầng 1 = danh sách đen khởi tạo, Tầng 3 tắt (giống ``tools/gen_engine_vectors.py``).
 * @param {Partial<import("../src/engine/engine.js").EngineSettings>} [settings]
 * @param {((host: string) => Promise<import("../src/engine/tier3.js").AgeInfo | null>) | null} [ageLookup]
 * @returns {Promise<{engine: Engine, data: import("../src/engine/data.js").EngineData}>}
 */
export async function makeEngine(settings = {}, ageLookup = null) {
  const data = await loadData();
  const { keys } = keysFromLines(data.seed, protectedDomains(data.rules));
  const fingerprints = await Fingerprints.fromKeys(keys);
  const engine = new Engine({
    rules: data.rules,
    advice: data.advice,
    settings: { tier3Enabled: false, aiAdvice: true, ...settings },
    blacklist: async () => fingerprints,
    ageLookup,
  });
  return { engine, data };
}
