// Sinh lại kết quả mong đợi trong url_vectors.json bằng parser WHATWG của Node.js (giống Chrome).
// Cách dùng: node tests/data/generate_url_vectors.js tests/data/url_vectors.json
// Chỉ đọc trường "input" của mỗi vector; các trường khác được tính lại.
"use strict";

const fs = require("fs");

function expected(input) {
  let parsed;
  try {
    parsed = new URL(input);
  } catch (error) {
    return { input, valid: false };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { input, valid: false };
  }
  const vector = { input, valid: true, href: parsed.href, host: parsed.hostname };
  if (parsed.hostname.endsWith(".")) {
    // CHOTTO bỏ dấu chấm cuối: "example.com." và "example.com" là cùng một tên DNS.
    const host = parsed.hostname.replace(/\.+$/, "");
    vector.href = parsed.href.replace(`${parsed.hostname}/`, `${host}/`);
    vector.host = host;
    vector.note = "CHOTTO bỏ dấu chấm cuối tên miền (cùng một tên DNS)";
  }
  return vector;
}

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("Thiếu đường dẫn url_vectors.json");
    process.exit(2);
  }
  const document = JSON.parse(fs.readFileSync(file, "utf8"));
  document.vectors = document.vectors.map((vector) => expected(vector.input));
  fs.writeFileSync(file, JSON.stringify(document, null, 1) + "\n", "utf8");
  console.log(`Đã sinh ${document.vectors.length} vector`);
}

main();
