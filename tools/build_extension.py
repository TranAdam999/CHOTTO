#!/usr/bin/env python3
"""Đóng gói tiện ích trình duyệt CHOTTO thành file .zip cho Chrome/Edge và Firefox.

- Kiểm tra dữ liệu ``extension/data`` khớp ``chotto/data`` (không khớp thì dừng, tránh hai bản chấm khác nhau).
- Kiểm tra phiên bản trong ``manifest.json`` trùng ``chotto.__version__``.
- Bản Chrome/Edge: nguyên ``manifest.json`` (service worker MV3).
- Bản Firefox (≥ 128): ``background.scripts`` thay cho ``service_worker``, thêm ``browser_specific_settings``.
- Chỉ đóng gói file chạy thật (manifest, ``src``, ``data``, ``icons``); bỏ test, e2e, node_modules.

Ví dụ:
  python tools/build_extension.py              # ghi vào dist/
  python tools/build_extension.py --out build/
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from chotto import __version__  # noqa: E402
import sync_extension_data  # noqa: E402

EXTENSION: Final[Path] = ROOT / "extension"
PACKAGED_DIRS: Final[tuple[str, ...]] = ("src", "data", "icons")
GECKO_ID: Final[str] = "chotto@tranadam999.github.io"
FIREFOX_MIN_VERSION: Final[str] = "128.0"
# Cố định thời điểm trong zip để hai lần build cùng mã cho cùng file.
ZIP_TIMESTAMP: Final[tuple[int, int, int, int, int, int]] = (2026, 1, 1, 0, 0, 0)


class BuildError(RuntimeError):
    """Không đóng gói được (dữ liệu lệch, thiếu file, sai phiên bản)."""


def load_manifest() -> dict[str, Any]:
    """Đọc ``extension/manifest.json`` và kiểm tra phiên bản.

    Raises:
        BuildError: Không đọc được hoặc phiên bản khác ``chotto.__version__``.
    """
    try:
        manifest = json.loads((EXTENSION / "manifest.json").read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"Không đọc được manifest.json: {exc}") from exc
    if manifest.get("version") != __version__:
        raise BuildError(f"manifest.json là {manifest.get('version')}, chotto là {__version__}")
    return manifest


def firefox_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Biến thể manifest cho Firefox."""
    variant = json.loads(json.dumps(manifest))
    worker = variant["background"].pop("service_worker")
    variant["background"]["scripts"] = [worker]
    variant.pop("minimum_chrome_version", None)
    variant["browser_specific_settings"] = {"gecko": {"id": GECKO_ID, "strict_min_version": FIREFOX_MIN_VERSION}}
    return variant


def packaged_files() -> list[Path]:
    """Các file chạy thật của tiện ích (đường dẫn tuyệt đối, đã sắp xếp).

    Raises:
        BuildError: Thiếu thư mục bắt buộc.
    """
    files: list[Path] = []
    for name in PACKAGED_DIRS:
        directory = EXTENSION / name
        if not directory.is_dir():
            raise BuildError(f"Thiếu thư mục extension/{name}")
        files.extend(p for p in directory.rglob("*") if p.is_file() and p.name != ".DS_Store")
    return sorted(files)


def write_zip(target: Path, manifest: dict[str, Any], files: list[Path]) -> None:
    """Ghi một gói .zip.

    Raises:
        OSError: Không ghi được file.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("manifest.json", ZIP_TIMESTAMP)
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        for path in files:
            entry = zipfile.ZipInfo(path.relative_to(EXTENSION).as_posix(), ZIP_TIMESTAMP)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, path.read_bytes())
    tmp.replace(target)


def main(argv: list[str] | None = None) -> int:
    """Điểm vào dòng lệnh. Trả về 0 nếu thành công, 1 nếu lỗi."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    args = parser.parse_args(argv)
    try:
        if sync_extension_data.main(["--check"]) != 0:
            raise BuildError("Dữ liệu tiện ích lệch với chotto/data")
        manifest = load_manifest()
        files = packaged_files()
        chrome_zip = args.out / f"chotto-extension-chrome-{__version__}.zip"
        firefox_zip = args.out / f"chotto-extension-firefox-{__version__}.zip"
        write_zip(chrome_zip, manifest, files)
        write_zip(firefox_zip, firefox_manifest(manifest), files)
    except (BuildError, OSError) as exc:
        print(f"Đóng gói thất bại: {exc}", file=sys.stderr)
        return 1
    print(f"Đã tạo {chrome_zip} và {firefox_zip} ({len(files) + 1} file mỗi gói)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
