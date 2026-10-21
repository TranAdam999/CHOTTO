"""Build CHOTTO.app cho macOS (chạy từ thư mục gốc dự án):
    pip install -r requirements.txt && python packaging/macos_setup.py py2app
Info.plist khai báo CHOTTO xử lý http/https để xuất hiện trong "Trình duyệt web mặc định"."""
import sys
from typing import Any

from setuptools import setup

if sys.version_info < (3, 11):
    raise SystemExit("CHOTTO cần Python 3.11 trở lên.")

VERSION = "1.3.0"

# Không khai báo CFBundleDocumentTypes: CHOTTO chỉ nhận link qua Apple Event kAEGetURL
# (::tk::mac::LaunchURL). Khai báo kiểu tài liệu HTML mà không xử lý OpenDocument sẽ khiến
# file .html/.webloc mở bằng CHOTTO bị nuốt im lặng.
PLIST = {
    "CFBundleName": "CHOTTO",
    "CFBundleDisplayName": "CHOTTO",
    "CFBundleIdentifier": "vn.chotto.app",
    "CFBundleVersion": VERSION,
    "CFBundleShortVersionString": VERSION,
    "LSMinimumSystemVersion": "11.0",
    "NSHighResolutionCapable": True,
    "LSUIElement": True,                         # không hiện icon Dock khi chạy nền
    "CFBundleURLTypes": [{"CFBundleURLName": "Web URL", "CFBundleURLSchemes": ["http", "https"]}],
}

# Khai báo kiểu Any: stub của setuptools chỉ cho phép Mapping[str, Mapping[str, str]],
# trong khi py2app cần giá trị là dict/list/bool.
OPTIONS: dict[str, Any] = {
    "py2app": {
        "plist": PLIST,
        "packages": ["chotto"],                  # kéo theo chotto/data (rules, PSL, confusables, seed)
        "includes": ["tkinter"],
        "argv_emulation": False,   # phải tắt: link http(s) đến qua Apple Event (::tk::mac::LaunchURL), không qua argv
    }
}

setup(
    name="CHOTTO",
    version=VERSION,
    app=["main.py"],
    packages=[],            # tắt auto-discovery của setuptools (thư mục gốc có nhiều package: chotto, tests, packaging)
    options=OPTIONS,
)
