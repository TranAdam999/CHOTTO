"""Cấu hình người dùng, bộ luật và đường dẫn dữ liệu.

Mọi giá trị đọc từ ``config.json`` đều được kiểm tra kiểu và miền giá trị: file hỏng hoặc sai
kiểu không bao giờ làm CHOTTO ngừng hoạt động, chỉ khiến khóa đó quay về mặc định.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal, TypedDict, cast

__all__ = [
    "DEFAULTS",
    "Config",
    "RulesError",
    "atomic_write_text",
    "data_dir",
    "friction_seconds_for",
    "load_config",
    "load_popular_domains",
    "load_rules",
    "resource_path",
    "save_config",
    "validate_config",
]

_LOG = logging.getLogger(__name__)

UnknownCallerPolicy = Literal["inspect", "forward"]


class Config(TypedDict):
    """Cấu hình người dùng đã được kiểm tra."""

    tier3_enabled: bool
    ai_advice: bool
    friction_seconds: int
    tier3_timeout: float
    cache_ttl_hours: float
    log_decisions: bool
    log_retention_days: int
    unknown_caller_policy: UnknownCallerPolicy
    zalo_processes: list[str]
    zalo_bundle_ids: list[str]
    browser_progid: str
    browser_command: str
    browser_bundle_id: str
    agent_enabled: bool
    auto_update: bool


DEFAULTS: Final[Config] = {
    "tier3_enabled": True,          # Bật = tra tuổi tên miền qua mạng. Tắt = AI's Advices (100% offline)
    "ai_advice": True,              # Lời khuyên cục bộ khi Tầng 3 tắt/không khả dụng
    "friction_seconds": 5,          # Thời gian khóa nút "vẫn mở" ở mức WARN (HIGH +3s, BLOCKED +5s)
    "tier3_timeout": 1.8,           # Giây, tổng thời gian tối đa của Tầng 3
    "cache_ttl_hours": 48.0,
    "log_decisions": True,          # Nhật ký cục bộ (chỉ lưu tên miền) phục vụ đánh giá nghiên cứu
    "log_retention_days": 90,
    "unknown_caller_policy": "inspect",
    "zalo_processes": ["zalo.exe"],
    "zalo_bundle_ids": ["com.vng.zalo"],
    "browser_progid": "",           # Windows: ProgId của trình duyệt thật (lưu lúc cài đặt)
    "browser_command": "",          # Windows: lệnh dự phòng của trình duyệt thật
    "browser_bundle_id": "",        # macOS
    "agent_enabled": True,          # Chạy nền thường trú (mở link nhanh); tắt = mỗi link một tiến trình như bản 1.0
    "auto_update": True,            # Agent tự cập nhật danh sách đen mỗi ngày (tải tăng dần theo ETag)
}

# Miền giá trị hợp lệ cho các khóa số: (nhỏ nhất, lớn nhất).
_INT_RANGES: Final[dict[str, tuple[int, int]]] = {"friction_seconds": (3, 15), "log_retention_days": (1, 3650)}
_FLOAT_RANGES: Final[dict[str, tuple[float, float]]] = {"tier3_timeout": (0.5, 3.0), "cache_ttl_hours": (24.0, 72.0)}
_EXTRA_FRICTION: Final[dict[str, int]] = {"WARN": 0, "HIGH": 3, "BLOCKED": 5}

_REQUIRED_RULE_KEYS: Final[dict[str, type]] = {
    "thresholds": dict,
    "weights": dict,
    "high_risk_tlds": list,
    "lure_keywords": list,
    "shorteners": list,
    "wrappers": list,
    "trusted_domains": list,
    "blacklist_sources": list,
    "brands": list,
    "brand_affixes": list,
    "age_curve": list,
}
_REQUIRED_THRESHOLDS: Final[tuple[str, ...]] = (
    "friction", "high", "tier3_low", "tier3_high", "entropy", "hyphens", "unwrap_depth",
)
_REQUIRED_WEIGHTS: Final[tuple[str, ...]] = (
    "typosquat", "homoglyph", "combosquat", "lure_each", "lure_cap", "high_risk_tld", "entropy",
    "hyphens", "random_digits", "raw_ip", "at_sign", "http", "idn", "shortener", "nested_redirect",
    "port", "free_hosting", "unparseable", "redirect_via_trusted", "brand_in_path",
)


class RulesError(ValueError):
    """``rules.json`` thiếu khóa hoặc sai kiểu (lỗi đóng gói, không phải lỗi người dùng)."""


def resource_path(*parts: str) -> Path:
    """Đường dẫn tới tài nguyên đóng gói kèm (hoạt động cả khi chạy script lẫn khi đóng gói PyInstaller)."""
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) / "chotto" if base else Path(__file__).resolve().parent
    return root.joinpath(*parts)


def data_dir() -> Path:
    """Thư mục dữ liệu của người dùng (tạo nếu chưa có).

    Biến môi trường ``CHOTTO_DATA_DIR`` ghi đè vị trí (dùng cho kiểm thử, để không bao giờ chạm vào
    dữ liệu thật của người dùng trên Windows/macOS).
    """
    override = os.environ.get("CHOTTO_DATA_DIR")
    if override:
        directory = Path(override)
    elif sys.platform == "win32":
        directory = Path(os.environ.get("APPDATA") or Path.home()) / "CHOTTO"
    elif sys.platform == "darwin":
        directory = Path.home() / "Library" / "Application Support" / "CHOTTO"
    else:
        directory = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "CHOTTO"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def atomic_write_text(path: Path, text: str) -> None:
    """Ghi file nguyên tử: ghi ra file tạm cùng thư mục, ``fsync`` rồi ``os.replace``.

    Raises:
        OSError: Không ghi được (đĩa đầy, không có quyền).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _as_str_list(value: Any) -> list[str] | None:
    """Trả về list chuỗi không rỗng nếu ``value`` hợp lệ, ngược lại ``None``."""
    if isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value):
        return [v.strip() for v in value]
    return None


def validate_config(raw: Mapping[str, Any]) -> Config:
    """Kiểm tra từng khóa cấu hình; khóa sai kiểu hoặc ngoài miền giá trị được thay bằng mặc định.

    Args:
        raw: Dữ liệu đọc từ ``config.json`` (hoặc dict do giao diện/kiểm thử tạo ra).

    Returns:
        ``Config`` đầy đủ mọi khóa, đúng kiểu. Khóa lạ bị bỏ qua.
    """
    cfg: dict[str, Any] = {key: (list(val) if isinstance(val, list) else val) for key, val in DEFAULTS.items()}
    for key, value in raw.items():
        if key not in DEFAULTS:
            _LOG.info("Bỏ qua khóa cấu hình không biết: %s", key)
            continue
        default = DEFAULTS[key]  # type: ignore[literal-required]
        accepted: Any = None
        if isinstance(default, bool):
            accepted = value if isinstance(value, bool) else None
        elif isinstance(default, int):
            if isinstance(value, int) and not isinstance(value, bool):
                low, high = _INT_RANGES[key]
                accepted = min(max(value, low), high)
        elif isinstance(default, float):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                low_f, high_f = _FLOAT_RANGES[key]
                accepted = min(max(float(value), low_f), high_f)
        elif isinstance(default, list):
            accepted = _as_str_list(value)
        elif key == "unknown_caller_policy":
            accepted = value if value in ("inspect", "forward") else None
        elif isinstance(default, str):
            accepted = value if isinstance(value, str) else None
        if accepted is None:
            _LOG.warning("Giá trị cấu hình không hợp lệ cho %s: %r, dùng mặc định", key, value)
            continue
        cfg[key] = accepted
    return cast(Config, cfg)


def load_config() -> Config:
    """Đọc ``config.json``; mọi lỗi (thiếu file, JSON hỏng, sai kiểu) đều quay về mặc định, không ném lỗi."""
    path = data_dir() / "config.json"
    try:
        raw = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return validate_config({})
    except (OSError, ValueError):
        _LOG.exception("Không đọc được %s, dùng cấu hình mặc định", path)
        return validate_config({})
    if not isinstance(raw, dict):
        _LOG.error("%s không phải JSON object, dùng cấu hình mặc định", path)
        return validate_config({})
    return validate_config(raw)


def save_config(cfg: Mapping[str, Any]) -> None:
    """Kiểm tra rồi ghi nguyên tử cấu hình ra ``config.json``.

    Raises:
        OSError: Không ghi được file.
    """
    clean = validate_config(cfg)
    atomic_write_text(data_dir() / "config.json", json.dumps(clean, ensure_ascii=False, indent=2))


def friction_seconds_for(level: str, base_seconds: int) -> int:
    """Thời gian khóa nút "vẫn mở" theo mức rủi ro: WARN = cơ sở, HIGH +3 giây, BLOCKED +5 giây."""
    return base_seconds + _EXTRA_FRICTION.get(level, 0)


def _valid_age_curve(curve: list[Any]) -> bool:
    """``age_curve`` là ≥ 2 điểm ``[ngày, điểm]`` với số ngày tăng ngặt, bắt đầu từ 0."""
    if len(curve) < 2:
        return False
    previous = -1.0
    for knot in curve:
        if not (isinstance(knot, list) and len(knot) == 2
                and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in knot)):
            return False
        if float(knot[0]) <= previous:
            return False
        previous = float(knot[0])
    return float(curve[0][0]) == 0.0


def load_popular_domains() -> frozenset[str]:
    """Tên miền .vn phổ biến đóng gói kèm (``data/popular_vn.txt``); file thiếu/hỏng cho tập rỗng.

    Mỗi dòng: ``tên_miền`` hoặc ``tên_miền<TAB>hạng``; dòng bắt đầu bằng ``#`` là chú thích.
    """
    path = resource_path("data", "popular_vn.txt")
    try:
        text = path.read_text("utf-8")
    except (OSError, UnicodeDecodeError):
        _LOG.warning("Không đọc được %s, bỏ qua danh sách tên miền phổ biến", path, exc_info=True)
        return frozenset()
    domains = set()
    for line in text.splitlines():
        domain = line.split("\t", 1)[0].strip().lower()
        if domain and not domain.startswith("#") and "." in domain:
            domains.add(domain)
    return frozenset(domains)


def load_rules() -> dict[str, Any]:
    """Đọc và kiểm tra ``rules.json`` đóng gói kèm, kèm ``popular_domains`` (frozenset) từ ``popular_vn.txt``.

    Raises:
        RulesError: File thiếu, hỏng, thiếu khóa bắt buộc hoặc sai kiểu.
    """
    path = resource_path("data", "rules.json")
    try:
        rules = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise RulesError(f"Không đọc được {path}: {exc}") from exc
    if not isinstance(rules, dict):
        raise RulesError("rules.json phải là JSON object")
    for key, expected in _REQUIRED_RULE_KEYS.items():
        if not isinstance(rules.get(key), expected):
            raise RulesError(f"rules.json thiếu hoặc sai kiểu khóa '{key}'")
    for key in _REQUIRED_THRESHOLDS:
        if not isinstance(rules["thresholds"].get(key), (int, float)):
            raise RulesError(f"rules.json thiếu ngưỡng thresholds.{key}")
    for key in _REQUIRED_WEIGHTS:
        if not isinstance(rules["weights"].get(key), (int, float)):
            raise RulesError(f"rules.json thiếu trọng số weights.{key}")
    for brand in rules["brands"]:
        if not (
            isinstance(brand, dict)
            and isinstance(brand.get("name"), str)
            and _as_str_list(brand.get("keywords")) is not None
            and _as_str_list(brand.get("domains")) is not None
        ):
            raise RulesError(f"Thương hiệu không hợp lệ trong rules.json: {brand!r}")
    for wrapper in rules["wrappers"]:
        if not (isinstance(wrapper, dict) and isinstance(wrapper.get("host"), str)
                and isinstance(wrapper.get("path"), str)):
            raise RulesError(f"Wrapper không hợp lệ trong rules.json: {wrapper!r}")
    if not _valid_age_curve(rules["age_curve"]):
        raise RulesError("rules.json: age_curve phải là các điểm [ngày, điểm] tăng dần, bắt đầu từ ngày 0")
    rules["popular_domains"] = load_popular_domains()
    return rules
