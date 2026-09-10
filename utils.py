import json
import re
from datetime import datetime, timezone
from urllib.parse import quote


def clean_package_name(name: str) -> str:
    return (name or "").strip()


def valid_package_name(name: str, manager: str) -> bool:
    if not name:
        return False
    if len(name) > 214:
        return False
    if manager == "pip":
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name))
    if manager == "npm":
        return bool(re.fullmatch(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+", name))
    return False


def iso_to_datetime(value):
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def format_date(value) -> str:
    dt = iso_to_datetime(value)
    return dt.strftime("%Y-%m-%d") if dt else "N/A"


def days_since(value):
    dt = iso_to_datetime(value)
    if not dt:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


def safe_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def package_url(manager: str, name: str) -> str:
    if manager == "pip":
        return f"https://pypi.org/project/{quote(name)}/"
    return f"https://www.npmjs.com/package/{quote(name, safe='@/') }"


def risk_color(level: str) -> str:
    return {"LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#ef4444"}.get(level, "#64748b")


def risk_emoji(level: str) -> str:
    return {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(level, "⚪")
