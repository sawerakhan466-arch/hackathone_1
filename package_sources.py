import requests
from urllib.parse import quote

TIMEOUT = 12
HEADERS = {"User-Agent": "PackagePatrol-AI/1.0 (defensive package metadata scanner)"}

PYPI_POPULAR = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "scikit-learn",
    "matplotlib", "seaborn", "tensorflow", "torch", "pillow", "beautifulsoup4",
    "selenium", "pytest", "cryptography", "sqlalchemy", "boto3", "rich", "streamlit",
    "httpx", "pydantic", "uvicorn", "celery", "opencv-python", "sympy", "scipy"
]

NPM_POPULAR = [
    "express", "react", "react-dom", "axios", "lodash", "next", "vue", "angular",
    "typescript", "webpack", "vite", "chalk", "commander", "moment", "dotenv",
    "jsonwebtoken", "mongoose", "eslint", "prettier", "tailwindcss", "cors", "uuid",
    "jQuery", "socket.io", "npm", "node-fetch"
]


class RegistryError(Exception):
    pass


def _get(url, params=None):
    try:
        response = requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise RegistryError(str(exc)) from exc
    except ValueError as exc:
        raise RegistryError("Registry returned malformed JSON") from exc


def fetch_pypi(name: str):
    data = _get(f"https://pypi.org/pypi/{quote(name)}/json")
    if not data:
        return None
    info = data.get("info", {})
    releases = data.get("releases", {}) or {}
    release_dates = []
    for version, files in releases.items():
        for item in files or []:
            if item.get("upload_time_iso_8601"):
                release_dates.append(item["upload_time_iso_8601"])
    latest = info.get("version")
    first_release = min(release_dates) if release_dates else None
    last_release = max(release_dates) if release_dates else None
    urls = info.get("project_urls") or {}
    repository = None
    homepage = info.get("home_page")
    for key, value in urls.items():
        if any(word in key.lower() for word in ["source", "repository", "github", "gitlab"]):
            repository = value
            break
    if not repository:
        repository = urls.get("Repository") or urls.get("Source")

    return {
        "name": info.get("name") or name,
        "manager": "pip",
        "version": latest or "N/A",
        "author": info.get("author") or info.get("maintainer") or "N/A",
        "maintainers": [],
        "description": info.get("summary") or "No description provided.",
        "homepage": homepage,
        "repository": repository,
        "license": info.get("license") or "N/A",
        "release_date": first_release,
        "last_updated": last_release,
        "versions_count": len(releases),
        "dependencies": info.get("requires_dist") or [],
        "package_url": f"https://pypi.org/project/{quote(name)}/",
        "downloads": None,
        "raw": data,
    }


def fetch_npm(name: str):
    encoded = quote(name, safe="@/")
    data = _get(f"https://registry.npmjs.org/{encoded}")
    if not data:
        return None
    latest = (data.get("dist-tags") or {}).get("latest")
    versions = data.get("versions") or {}
    latest_meta = versions.get(latest, {}) if latest else {}
    maintainers = data.get("maintainers") or []
    author = data.get("author")
    if isinstance(author, dict):
        author = author.get("name")
    if not author and maintainers:
        author = maintainers[0].get("name")
    repository = data.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url")
    time_map = data.get("time") or {}
    release_dates = [v for k, v in time_map.items() if k not in {"created", "modified"}]
    return {
        "name": data.get("name") or name,
        "manager": "npm",
        "version": latest or "N/A",
        "author": author or "N/A",
        "maintainers": [m.get("name") for m in maintainers if m.get("name")],
        "description": data.get("description") or "No description provided.",
        "homepage": data.get("homepage"),
        "repository": repository,
        "license": (latest_meta.get("license") or data.get("license") or "N/A"),
        "release_date": time_map.get("created") or (min(release_dates) if release_dates else None),
        "last_updated": time_map.get("modified") or (max(release_dates) if release_dates else None),
        "versions_count": len(versions),
        "dependencies": list((latest_meta.get("dependencies") or {}).keys()),
        "package_url": f"https://www.npmjs.com/package/{quote(name, safe='@/')}",
        "downloads": None,
        "raw": data,
    }


def search_npm(name: str, size: int = 20):
    data = _get("https://registry.npmjs.org/-/v1/search", params={"text": name, "size": size})
    if not data:
        return []
    return [item.get("package", {}).get("name") for item in data.get("objects", []) if item.get("package", {}).get("name")]


def get_downloads(name: str):
    encoded = quote(name, safe="@/")
    data = _get(f"https://api.npmjs.org/downloads/point/last-week/{encoded}")
    return data.get("downloads") if data else None


def candidate_names(manager: str, entered: str):
    if manager == "pip":
        base = list(PYPI_POPULAR)
        # PyPI does not expose a stable general-purpose search API for this use case.
        return base
    base = list(NPM_POPULAR)
    try:
        base.extend(search_npm(entered, size=20))
    except RegistryError:
        pass
    return list(dict.fromkeys(base))


def fetch_package(manager: str, name: str):
    package = fetch_pypi(name) if manager == "pip" else fetch_npm(name)
    if package and manager == "npm":
        try:
            package["downloads"] = get_downloads(name)
        except RegistryError:
            package["downloads"] = None
    return package
