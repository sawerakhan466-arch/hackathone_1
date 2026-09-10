from rapidfuzz.fuzz import ratio
from package_sources import candidate_names, fetch_package, RegistryError
from utils import days_since


def similarity_score(a: str, b: str) -> float:
    return round(ratio(a.lower(), b.lower()) / 100, 3)


def find_typosquat(manager: str, entered: str):
    candidates = candidate_names(manager, entered)
    best_name = None
    best_score = 0.0
    for candidate in candidates:
        if candidate.lower() == entered.lower():
            continue
        score = similarity_score(entered, candidate)
        if score > best_score:
            best_name, best_score = candidate, score
    if not best_name:
        return None
    if best_score >= 0.86:
        severity = "HIGH"
    elif best_score >= 0.78:
        severity = "MEDIUM"
    else:
        return None
    return {"type": "Typosquatting", "severity": severity, "target": best_name, "similarity": best_score}


def query_osv(package, version):
    import requests
    ecosystem = "PyPI" if package["manager"] == "pip" else "npm"
    payload = {"package": {"name": package["name"], "ecosystem": ecosystem}}
    if version and version != "N/A":
        payload["version"] = version
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=12)
        r.raise_for_status()
        return r.json().get("vulns", []) or []
    except Exception:
        return []


def analyze_package(package):
    findings = []
    score = 0

    typo = find_typosquat(package["manager"], package["name"])
    if typo:
        score += 35 if typo["similarity"] >= 0.92 else 25
        findings.append({
            "title": "Possible Typosquatting",
            "severity": typo["severity"],
            "explanation": f"Package name is highly similar to {typo['target']}.",
            "evidence": f"Name similarity: {typo['similarity'] * 100:.1f}%.",
            "category": "heuristic",
            "typo": typo,
        })
    else:
        findings.append({
            "title": "Package Name Similarity",
            "severity": "SAFE",
            "explanation": "No strong similarity to the current popular-package comparison list was detected.",
            "evidence": "Heuristic name comparison only.",
            "category": "normal",
        })

    age_days = days_since(package.get("release_date"))
    if age_days is not None and age_days < 7:
        score += 5
        findings.append({
            "title": "Very Recent Package",
            "severity": "MEDIUM",
            "explanation": "The package appears to have been published within the last 7 days.",
            "evidence": f"Approximate age: {age_days} day(s). This is only a caution signal.",
            "category": "heuristic",
        })
    elif age_days is not None and age_days < 30:
        score += 2
        findings.append({
            "title": "Recently Published",
            "severity": "INFO",
            "explanation": "The package is relatively new.",
            "evidence": f"Approximate age: {age_days} day(s). New does not mean malicious.",
            "category": "heuristic",
        })

    if not package.get("repository"):
        score += 3
        findings.append({
            "title": "Repository Metadata Missing",
            "severity": "LOW",
            "explanation": "No repository URL was found in the registry metadata.",
            "evidence": "Repository field was empty or unavailable.",
            "category": "heuristic",
        })
    else:
        findings.append({
            "title": "Repository Information",
            "severity": "INFO",
            "explanation": "Repository information is available in registry metadata.",
            "evidence": package["repository"],
            "category": "normal",
        })

    if not package.get("author") or package.get("author") == "N/A":
        score += 2
        findings.append({
            "title": "Maintainer Information Limited",
            "severity": "LOW",
            "explanation": "Author or maintainer information was not clearly available.",
            "evidence": "Registry metadata did not provide a clear maintainer name.",
            "category": "heuristic",
        })

    deps = package.get("dependencies") or []
    if len(deps) > 100:
        score += 5
        findings.append({
            "title": "Large Dependency Set",
            "severity": "MEDIUM",
            "explanation": "The latest release declares a large number of direct dependencies.",
            "evidence": f"{len(deps)} direct dependencies were listed.",
            "category": "heuristic",
        })
    else:
        findings.append({
            "title": "Dependency Metadata",
            "severity": "INFO",
            "explanation": "Dependency information was retrieved from the registry.",
            "evidence": f"{len(deps)} direct dependencies listed.",
            "category": "normal",
        })

    vulnerabilities = query_osv(package, package.get("version"))
    if vulnerabilities:
        score += min(40, 20 + 5 * max(0, len(vulnerabilities) - 1))
        findings.append({
            "title": "Known Vulnerability Record",
            "severity": "HIGH",
            "explanation": f"A trusted vulnerability database returned {len(vulnerabilities)} record(s) for this package/version.",
            "evidence": ", ".join(v.get("id", "Unknown ID") for v in vulnerabilities[:5]),
            "category": "known_security",
            "vulnerabilities": vulnerabilities[:5],
        })
    else:
        findings.append({
            "title": "Vulnerability Check",
            "severity": "SAFE",
            "explanation": "No matching OSV vulnerability record was returned for the checked package/version.",
            "evidence": "This does not prove the package is completely safe.",
            "category": "normal",
        })

    score = min(100, score)
    if score <= 30:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    if level == "HIGH":
        action = "Do not install until you verify the package and its source."
    elif level == "MEDIUM":
        action = "Review the findings and verify the package before installing."
    else:
        action = "No major suspicious indicators were detected by the available checks. Verify the package name before installing."

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "typosquatting": typo,
        "recommended_action": action,
        "osv_vulnerabilities": vulnerabilities[:5],
    }


def full_scan(manager: str, name: str):
    package = fetch_package(manager, name)
    if not package:
        return None
    analysis = analyze_package(package)
    return {"package": package, "analysis": analysis}
