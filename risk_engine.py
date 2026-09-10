def risk_label(score: int) -> str:
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    return "HIGH"


def risk_summary(score: int, level: str) -> str:
    if level == "HIGH":
        return "Strong suspicious or known-security indicators were detected."
    if level == "MEDIUM":
        return "Some indicators deserve review before installation."
    return "No major suspicious indicators were detected by the available checks."
