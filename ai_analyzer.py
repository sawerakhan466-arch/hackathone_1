import os
import requests


def _secret(name):
    value = os.getenv(name)
    if value:
        return value
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None


def generate_ai_explanation(scan_result):
    api_key = _secret("GROQ_API_KEY")
    if not api_key:
        return None

    model = _secret("GROQ_MODEL") or "openai/gpt-oss-20b"
    package = scan_result["package"]
    analysis = scan_result["analysis"]
    evidence = {
        "package": package["name"],
        "manager": package["manager"],
        "version": package["version"],
        "risk_score": analysis["score"],
        "risk_level": analysis["level"],
        "typosquatting": analysis["typosquatting"],
        "findings": analysis["findings"],
        "recommended_action": analysis["recommended_action"],
    }

    system = (
        "You are a defensive software supply-chain security assistant. "
        "Explain only the evidence supplied by the application. Never invent malware, "
        "authors, vulnerabilities, downloads, or security facts. Clearly distinguish "
        "heuristic warnings from known vulnerability records. Keep the answer concise, "
        "practical, and understandable to a developer."
    )
    user = (
        "Write a short 'AI Security Analysis' with three headings: Why it matters, "
        "Evidence, Recommended action. Mention that heuristic checks are not proof of malware. "
        f"Here is the scan data:\n{evidence}"
    )

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.2,
                "max_tokens": 500,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None
