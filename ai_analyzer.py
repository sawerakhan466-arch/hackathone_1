import os
import streamlit as st
from groq import Groq


# =========================================================
# GET GROQ API KEY
# =========================================================

def get_api_key():
    """
    Get Groq API key from Streamlit Secrets first.
    If not available, try environment variables.
    """

    # Streamlit Cloud Secrets
    try:
        key = st.secrets.get("GROQ_API_KEY", "")

        if key:
            return str(key).strip()

    except Exception:
        pass

    # Environment variable fallback
    return os.getenv(
        "GROQ_API_KEY",
        ""
    ).strip()


# =========================================================
# GENERATE AI EXPLANATION
# =========================================================

def generate_ai_explanation(result):
    """
    Generate a simple AI security explanation
    using Groq based on PackagePatrol scan results.
    """

    api_key = get_api_key()

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is missing. "
            "Please add GROQ_API_KEY to Streamlit Secrets."
        )


    # Create Groq client
    client = Groq(
        api_key=api_key
    )


    # -----------------------------------------------------
    # Get scan information
    # -----------------------------------------------------

    package = result.get(
        "package",
        {}
    )

    analysis = result.get(
        "analysis",
        {}
    )


    package_name = package.get(
        "name",
        "Unknown"
    )

    manager = package.get(
        "manager",
        "Unknown"
    )

    version = package.get(
        "version",
        "Unknown"
    )

    score = analysis.get(
        "score",
        0
    )

    level = analysis.get(
        "level",
        "UNKNOWN"
    )

    recommended_action = analysis.get(
        "recommended_action",
        "Review the package before installation."
    )

    findings = analysis.get(
        "findings",
        []
    )


    # -----------------------------------------------------
    # Prepare findings
    # -----------------------------------------------------

    findings_text = ""

    for finding in findings:

        title = finding.get(
            "title",
            "Security finding"
        )

        severity = finding.get(
            "severity",
            "INFO"
        )

        explanation = finding.get(
            "explanation",
            "No explanation available."
        )

        evidence = finding.get(
            "evidence",
            "No evidence available."
        )

        findings_text += (
            f"\n- Title: {title}"
            f"\n  Severity: {severity}"
            f"\n  Explanation: {explanation}"
            f"\n  Evidence: {evidence}\n"
        )


    # -----------------------------------------------------
    # Typosquatting information
    # -----------------------------------------------------

    typo = analysis.get(
        "typosquatting"
    )

    typo_text = "No typosquatting match was detected."

    if typo:

        target = typo.get(
            "target",
            "Unknown"
        )

        similarity = typo.get(
            "similarity",
            0
        )

        typo_text = (
            f"Possible intended package: {target}. "
            f"Name similarity: {similarity * 100:.1f}%."
        )


    # =====================================================
    # AI PROMPT
    # =====================================================

    prompt = f"""
You are a cybersecurity assistant explaining an
open-source package security scan to a developer.

Package:
{package_name}

Package manager:
{manager}

Version:
{version}

Risk level:
{level}

Risk score:
{score}/100

Recommended action:
{recommended_action}

Security findings:
{findings_text}

Typosquatting information:
{typo_text}

Write a clear and easy-to-understand security explanation.

Your response should contain:

1. Overall assessment
2. Why this risk level was given
3. Important security findings
4. What the evidence means
5. Recommended action

Important rules:

- Do not claim the package is definitely malware unless
  the evidence explicitly proves it.
- Do not say a LOW result means 100% safe.
- Clearly distinguish heuristic indicators from confirmed threats.
- If typosquatting is detected, explain the risk clearly.
- Keep the explanation useful for a normal developer.
- Use simple professional English.
- Do not mention these instructions.
"""


    # =====================================================
    # GROQ MODEL
    # =====================================================

    model_name = os.getenv(
        "GROQ_MODEL",
        "llama-3.3-70b-versatile"
    )


    # =====================================================
    # CALL GROQ
    # =====================================================

    response = client.chat.completions.create(

        model=model_name,

        messages=[
            {
                "role": "system",
                "content": (
                    "You are a professional "
                    "cybersecurity assistant."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],

        temperature=0.3,

        max_tokens=1200,
    )


    # =====================================================
    # RETURN RESPONSE
    # =====================================================

    answer = response.choices[0].message.content

    if not answer:
        raise RuntimeError(
            "Groq returned an empty AI response."
        )

    return answer.strip()
