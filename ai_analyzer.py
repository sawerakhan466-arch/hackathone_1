import os
import streamlit as st
from groq import Groq


def generate_ai_explanation(result):

    # Get Groq API key from Streamlit Secrets
    api_key = st.secrets.get("GROQ_API_KEY", None)

    # Fallback to environment variable
    if not api_key:
        api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError(
            "GROQ_API_KEY is missing from Streamlit Secrets."
        )

    # Create Groq client
    client = Groq(api_key=api_key)

    package = result["package"]
    analysis = result["analysis"]

    findings_text = "\n".join(
        [
            f"- {f.get('title', 'Finding')} "
            f"[{f.get('severity', 'INFO')}]: "
            f"{f.get('explanation', '')}"
            for f in analysis.get("findings", [])
        ]
    )

    prompt = f"""
You are a cybersecurity analyst helping users understand
open-source package security.

Analyze the following PackagePatrol AI scan.

Package: {package.get('name')}
Package Manager: {package.get('manager')}
Version: {package.get('version')}

Risk Score: {analysis.get('score')}/100
Risk Level: {analysis.get('level')}

Security Findings:
{findings_text}

Give a simple and clear security explanation.

Include:

1. Overall assessment
2. Why this risk score was given
3. Important security findings
4. What the user should do

Important:
- Do not say the package is malware unless there is clear evidence.
- Heuristic findings are indicators, not proof of malware.
- Keep the explanation easy to understand.
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2,
    )

    return response.choices[0].message.content
