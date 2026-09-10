import json
import sqlite3
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from ai_analyzer import generate_ai_explanation
from analyzer import full_scan
from risk_engine import risk_summary
from utils import clean_package_name, package_url, risk_color, risk_emoji, valid_package_name

DB_FILE = "packagepatrol.db"

st.set_page_config(page_title="PackagePatrol AI", page_icon="🛡️", layout="wide")


def db_connect():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            manager TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            top_threat TEXT
        )"""
    )
    conn.commit()
    return conn


conn = db_connect()


def save_scan(name, manager, score, level, findings):
    threat = "None"
    for f in findings:
        if f.get("severity") in {"HIGH", "MEDIUM"} and f.get("category") != "normal":
            threat = f.get("title", "Security indicator")
            break
    conn.execute(
        "INSERT INTO scans(package_name, manager, score, level, timestamp, top_threat) VALUES (?, ?, ?, ?, ?, ?)",
        (name, manager, score, level, datetime.now(timezone.utc).isoformat(), threat),
    )
    conn.commit()


def load_history(limit=100):
    return pd.read_sql_query(
        "SELECT package_name, manager, score, level, timestamp, top_threat FROM scans ORDER BY id DESC LIMIT ?",
        conn,
        params=(limit,),
    )


def render_css():
    st.markdown(
        """
        <style>
        .block-container {padding-top: 2rem; padding-bottom: 3rem; max-width: 1250px;}
        .hero {padding: 1.5rem 1.7rem; border: 1px solid rgba(100,116,139,.25); border-radius: 18px; background: linear-gradient(135deg, rgba(15,23,42,.98), rgba(30,41,59,.92)); color: white; margin-bottom: 1rem;}
        .hero h1 {margin: 0; font-size: 2.4rem;}
        .hero p {margin: .45rem 0 0; color: #cbd5e1;}
        .risk-card {padding: 1.2rem; border-radius: 18px; border: 1px solid rgba(100,116,139,.25); background: rgba(15,23,42,.04);}
        .finding {padding: 1rem; border-radius: 14px; border: 1px solid rgba(100,116,139,.2); margin: .5rem 0;}
        .muted {color: #64748b; font-size: .9rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )


render_css()

st.markdown(
    '<div class="hero"><h1>🛡️ PackagePatrol AI</h1><p>Intelligent Supply Chain Security for Open-Source Packages</p><p><b>The Antivirus for Your Package Manager.</b> — scan before you install.</p></div>',
    unsafe_allow_html=True,
)

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "ai_explanation" not in st.session_state:
    st.session_state.ai_explanation = None
if "manager" not in st.session_state:
    st.session_state.manager = "pip"
if "package_input" not in st.session_state:
    st.session_state.package_input = ""

with st.sidebar:
    st.header("Navigation")
    page = st.radio("Open", ["Scanner", "Dashboard", "History"], label_visibility="collapsed")
    st.divider()
    st.caption("Defensive MVP: metadata + heuristics + vulnerability lookup. It never installs or executes packages.")

if page == "Scanner":
    st.subheader("🔎 Package Scanner")
    st.write("Enter a Python PyPI or JavaScript npm package and check its available security signals.")

    c1, c2 = st.columns([2, 1])
    with c1:
        name = st.text_input("Package name", key="package_input", placeholder="e.g. requests, reqeusts, express")
    with c2:
        manager = st.selectbox("Package manager", ["pip", "npm"], key="manager")

    st.caption("Try demo packages:")
    demo_cols = st.columns(4)
    demos = [("requests", "pip"), ("reqeusts", "pip"), ("numpy", "pip"), ("express", "npm")]
    for col, (demo_name, demo_manager) in zip(demo_cols, demos):
        if col.button(demo_name, use_container_width=True):
            st.session_state.package_input = demo_name
            st.session_state.manager = demo_manager
            st.rerun()

    if st.button("🛡️ Scan Package", type="primary", use_container_width=True):
        package_name = clean_package_name(name)
        if not valid_package_name(package_name, manager):
            st.error("Please enter a valid package name for the selected package manager.")
        else:
            with st.spinner("Retrieving registry metadata and running security checks..."):
                try:
                    result = full_scan(manager, package_name)
                except Exception as exc:
                    result = None
                    st.error("Package information could not be retrieved. Please try again.")
                    st.caption(f"Technical detail: {exc}")
                if result is None:
                    st.error("Package not found in the selected registry, or the registry is temporarily unavailable.")
                else:
                    st.session_state.scan_result = result
                    st.session_state.ai_explanation = None
                    save_scan(package_name, manager, result["analysis"]["score"], result["analysis"]["level"], result["analysis"]["findings"])
                    st.success("Scan completed.")

    result = st.session_state.scan_result
    if result:
        package = result["package"]
        analysis = result["analysis"]
        level = analysis["level"]
        score = analysis["score"]

        st.divider()
        st.subheader("Security Result")
        color = risk_color(level)
        st.markdown(
            f'<div class="risk-card"><div style="font-size:2rem;font-weight:800;color:{color}">{risk_emoji(level)} {level} RISK</div><div style="font-size:1.4rem;margin-top:.3rem"><b>{score} / 100</b></div><div class="muted">{risk_summary(score, level)}</div></div>',
            unsafe_allow_html=True,
        )
        st.progress(score / 100, text=f"Risk score: {score}/100")
        st.info(f"**Recommended action:** {analysis['recommended_action']}")

        why = [f["explanation"] for f in analysis["findings"] if f.get("severity") in {"HIGH", "MEDIUM", "LOW"}]
        if why:
            st.markdown("### Why?")
            for item in why[:5]:
                st.write(f"• {item}")

        st.markdown("### Security Findings")
        for finding in analysis["findings"]:
            sev = finding.get("severity", "INFO")
            icon = "🔴" if sev == "HIGH" else "🟡" if sev in {"MEDIUM", "LOW"} else "🟢" if sev == "SAFE" else "ℹ️"
            st.markdown(
                f'<div class="finding"><b>{icon} {finding["title"]}</b> &nbsp; <code>{sev}</code><br>{finding["explanation"]}<br><span class="muted">Evidence: {finding["evidence"]}</span></div>',
                unsafe_allow_html=True,
            )

        st.markdown("### 🤖 AI Security Analysis")
        if st.session_state.ai_explanation is None:
            if st.button("Generate AI Explanation"):
                with st.spinner("Generating explanation from the scan evidence..."):
                    st.session_state.ai_explanation = generate_ai_explanation(result)
                st.rerun()
        if st.session_state.ai_explanation:
            st.markdown(st.session_state.ai_explanation)
        else:
            st.warning("AI explanation unavailable — showing rule-based analysis. Add GROQ_API_KEY in Streamlit Secrets to enable the optional AI explanation.")

        st.markdown("### Package Details")
        details = {
            "Package": package["name"],
            "Manager": package["manager"],
            "Latest version": package["version"],
            "Author / maintainer": package["author"],
            "Description": package["description"],
            "License": package["license"],
            "First release": package["release_date"] or "N/A",
            "Last updated": package["last_updated"] or "N/A",
            "Versions": package["versions_count"],
            "Dependencies": len(package.get("dependencies") or []),
            "Downloads (npm last week)": package.get("downloads") if package["manager"] == "npm" else "Not provided by PyPI JSON API",
        }
        st.dataframe(pd.DataFrame(details.items(), columns=["Field", "Value"]), use_container_width=True, hide_index=True)
        if package.get("repository"):
            st.markdown(f"**Repository:** {package['repository']}")
        st.markdown(f"**Registry page:** {package_url(package['manager'], package['name'])}")

        typo = analysis.get("typosquatting")
        if typo:
            st.markdown("### 🔍 Possible Intended Package")
            st.write(f"The closest popular package found was **{typo['target']}** with **{typo['similarity'] * 100:.1f}%** name similarity.")
            if st.button("Compare Packages"):
                with st.spinner("Fetching the possible intended package..."):
                    compare = full_scan(package["manager"], typo["target"])
                if compare:
                    a = package
                    b = compare["package"]
                    rows = [
                        ("Name", a["name"], b["name"]),
                        ("Version", a["version"], b["version"]),
                        ("Author", a["author"], b["author"]),
                        ("Description", a["description"], b["description"]),
                        ("Repository", a.get("repository") or "N/A", b.get("repository") or "N/A"),
                        ("Release date", a.get("release_date") or "N/A", b.get("release_date") or "N/A"),
                        ("Dependencies", len(a.get("dependencies") or []), len(b.get("dependencies") or [])),
                        ("Risk score", analysis["score"], compare["analysis"]["score"]),
                        ("Similarity", f"{typo['similarity'] * 100:.1f}%", "Reference package"),
                    ]
                    st.dataframe(pd.DataFrame(rows, columns=["Field", "Scanned package", "Possible intended package"]), use_container_width=True, hide_index=True)

        report = {
            "package": package["name"],
            "manager": package["manager"],
            "version": package["version"],
            "risk_score": score,
            "risk_level": level,
            "findings": analysis["findings"],
            "typosquatting": analysis["typosquatting"],
            "metadata": {k: v for k, v in package.items() if k != "raw"},
            "ai_explanation": st.session_state.ai_explanation,
            "recommended_action": analysis["recommended_action"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        st.markdown("### Download Report")
        r1, r2 = st.columns(2)
        r1.download_button("Download JSON", json.dumps(report, indent=2, ensure_ascii=False), file_name=f"packagepatrol_{package['name'].replace('/', '_')}.json", mime="application/json", use_container_width=True)
        txt = f"PackagePatrol AI Report\n{'='*30}\nPackage: {package['name']}\nManager: {package['manager']}\nVersion: {package['version']}\nRisk: {level} ({score}/100)\n\nRecommendation:\n{analysis['recommended_action']}\n\nFindings:\n" + "\n".join([f"- {f['title']} [{f['severity']}]: {f['explanation']} Evidence: {f['evidence']}" for f in analysis['findings']])
        r2.download_button("Download TXT", txt, file_name=f"packagepatrol_{package['name'].replace('/', '_')}.txt", mime="text/plain", use_container_width=True)

elif page == "Dashboard":
    st.subheader("📊 Security Dashboard")
    df = load_history()
    if df.empty:
        st.info("No scans yet. Scan a package from the Scanner page to populate the dashboard.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Packages Scanned", len(df))
        c2.metric("High Risk", int((df.level == "HIGH").sum()))
        c3.metric("Medium Risk", int((df.level == "MEDIUM").sum()))
        c4.metric("Low Risk", int((df.level == "LOW").sum()))
        st.markdown("### Recent Scans")
        st.dataframe(df.head(10), use_container_width=True, hide_index=True)
        threats = df[df.top_threat != "None"]["top_threat"].value_counts()
        st.markdown("### Top Detected Threat Type")
        st.write(threats.index[0] if not threats.empty else "No threat pattern recorded yet.")

else:
    st.subheader("🕘 Scan History")
    df = load_history()
    if df.empty:
        st.info("No scans yet.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()
st.caption("PackagePatrol AI is a defensive metadata/static analysis MVP. A LOW result is not a guarantee that a package is safe, and heuristic warnings are not proof of malware.")
