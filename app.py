import json
import sqlite3
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from ai_analyzer import generate_ai_explanation
from analyzer import full_scan
from risk_engine import risk_summary
from utils import clean_package_name, package_url, valid_package_name


# =========================================================
# CONFIGURATION
# =========================================================

DB_FILE = "packagepatrol.db"

st.set_page_config(
    page_title="PackagePatrol AI",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# DATABASE
# =========================================================

def db_connect():
    conn = sqlite3.connect(
        DB_FILE,
        check_same_thread=False
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            manager TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            top_threat TEXT
        )
        """
    )

    conn.commit()

    return conn


conn = db_connect()


def save_scan(name, manager, score, level, findings):

    threat = "None"

    for finding in findings:

        if (
            finding.get("severity") in {"HIGH", "MEDIUM"}
            and finding.get("category") != "normal"
        ):

            threat = finding.get(
                "title",
                "Security indicator"
            )

            break

    conn.execute(
        """
        INSERT INTO scans (
            package_name,
            manager,
            score,
            level,
            timestamp,
            top_threat
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            name,
            manager,
            score,
            level,
            datetime.now(timezone.utc).isoformat(),
            threat,
        ),
    )

    conn.commit()


def load_history(limit=100):

    return pd.read_sql_query(
        """
        SELECT
            package_name,
            manager,
            score,
            level,
            timestamp,
            top_threat
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        conn,
        params=(limit,),
    )


# =========================================================
# SESSION STATE
# =========================================================

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "ai_explanation" not in st.session_state:
    st.session_state.ai_explanation = None

if "manager" not in st.session_state:
    st.session_state.manager = "pip"

if "package_input" not in st.session_state:
    st.session_state.package_input = ""

if "demo_package" not in st.session_state:
    st.session_state.demo_package = None


# =========================================================
# DEMO PACKAGE HANDLING
# =========================================================

if st.session_state.demo_package is not None:

    st.session_state.package_input = (
        st.session_state.demo_package["name"]
    )

    st.session_state.manager = (
        st.session_state.demo_package["manager"]
    )

    st.session_state.demo_package = None


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ PackagePatrol AI")

st.subheader(
    "Intelligent Supply Chain Security for Open-Source Packages"
)

st.write(
    "**The Antivirus for Your Package Manager.** "
    "— scan before you install."
)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.header("Navigation")

    page = st.radio(
        "Open",
        [
            "Scanner",
            "Dashboard",
            "History"
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.caption(
        "Defensive MVP: metadata + heuristics + "
        "vulnerability lookup. It never installs "
        "or executes packages."
    )


# =========================================================
# SCANNER
# =========================================================

if page == "Scanner":

    st.subheader("🔎 Package Scanner")

    st.write(
        "Enter a Python PyPI or JavaScript npm package "
        "and check its available security signals."
    )


    # =====================================================
    # INPUT SECTION
    # =====================================================

    c1, c2 = st.columns([2, 1])


    with c1:

        name = st.text_input(
            "Package name",
            key="package_input",
            placeholder="e.g. requests, reqeusts, express",
        )


    with c2:

        manager = st.selectbox(
            "Package manager",
            [
                "pip",
                "npm"
            ],
            key="manager",
        )


    # =====================================================
    # DEMO PACKAGES
    # =====================================================

    st.caption("Try demo packages:")

    demo_cols = st.columns(4)

    demos = [
        ("requests", "pip"),
        ("reqeusts", "pip"),
        ("numpy", "pip"),
        ("express", "npm"),
    ]


    for col, (demo_name, demo_manager) in zip(
        demo_cols,
        demos
    ):

        if col.button(
            demo_name,
            use_container_width=True,
            key=f"demo_{demo_name}_{demo_manager}",
        ):

            st.session_state.demo_package = {
                "name": demo_name,
                "manager": demo_manager,
            }

            st.rerun()


    # =====================================================
    # SCAN BUTTON
    # =====================================================

    if st.button(
        "🛡️ Scan Package",
        type="primary",
        use_container_width=True,
    ):

        package_name = clean_package_name(name)


        if not valid_package_name(
            package_name,
            manager
        ):

            st.error(
                "Please enter a valid package name "
                "for the selected package manager."
            )


        else:

            with st.spinner(
                "Retrieving registry metadata and "
                "running security checks..."
            ):

                try:

                    result = full_scan(
                        manager,
                        package_name
                    )

                except Exception as exc:

                    result = None

                    st.error(
                        "Package information could not "
                        "be retrieved. Please try again."
                    )

                    st.caption(
                        f"Technical detail: {exc}"
                    )


                if result is None:

                    st.error(
                        "Package not found in the selected "
                        "registry, or the registry is "
                        "temporarily unavailable."
                    )


                else:

                    st.session_state.scan_result = result

                    st.session_state.ai_explanation = None

                    save_scan(
                        package_name,
                        manager,
                        result["analysis"]["score"],
                        result["analysis"]["level"],
                        result["analysis"]["findings"],
                    )

                    st.success(
                        "Scan completed successfully."
                    )


    # =====================================================
    # SECURITY RESULT
    # =====================================================

    result = st.session_state.scan_result


    if result:

        package = result["package"]

        analysis = result["analysis"]

        level = analysis["level"]

        score = analysis["score"]


        st.divider()

        st.subheader("🛡️ Security Result")


        # =================================================
        # SAFE SCORE
        # =================================================

        safe_score = max(
            0,
            min(
                100,
                int(score)
            )
        )


        # =================================================
        # DYNAMIC RISK LEVEL
        # =================================================

        if level == "HIGH":

            st.error(
                f"🔴 HIGH RISK\n\n"
                f"**Risk Score: {safe_score}/100**\n\n"
                f"{risk_summary(safe_score, level)}"
            )


        elif level == "MEDIUM":

            st.warning(
                f"🟠 MEDIUM RISK\n\n"
                f"**Risk Score: {safe_score}/100**\n\n"
                f"{risk_summary(safe_score, level)}"
            )


        else:

            st.success(
                f"🟢 LOW RISK\n\n"
                f"**Risk Score: {safe_score}/100**\n\n"
                f"{risk_summary(safe_score, level)}"
            )


        # =================================================
        # RISK SCORE BAR
        # =================================================

        st.progress(
            safe_score / 100,
            text=f"Risk score: {safe_score}/100"
        )


        # =================================================
        # RECOMMENDED ACTION
        # =================================================

        if level == "HIGH":

            st.error(
                f"🚨 **Recommended action:** "
                f"{analysis['recommended_action']}"
            )


        elif level == "MEDIUM":

            st.warning(
                f"⚠️ **Recommended action:** "
                f"{analysis['recommended_action']}"
            )


        else:

            st.info(
                f"ℹ️ **Recommended action:** "
                f"{analysis['recommended_action']}"
            )


        # =================================================
        # WHY?
        # =================================================

        why = [
            finding.get(
                "explanation",
                ""
            )

            for finding in analysis["findings"]

            if finding.get("severity")
            in {
                "HIGH",
                "MEDIUM",
                "LOW"
            }
        ]


        if why:

            st.markdown("### Why?")


            for item in why[:5]:

                st.write(
                    f"• {item}"
                )


        # =================================================
        # SECURITY FINDINGS
        # =================================================

        st.markdown(
            "### 🔍 Security Findings"
        )


        for finding in analysis["findings"]:

            sev = finding.get(
                "severity",
                "INFO"
            )

            title = finding.get(
                "title",
                "Security Finding"
            )

            explanation = finding.get(
                "explanation",
                "No explanation available."
            )

            evidence = finding.get(
                "evidence",
                "No evidence available."
            )


            if sev == "HIGH":

                st.error(
                    f"🔴 **{title}**\n\n"
                    f"**Severity:** HIGH\n\n"
                    f"{explanation}\n\n"
                    f"**Evidence:** {evidence}"
                )


            elif sev == "MEDIUM":

                st.warning(
                    f"🟠 **{title}**\n\n"
                    f"**Severity:** MEDIUM\n\n"
                    f"{explanation}\n\n"
                    f"**Evidence:** {evidence}"
                )


            elif sev == "LOW":

                st.warning(
                    f"🟡 **{title}**\n\n"
                    f"**Severity:** LOW\n\n"
                    f"{explanation}\n\n"
                    f"**Evidence:** {evidence}"
                )


            elif sev == "SAFE":

                st.success(
                    f"🟢 **{title}**\n\n"
                    f"**Severity:** SAFE\n\n"
                    f"{explanation}\n\n"
                    f"**Evidence:** {evidence}"
                )


            else:

                st.info(
                    f"ℹ️ **{title}**\n\n"
                    f"**Severity:** {sev}\n\n"
                    f"{explanation}\n\n"
                    f"**Evidence:** {evidence}"
                )


        # =================================================
        # AI SECURITY ANALYSIS
        # =================================================

        st.markdown(
            "### 🤖 AI Security Analysis"
        )


        if st.session_state.ai_explanation is None:

            if st.button(
                "Generate AI Explanation",
                key="generate_ai_explanation",
            ):

                with st.spinner(
                    "Generating explanation from "
                    "the scan evidence..."
                ):

                    try:

                        st.session_state.ai_explanation = (
                            generate_ai_explanation(
                                result
                            )
                        )

                    except Exception as exc:

                        st.session_state.ai_explanation = None

                        st.warning(
                            "AI explanation could not "
                            "be generated."
                        )

                        st.caption(
                            f"Technical detail: {exc}"
                        )

                st.rerun()


        if st.session_state.ai_explanation:

            st.markdown(
                st.session_state.ai_explanation
            )


        # =================================================
        # PACKAGE DETAILS
        # =================================================

        st.markdown(
            "### 📦 Package Details"
        )


        details = {

            "Package":
                package["name"],

            "Manager":
                package["manager"],

            "Latest version":
                package["version"],

            "Author / maintainer":
                package["author"],

            "Description":
                package["description"],

            "License":
                package["license"],

            "First release":
                package["release_date"]
                or "N/A",

            "Last updated":
                package["last_updated"]
                or "N/A",

            "Versions":
                package["versions_count"],

            "Dependencies":
                len(
                    package.get(
                        "dependencies"
                    )
                    or []
                ),

            "Downloads (npm last week)":
                (
                    package.get(
                        "downloads"
                    )

                    if package["manager"] == "npm"

                    else
                    "Not provided by PyPI JSON API"
                ),
        }


        st.dataframe(
            pd.DataFrame(
                details.items(),
                columns=[
                    "Field",
                    "Value"
                ],
            ),
            use_container_width=True,
            hide_index=True,
        )
