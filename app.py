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
        INSERT INTO scans
        (
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
# CUSTOM CSS
# =========================================================

def render_css():

    st.markdown(
        """
        <style>

        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 1250px;
        }

        .hero {
            padding: 1.5rem 1.7rem;
            border: 1px solid rgba(100,116,139,.25);
            border-radius: 18px;
            background: linear-gradient(
                135deg,
                rgba(15,23,42,.98),
                rgba(30,41,59,.92)
            );
            color: white;
            margin-bottom: 1rem;
        }

        .hero h1 {
            margin: 0;
            font-size: 2.4rem;
        }

        .hero p {
            margin: .45rem 0 0;
            color: #cbd5e1;
        }

        </style>
        """,
        unsafe_allow_html=True,
    )


render_css()


# =========================================================
# HERO HEADER
# =========================================================

st.markdown(
    """
    <div class="hero">
        <h1>🛡️ PackagePatrol AI</h1>

        <p>
            Intelligent Supply Chain Security for Open-Source Packages
        </p>

        <p>
            <b>The Antivirus for Your Package Manager.</b>
            — scan before you install.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
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

# Important:
# Demo buttons will store their value here first.
# The package_input widget will receive the value
# BEFORE it is created on the next rerun.
if "demo_package" not in st.session_state:
    st.session_state.demo_package = None


# =========================================================
# DEMO PACKAGE STATE
# =========================================================

if st.session_state.demo_package:

    st.session_state.package_input = (
        st.session_state.demo_package["name"]
    )

    st.session_state.manager = (
        st.session_state.demo_package["manager"]
    )

    st.session_state.demo_package = None


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


    # -----------------------------------------------------
    # INPUT SECTION
    # -----------------------------------------------------

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
            ["pip", "npm"],
            key="manager",
        )


    # -----------------------------------------------------
    # DEMO PACKAGES
    # -----------------------------------------------------

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

            # Do NOT modify package_input directly here.
            # This avoids StreamlitWidgetAlreadyInstantiatedError.

            st.session_state.demo_package = {
                "name": demo_name,
                "manager": demo_manager,
            }

            st.rerun()


    # -----------------------------------------------------
    # SCAN BUTTON
    # -----------------------------------------------------

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


        # -------------------------------------------------
        # RISK DISPLAY
        # -------------------------------------------------

        # Dynamic risk level
        # comes directly from risk_engine.py

        if level == "HIGH":

            st.error(
                f"""
                🔴 HIGH RISK

                **Risk Score: {score}/100**

                {risk_summary(score, level)}
                """
            )

        elif level == "MEDIUM":

            st.warning(
                f"""
                🟠 MEDIUM RISK

                **Risk Score: {score}/100**

                {risk_summary(score, level)}
                """
            )

        else:

            st.success(
                f"""
                🟢 LOW RISK

                **Risk Score: {score}/100**

                {risk_summary(score, level)}
                """
            )


        # -------------------------------------------------
        # SCORE BAR
        # -------------------------------------------------

        # Keep score between 0 and 100
        safe_score = max(
            0,
            min(100, int(score))
        )

        st.progress(
            safe_score / 100,
            text=f"Risk score: {safe_score}/100"
        )


        # -------------------------------------------------
        # RECOMMENDED ACTION
        # -------------------------------------------------

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
            finding["explanation"]
            for finding in analysis["findings"]
            if finding.get("severity")
            in {"HIGH", "MEDIUM", "LOW"}
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

        st.markdown("### 🔍 Security Findings")


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


            # HIGH
            if sev == "HIGH":

                st.error(
                    f"""
                    🔴 **{title}**

                    **Severity:** HIGH

                    {explanation}

                    **Evidence:** {evidence}
                    """
                )


            # MEDIUM
            elif sev == "MEDIUM":

                st.warning(
                    f"""
                    🟠 **{title}**

                    **Severity:** MEDIUM

                    {explanation}

                    **Evidence:** {evidence}
                    """
                )


            # LOW
            elif sev == "LOW":

                st.warning(
                    f"""
                    🟡 **{title}**

                    **Severity:** LOW

                    {explanation}

                    **Evidence:** {evidence}
                    """
                )


            # SAFE
            elif sev == "SAFE":

                st.success(
                    f"""
                    🟢 **{title}**

                    **Severity:** SAFE

                    {explanation}

                    **Evidence:** {evidence}
                    """
                )


            # INFO
            else:

                st.info(
                    f"""
                    ℹ️ **{title}**

                    **Severity:** {sev}

                    {explanation}

                    **Evidence:** {evidence}
                    """
                )


        # =================================================
        # AI SECURITY ANALYSIS
        # =================================================

        st.markdown("### 🤖 AI Security Analysis")


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

            # Normal Markdown output.
            # No custom HTML here.

            st.markdown(
                st.session_state.ai_explanation
            )

        else:

            st.warning(
                "AI explanation unavailable — "
                "showing rule-based analysis. "
                "Add GROQ_API_KEY in Streamlit "
                "Secrets to enable the optional "
                "AI explanation."
            )


        # =================================================
        # PACKAGE DETAILS
        # =================================================

        st.markdown("### 📦 Package Details")


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
                package["release_date"] or "N/A",

            "Last updated":
                package["last_updated"] or "N/A",

            "Versions":
                package["versions_count"],

            "Dependencies":
                len(
                    package.get("dependencies")
                    or []
                ),

            "Downloads (npm last week)":
                (
                    package.get("downloads")
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


        # -------------------------------------------------
        # REPOSITORY
        # -------------------------------------------------

        if package.get("repository"):

            st.markdown(
                f"**Repository:** "
                f"{package['repository']}"
            )


        # -------------------------------------------------
        # REGISTRY
        # -------------------------------------------------

        st.markdown(
            f"**Registry page:** "
            f"{package_url(package['manager'], package['name'])}"
        )


        # =================================================
        # TYPOSQUATTING
        # =================================================

        typo = analysis.get(
            "typosquatting"
        )


        if typo:

            st.markdown(
                "### 🔍 Possible Intended Package"
            )

            similarity = (
                typo["similarity"] * 100
            )


            st.write(
                f"The closest popular package "
                f"found was **{typo['target']}** "
                f"with **{similarity:.1f}%** "
                f"name similarity."
            )


            if st.button(
                "Compare Packages",
                key="compare_packages",
            ):

                with st.spinner(
                    "Fetching the possible "
                    "intended package..."
                ):

                    try:

                        compare = full_scan(
                            package["manager"],
                            typo["target"]
                        )

                    except Exception as exc:

                        compare = None

                        st.error(
                            "Could not compare "
                            "the packages."
                        )

                        st.caption(
                            f"Technical detail: {exc}"
                        )


                if compare:

                    a = package

                    b = compare["package"]


                    rows = [

                        (
                            "Name",
                            a["name"],
                            b["name"]
                        ),

                        (
                            "Version",
                            a["version"],
                            b["version"]
                        ),

                        (
                            "Author",
                            a["author"],
                            b["author"]
                        ),

                        (
                            "Description",
                            a["description"],
                            b["description"]
                        ),

                        (
                            "Repository",
                            a.get("repository")
                            or "N/A",
                            b.get("repository")
                            or "N/A"
                        ),

                        (
                            "Release date",
                            a.get("release_date")
                            or "N/A",
                            b.get("release_date")
                            or "N/A"
                        ),

                        (
                            "Dependencies",
                            len(
                                a.get(
                                    "dependencies"
                                )
                                or []
                            ),
                            len(
                                b.get(
                                    "dependencies"
                                )
                                or []
                            ),
                        ),

                        (
                            "Risk score",
                            analysis["score"],
                            compare["analysis"]["score"],
                        ),

                        (
                            "Similarity",
                            f"{similarity:.1f}%",
                            "Reference package",
                        ),
                    ]


                    st.dataframe(
                        pd.DataFrame(
                            rows,
                            columns=[
                                "Field",
                                "Scanned package",
                                "Possible intended package",
                            ],
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )


        # =================================================
        # DOWNLOAD REPORT
        # =================================================

        report = {

            "package":
                package["name"],

            "manager":
                package["manager"],

            "version":
                package["version"],

            "risk_score":
                score,

            "risk_level":
                level,

            "findings":
                analysis["findings"],

            "typosquatting":
                analysis["typosquatting"],

            "metadata":
                {
                    k: v
                    for k, v in package.items()
                    if k != "raw"
                },

            "ai_explanation":
                st.session_state.ai_explanation,

            "recommended_action":
                analysis["recommended_action"],

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),
        }


        st.markdown(
            "### 📥 Download Report"
        )


        r1, r2 = st.columns(2)


        # -------------------------------------------------
        # JSON REPORT
        # -------------------------------------------------

        r1.download_button(

            "Download JSON",

            json.dumps(
                report,
                indent=2,
                ensure_ascii=False
            ),

            file_name=(
                f"packagepatrol_"
                f"{package['name'].replace('/', '_')}"
                f".json"
            ),

            mime="application/json",

            use_container_width=True,
        )


        # -------------------------------------------------
        # TXT REPORT
        # -------------------------------------------------

        txt = (
            "PackagePatrol AI Report\n"
            + "=" * 30
            + "\n"
            + f"Package: {package['name']}\n"
            + f"Manager: {package['manager']}\n"
            + f"Version: {package['version']}\n"
            + f"Risk: {level} ({score}/100)\n\n"
            + "Recommendation:\n"
            + f"{analysis['recommended_action']}\n\n"
            + "Findings:\n"
            + "\n".join(
                [
                    (
                        f"- {f['title']} "
                        f"[{f['severity']}]: "
                        f"{f['explanation']} "
                        f"Evidence: {f['evidence']}"
                    )
                    for f in analysis["findings"]
                ]
            )
        )


        r2.download_button(

            "Download TXT",

            txt,

            file_name=(
                f"packagepatrol_"
                f"{package['name'].replace('/', '_')}"
                f".txt"
            ),

            mime="text/plain",

            use_container_width=True,
        )


# =========================================================
# DASHBOARD
# =========================================================

elif page == "Dashboard":

    st.subheader(
        "📊 Security Dashboard"
    )


    df = load_history()


    if df.empty:

        st.info(
            "No scans yet. Scan a package "
            "from the Scanner page to populate "
            "the dashboard."
        )


    else:

        c1, c2, c3, c4 = st.columns(4)


        c1.metric(
            "Total Packages Scanned",
            len(df)
        )


        c2.metric(
            "High Risk",
            int(
                (df.level == "HIGH").sum()
            )
        )


        c3.metric(
            "Medium Risk",
            int(
                (df.level == "MEDIUM").sum()
            )
        )


        c4.metric(
            "Low Risk",
            int(
                (df.level == "LOW").sum()
            )
        )


        st.markdown(
            "### Recent Scans"
        )


        st.dataframe(
            df.head(10),
            use_container_width=True,
            hide_index=True,
        )


        threats = df[
            df.top_threat != "None"
        ]["top_threat"].value_counts()


        st.markdown(
            "### Top Detected Threat Type"
        )


        if not threats.empty:

            st.write(
                threats.index[0]
            )

        else:

            st.write(
                "No threat pattern recorded yet."
            )


# =========================================================
# HISTORY
# =========================================================

else:

    st.subheader(
        "🕘 Scan History"
    )


    df = load_history()


    if df.empty:

        st.info(
            "No scans yet."
        )


    else:

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )


# =========================================================
# FOOTER
# =========================================================

st.divider()


st.caption(
    "PackagePatrol AI is a defensive "
    "metadata/static analysis MVP. "
    "A LOW result is not a guarantee that "
    "a package is safe, and heuristic warnings "
    "are not proof of malware."
)
