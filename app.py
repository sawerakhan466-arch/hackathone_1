# =========================================================
# DASHBOARD
# =========================================================

elif page == "Dashboard":

    st.title("📊 Security Dashboard")

    df = load_history()

    if df.empty:

        st.info(
            "No scans yet. Scan a package from the Scanner page "
            "to populate the dashboard."
        )

    else:

        # Dashboard statistics
        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Total Packages Scanned",
            len(df)
        )

        c2.metric(
            "High Risk",
            int((df["level"] == "HIGH").sum())
        )

        c3.metric(
            "Medium Risk",
            int((df["level"] == "MEDIUM").sum())
        )

        c4.metric(
            "Low Risk",
            int((df["level"] == "LOW").sum())
        )

        st.divider()

        # Recent scans
        st.subheader("📋 Recent Scans")

        dashboard_df = df.copy()

        st.dataframe(
            dashboard_df.head(10),
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # Top detected threat
        st.subheader("🚨 Top Detected Threat")

        threats = df[
            df["top_threat"] != "None"
        ]["top_threat"].value_counts()

        if not threats.empty:

            st.write(
                f"**Most detected threat:** "
                f"{threats.index[0]}"
            )

            st.write(
                f"**Occurrences:** {threats.iloc[0]}"
            )

        else:

            st.success(
                "No threat patterns have been recorded yet."
            )


# =========================================================
# HISTORY
# =========================================================

elif page == "History":

    st.title("🕘 Scan History")

    df = load_history()

    if df.empty:

        st.info(
            "No scan history available yet. "
            "Scan a package from the Scanner page first."
        )

    else:

        st.write(
            f"Total recorded scans: **{len(df)}**"
        )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "PackagePatrol AI is a defensive metadata/static analysis MVP. "
    "A LOW result is not a guarantee that a package is safe, "
    "and heuristic warnings are not proof of malware."
)
