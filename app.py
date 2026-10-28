import streamlit as st
import pandas as pd
import plotly.express as px
from io import StringIO

st.set_page_config(
    page_title="CyberTrace AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------- DESIGN --------------------

   


# CYBERTRACE AI — PROFESSIONAL DASHBOARD THEME
st.markdown("""
<style>
/* Main application background */
.stApp {
    background:
        radial-gradient(ellipse at top left, #172554 0%, transparent 45%),
        linear-gradient(135deg, #070b18 0%, #10172a 55%, #11112b 100%);
    color: #f1f5f9;
}

/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* Main headings */
h1 {
    color: #67e8f9 !important;
    font-size: 2.8rem !important;
    font-weight: 850 !important;
    letter-spacing: -1px;
}

h2 {
    color: #a5b4fc !important;
    font-size: 2rem !important;
    font-weight: 800 !important;
}

h3 {
    color: #67e8f9 !important;
    font-size: 1.45rem !important;
    font-weight: 750 !important;
}

/* Body text */
.stApp p,
.stApp li,
.stApp label,
.stMarkdown {
    color: #e2e8f0;
    font-size: 1.08rem;
    line-height: 1.75;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #10172a, #17163b 60%, #0c2238);
    border-right: 1px solid #263c66;
}

[data-testid="stSidebar"] h1 {
    font-size: 2.1rem !important;
    color: #67e8f9 !important;
}

[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label {
    font-size: 1.05rem;
    color: #e0e7ff;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: linear-gradient(135deg, #172554, #25205a);
    border: 1px solid #3b82f6;
    border-radius: 18px;
    padding: 22px 20px;
    box-shadow: 0 6px 22px rgba(37, 99, 235, 0.16);
    min-height: 125px;
    transition: all 0.2s ease-in-out;
}

div[data-testid="stMetric"]:hover {
    border-color: #67e8f9;
    box-shadow: 0 8px 28px rgba(34, 211, 238, 0.2);
    transform: translateY(-2px);
}

div[data-testid="stMetricLabel"] {
    color: #bfdbfe !important;
    font-size: 1.02rem !important;
    font-weight: 650 !important;
}

div[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-size: 2.25rem !important;
    font-weight: 850 !important;
}

/* Containers and cards */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: rgba(17, 27, 51, 0.72);
    border: 1px solid #293d65;
    border-radius: 16px;
}

/* Buttons */
.stButton button,
.stDownloadButton button {
    background: linear-gradient(90deg, #2563eb, #7c3aed);
    color: #ffffff !important;
    font-size: 1.05rem;
    font-weight: 750;
    border: 1px solid #60a5fa;
    border-radius: 12px;
    min-height: 46px;
    padding: 8px 18px;
    transition: all 0.2s ease;
}

.stButton button:hover,
.stDownloadButton button:hover {
    border-color: #67e8f9;
    box-shadow: 0 0 18px rgba(34, 211, 238, 0.24);
}

/* Input boxes */
.stTextInput input,
.stNumberInput input,
.stTextArea textarea {
    background: #111c33 !important;
    color: #f8fafc !important;
    border: 1px solid #3b5280 !important;
    border-radius: 10px !important;
    font-size: 1.05rem !important;
}

div[data-baseweb="select"] > div {
    background: #111c33;
    border-color: #3b5280;
    border-radius: 10px;
}

/* Tabs */
button[data-baseweb="tab"] {
    color: #cbd5e1;
    font-size: 1.05rem;
    font-weight: 700;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #67e8f9;
    border-bottom-color: #22d3ee;
}

/* Tables */
div[data-testid="stDataFrame"],
div[data-testid="stTable"] {
    border: 1px solid #334b70;
    border-radius: 12px;
    overflow: hidden;
}

/* Alerts */
div[data-testid="stAlert"] {
    border-radius: 12px;
    border: 1px solid #3b5280;
}

/* Expanders */
[data-testid="stExpander"] {
    background: rgba(20, 32, 58, 0.8);
    border: 1px solid #334b70;
    border-radius: 12px;
}

/* Progress bars */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #06b6d4, #8b5cf6);
}

/* File uploader */
[data-testid="stFileUploader"] {
    background: rgba(23, 37, 84, 0.45);
    border: 1px dashed #60a5fa;
    border-radius: 14px;
    padding: 12px;
}

/* Mobile display */
@media (max-width: 768px) {
    .block-container {
        padding-top: 1rem;
    }

    h1 {
        font-size: 2rem !important;
    }

    h2 {
        font-size: 1.55rem !important;
    }

    h3 {
        font-size: 1.25rem !important;
    }

    div[data-testid="stMetricValue"] {
        font-size: 1.65rem !important;
    }

    .stApp p,
    .stApp li,
    .stApp label {
        font-size: 1rem;
    }
}
</style>
""", unsafe_allow_html=True)

# -------------------- SAMPLE DATA --------------------
SAMPLE_CSV = """timestamp,username,source_ip,event_type,description,hostname,severity
2026-10-27 09:00:00,ali,192.168.1.10,login_success,Normal login,PC-01,Low
2026-10-27 09:02:00,ahmad,192.168.1.11,login_failure,Incorrect password,PC-02,Medium
2026-10-27 09:02:20,ahmad,192.168.1.11,login_failure,Incorrect password,PC-02,Medium
2026-10-27 09:02:40,ahmad,192.168.1.11,login_failure,Incorrect password,PC-02,Medium
2026-10-27 09:03:00,ahmad,192.168.1.11,login_failure,Incorrect password,PC-02,Medium
2026-10-27 09:04:00,ahmad,192.168.1.11,login_success,Login after repeated failures,PC-02,High
2026-10-27 09:10:00,sara,203.0.113.45,privilege_change,Administrator privilege granted,SERVER-01,High
2026-10-27 09:15:00,ali,192.168.1.10,file_access,Accessed confidential file,PC-01,Medium
2026-10-27 09:20:00,unknown,198.51.100.77,login_failure,Unknown account login attempt,SERVER-02,High
2026-10-27 09:25:00,admin,203.0.113.45,login_success,Administrator login,SERVER-01,Medium
2026-10-27 09:30:00,admin,203.0.113.45,file_access,Accessed restricted folder,SERVER-01,High
2026-10-27 09:35:00,ali,192.168.1.10,logout,User logged out,PC-01,Low
"""

# -------------------- DETECTION --------------------
def analyze_logs(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["event_type"] = df["event_type"].fillna("unknown").astype(str)
    df["username"] = df["username"].fillna("unknown").astype(str)
    df["source_ip"] = df["source_ip"].fillna("unknown").astype(str)

    findings = []

    failures = df[df["event_type"].str.lower().str.contains(
        "login_failure|failed_login|login_failed", regex=True
    )]

    for username, group in failures.groupby("username"):
        if len(group) >= 3:
            findings.append({
                "severity": "High",
                "finding": "Repeated failed login attempts",
                "username": username,
                "evidence": f"{len(group)} failed login events for this account."
            })

    successes = df[df["event_type"].str.lower().str.contains(
        "login_success|successful_login", regex=True
    )]

    for _, success in successes.iterrows():
        earlier = failures[
            (failures["username"] == success["username"]) &
            (failures["timestamp"] <= success["timestamp"]) &
            (failures["timestamp"] >= success["timestamp"] - pd.Timedelta(minutes=10))
        ]
        if len(earlier) >= 3:
            findings.append({
                "severity": "Critical",
                "finding": "Successful login after repeated failures",
                "username": success["username"],
                "evidence": (
                    f"{len(earlier)} failed login events occurred within "
                    "10 minutes before a successful login."
                )
            })

    for _, event in df.iterrows():
        kind = str(event["event_type"]).lower()
        if "privilege" in kind or "admin_grant" in kind:
            findings.append({
                "severity": "High",
                "finding": "Privilege change detected",
                "username": event["username"],
                "evidence": str(event.get("description", "Privilege-related event"))
            })

    return pd.DataFrame(
        findings,
        columns=["severity", "finding", "username", "evidence"]
    )

# -------------------- SIDEBAR --------------------
st.sidebar.title("🛡️ CyberTrace AI")
st.sidebar.caption("Evidence-based security investigation")
page = st.sidebar.radio(
    "Navigation",
    [
        "Home Dashboard",
        "Upload Security Logs",
        "Activity Analysis",
        "Attack Timeline",
        "Evidence Relationship Graph",
        "AI Investigator",
        "Incident Reports",
        "About CyberTrace AI"
    ]
)

st.sidebar.divider()
st.sidebar.info("Demo mode: fictional sample security logs are available.")

# -------------------- LOAD DATA --------------------
if "logs" not in st.session_state:
    st.session_state.logs = pd.read_csv(StringIO(SAMPLE_CSV))
    st.session_state.data_source = "Synthetic sample data"

if "logs" not in st.session_state:
    st.session_state.logs = pd.read_csv(StringIO(SAMPLE_CSV))

df = st.session_state.logs.copy()

required = ["timestamp", "username", "source_ip", "event_type"]
for column in required:
    if column not in df.columns:
        df[column] = "unknown"

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["username"] = df["username"].fillna("unknown").astype(str)
df["source_ip"] = df["source_ip"].fillna("unknown").astype(str)
df["event_type"] = df["event_type"].fillna("unknown").astype(str)

if "severity" not in df.columns:
    df["severity"] = "Unknown"
df["severity"] = df["severity"].fillna("Unknown").astype(str)

findings = analyze_logs(df)
suspicious_count = len(findings)
failed_count = int(df["event_type"].str.lower().str.contains(
    "login_failure|failed_login|login_failed", regex=True
).sum())
success_count = int(df["event_type"].str.lower().str.contains(
    "login_success|successful_login", regex=True
).sum())

# -------------------- HOME --------------------
if page == "Home Dashboard":
    st.title("🛡️ CyberTrace AI")
    st.subheader("Evidence-Based Cyberattack Reconstruction and Investigation")
    st.write(
        "Investigate security logs, identify suspicious patterns, "
        "and explore events through an interactive dashboard."
    )

    if st.button("🚀 Start Investigation", type="primary"):
        st.session_state.show_investigation = True
        st.success("Investigation dashboard is ready below.")

    st.caption(f"Data source: {st.session_state.data_source}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", len(df))
    c2.metric("Suspicious Findings", suspicious_count)
    c3.metric("Failed Logins", failed_count)
    c4.metric("Unique Source IPs", df["source_ip"].nunique())

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Successful Logins", success_count)
    c6.metric("Affected Accounts", df["username"].nunique())
    c7.metric("High/Critical Findings", int(
        findings["severity"].isin(["High", "Critical"]).sum()
    ))
    c8.metric("Investigation Status", "Demo")

    st.divider()
    left, right = st.columns(2)

    with left:
        st.subheader("Events by Type")
        if not df.empty:
            event_counts = df["event_type"].value_counts().reset_index()
            event_counts.columns = ["Event Type", "Count"]
            fig = px.bar(
                event_counts, x="Event Type", y="Count",
                color="Event Type", template="plotly_dark",
                title="Security Event Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events to display.")

    with right:
        st.subheader("Events by Severity")
        if not df.empty:
            sev_counts = df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig = px.pie(
                sev_counts, names="Severity", values="Count",
                hole=0.45, color="Severity",
                color_discrete_map={
                    "Low": "#22c55e",
                    "Medium": "#facc15",
                    "High": "#f97316",
                    "Critical": "#ef4444",
                    "Unknown": "#94a3b8"
                },
                template="plotly_dark"
            )
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent Security Events")
    st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)

# -------------------- UPLOAD --------------------
elif page == "Upload Security Logs":
    st.title("📂 Upload Security Logs")
    uploaded = st.file_uploader("Upload a CSV security log file", type=["csv"])
    if uploaded is not None:
        try:
            new_df = pd.read_csv(uploaded)
            if new_df.empty:
                st.error("The uploaded CSV is empty.")
            else:
                st.write("Preview")
                st.dataframe(new_df.head(10), use_container_width=True)
                missing = [c for c in required if c not in new_df.columns]
                if missing:
                    st.warning(f"Missing columns: {', '.join(missing)}")
                    st.info(
                        "Expected columns: timestamp, username, source_ip, event_type. "
                        "You can include description, hostname, and severity too."
                    )
                else:
                    if st.button("Use Uploaded Logs", type="primary"):
                        st.session_state.logs = new_df
                        st.session_state.data_source = "Uploaded CSV"
                        st.success("Logs loaded. Open another page to inspect the data.")
                        st.rerun()
        except Exception as exc:
            st.error(f"Could not read this CSV: {exc}")

    st.download_button(
        "⬇️ Download Sample CSV",
        data=SAMPLE_CSV,
        file_name="sample_logs.csv",
        mime="text/csv"
    )

# -------------------- ACTIVITY --------------------
elif page == "Activity Analysis":
    st.title("📊 Activity Analysis")
    if df.empty:
        st.info("No data available.")
    else:
        event_counts = df["event_type"].value_counts().reset_index()
        event_counts.columns = ["Event Type", "Count"]
        fig = px.bar(
            event_counts, x="Event Type", y="Count",
            color="Event Type", template="plotly_dark"
        )
        st.plotly_chart(fig, use_container_width=True)

        valid_times = df.dropna(subset=["timestamp"])
        if not valid_times.empty:
            timeline = valid_times.set_index("timestamp").resample("5min").size().reset_index(name="Events")
            fig = px.line(
                timeline, x="timestamp", y="Events",
                markers=True, template="plotly_dark",
                title="Events Over Time"
            )
            st.plotly_chart(fig, use_container_width=True)

        ip_counts = df["source_ip"].value_counts().head(10).reset_index()
        ip_counts.columns = ["Source IP", "Count"]
        fig = px.bar(
            ip_counts, x="Source IP", y="Count",
            color="Count", template="plotly_dark",
            title="Top Source IPs"
        )
        st.plotly_chart(fig, use_container_width=True)

# -------------------- TIMELINE --------------------
elif page == "Attack Timeline":
    st.title("🕒 Attack Timeline")
    valid = df.dropna(subset=["timestamp"]).sort_values("timestamp")
    if valid.empty:
        st.warning("No valid timestamps were found.")
    else:
        users = ["All"] + sorted(valid["username"].unique().tolist())
        selected_user = st.selectbox("Filter by username", users)
        if selected_user != "All":
            valid = valid[valid["username"] == selected_user]

        ips = ["All"] + sorted(valid["source_ip"].unique().tolist())
        selected_ip = st.selectbox("Filter by source IP", ips)
        if selected_ip != "All":
            valid = valid[valid["source_ip"] == selected_ip]

        fig = px.scatter(
            valid, x="timestamp", y="username",
            color="severity", hover_data=["source_ip", "event_type"],
            template="plotly_dark", title="Chronological Event Timeline"
        )
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(valid, use_container_width=True)

# -------------------- EVIDENCE GRAPH --------------------
elif page == "Evidence Relationship Graph":
    st.title("🕸️ Evidence Relationship Graph")
    st.info(
        "This first version shows shared users and source IPs. "
        "A shared value is a relationship clue, not proof of an attack."
    )
    if df.empty:
        st.info("No events available.")
    else:
        graph_df = df.groupby(["username", "source_ip"]).size().reset_index(name="Events")
        graph_df = graph_df.head(40)
        fig = px.scatter(
            graph_df, x="username", y="source_ip",
            size="Events", color="Events",
            hover_data=["Events"], template="plotly_dark",
            title="Users Associated with Source IPs"
        )
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(graph_df, use_container_width=True)

# -------------------- AI INVESTIGATOR --------------------
elif page == "AI Investigator":
    st.title("🤖 AI Investigator")
    st.warning(
        "Only send logs to an external AI service if you have permission. "
        "Remove passwords, tokens, personal data, and confidential details first."
    )
    st.write(
        "The AI integration will be configured after the core dashboard is working. "
        "For now, review the rule-based findings below."
    )
    if findings.empty:
        st.success("No findings matched the current detection rules.")
    else:
        st.dataframe(findings, use_container_width=True)

    if st.button("Generate Rule-Based Summary"):
        st.write(f"Analyzed {len(df)} events.")
        st.write(f"Generated {len(findings)} rule-based findings.")
        st.write(
            "These findings are indicators for investigation, not proof "
            "that a cyberattack occurred."
        )

# -------------------- REPORTS --------------------
elif page == "Incident Reports":
    st.title("📄 Incident Reports")
    st.subheader("Detection Findings")
    if findings.empty:
        st.info("No findings matched the current detection rules.")
    else:
        st.dataframe(findings, use_container_width=True)

    st.download_button(
        "⬇️ Download Findings CSV",
        data=findings.to_csv(index=False),
        file_name="cybertrace_findings.csv",
        mime="text/csv"
    )
    st.download_button(
        "⬇️ Download Analyzed Logs CSV",
        data=df.to_csv(index=False),
        file_name="cybertrace_analyzed_logs.csv",
        mime="text/csv"
    )

    report_text = (
        "CYBERTRACE AI - INVESTIGATION REPORT\n\n"
        f"Data source: {st.session_state.data_source}\n"
        f"Total events: {len(df)}\n"
        f"Failed login events: {failed_count}\n"
        f"Successful login events: {success_count}\n"
        f"Rule-based findings: {len(findings)}\n\n"
        "LIMITATION: Findings are indicators for investigation, not proof of an attack.\n\n"
        + findings.to_string(index=False)
    )
    st.download_button(
        "⬇️ Download Text Report",
        data=report_text,
        file_name="cybertrace_report.txt",
        mime="text/plain"
    )

# -------------------- ABOUT --------------------
elif page == "About CyberTrace AI":
    st.title("ℹ️ About CyberTrace AI")
    st.write("""
    **CyberTrace AI** is a university cybersecurity project for evidence-based
    security log analysis and incident investigation.

    **Core capabilities**
    - CSV security log analysis
    - Transparent rule-based detection
    - Interactive charts and timelines
    - User/IP relationship exploration
    - Downloadable investigation reports

    **Important limitations**
    - Synthetic sample data is fictional.
    - Detection rules may miss attacks or flag legitimate activity.
    - Shared IPs or usernames do not prove malicious activity.
    - AI-based explanations are not enabled in this first version.
    """)

st.sidebar.divider()
st.sidebar.caption("CyberTrace AI | University Project")
