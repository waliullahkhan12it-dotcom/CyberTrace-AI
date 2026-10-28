import os
from datetime import datetime

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="CyberTrace AI | Threat Hunter",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ====================== VISUAL THEME ======================
st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(ellipse at top left, rgba(13,148,136,.13), transparent 38%),
        linear-gradient(135deg, #0b1220, #111c2d 55%, #101923);
    color: #f1f5f9;
}
.block-container {
    max-width: 1500px;
    padding-top: 1.7rem;
    padding-bottom: 3rem;
}
h1 {
    color: #5eead4 !important;
    font-size: 2.65rem !important;
    font-weight: 850 !important;
    letter-spacing: -.8px;
}
h2 {
    color: #99f6e4 !important;
    font-size: 1.9rem !important;
    font-weight: 800 !important;
}
h3 {
    color: #67e8f9 !important;
    font-size: 1.35rem !important;
    font-weight: 750 !important;
}
.stApp p, .stApp li, .stApp label {
    color: #e2e8f0;
    font-size: 1.06rem;
    line-height: 1.7;
}
.hero-card {
    padding: 26px 28px;
    border-radius: 22px;
    margin: 8px 0 22px 0;
    background: linear-gradient(
        120deg,
        rgba(13,148,136,.28),
        rgba(37,99,235,.22),
        rgba(124,58,237,.22)
    );
    border: 1px solid rgba(94,234,212,.55);
    box-shadow: 0 12px 35px rgba(0,0,0,.20);
}
.hero-kicker {
    color: #5eead4;
    font-size: .85rem;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.hero-title {
    color: #f8fafc;
    font-size: 2.55rem;
    line-height: 1.15;
    font-weight: 900;
    margin: 8px 0;
}
.hero-subtitle {
    color: #cbd5e1;
    font-size: 1.12rem;
    line-height: 1.65;
}
.section-card {
    padding: 18px 20px;
    border-radius: 16px;
    background: rgba(15,31,47,.78);
    border: 1px solid #29475b;
    margin-bottom: 12px;
}
.upload-banner {
    padding: 22px;
    border-radius: 18px;
    background: linear-gradient(
        120deg,
        rgba(14,116,144,.24),
        rgba(13,148,136,.20)
    );
    border: 1px dashed #5eead4;
}
.mini-label {
    color: #94a3b8;
    font-size: .82rem;
    font-weight: 800;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #101a29, #132c39 60%, #10221f);
    border-right: 1px solid #24545a;
}
[data-testid="stSidebar"] h1 {
    font-size: 1.8rem !important;
}
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label {
    color: #dbeafe;
}
div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #192b3c, #172238);
    border: 1px solid #287d7b;
    border-radius: 16px;
    padding: 18px;
    min-height: 118px;
    box-shadow: 0 5px 20px rgba(0,0,0,.20);
}
div[data-testid="stMetricLabel"] {
    color: #b8cbd9 !important;
    font-size: .98rem !important;
    font-weight: 650 !important;
}
div[data-testid="stMetricValue"] {
    color: #5eead4 !important;
    font-size: 2rem !important;
    font-weight: 850 !important;
}
.stButton button, .stDownloadButton button {
    background: linear-gradient(100deg, #0f766e, #115e59);
    color: #fff !important;
    border: 1px solid #2dd4bf;
    border-radius: 10px;
    min-height: 44px;
    padding: 8px 16px;
    font-size: 1rem;
    font-weight: 700;
}
.stButton button:hover, .stDownloadButton button:hover {
    background: linear-gradient(100deg, #0d9488, #0f766e);
    border-color: #99f6e4;
    box-shadow: 0 0 15px rgba(45,212,191,.20);
}
.stTextInput input, .stNumberInput input, .stTextArea textarea {
    background: #111e2d !important;
    color: #f8fafc !important;
    border: 1px solid #38546a !important;
    border-radius: 9px !important;
}
div[data-baseweb="select"] > div {
    background: #142337;
    border-color: #38546a;
    border-radius: 9px;
}
div[data-testid="stDataFrame"], div[data-testid="stTable"] {
    border: 1px solid #29475b;
    border-radius: 12px;
}
div[data-testid="stAlert"] {
    border-radius: 12px;
}
[data-testid="stExpander"] {
    background: rgba(20,35,52,.85);
    border: 1px solid #29475b;
    border-radius: 12px;
}
[data-testid="stFileUploader"] {
    background: rgba(20,40,55,.65);
    border: 1px dashed #2dd4bf;
    border-radius: 14px;
    padding: 12px;
}
@media (max-width: 768px) {
    .block-container { padding-top: 1rem; }
    h1 { font-size: 2rem !important; }
    h2 { font-size: 1.5rem !important; }
    div[data-testid="stMetricValue"] { font-size: 1.55rem !important; }
    .hero-title { font-size: 2rem; }
}
</style>
""", unsafe_allow_html=True)

COLORS = {
    "Low": "#5eead4",
    "Medium": "#fbbf24",
    "High": "#fb923c",
    "Critical": "#f87171",
    "Informational": "#60a5fa",
    "Unknown": "#94a3b8",
}


# ====================== FICTIONAL SAMPLE DATA ======================
def make_sample_logs():
    now = pd.Timestamp.now().floor("min")
    rows = [
        (-58, "192.168.1.10", "alice", "login_success", "Low", "Successful login"),
        (-55, "203.0.113.42", "admin", "login_failure", "Medium", "Invalid password"),
        (-54, "203.0.113.42", "admin", "login_failure", "Medium", "Invalid password"),
        (-53, "203.0.113.42", "admin", "login_failure", "High", "Repeated invalid password"),
        (-50, "203.0.113.42", "admin", "login_failure", "High", "Repeated invalid password"),
        (-45, "203.0.113.42", "admin", "login_success", "High", "Login after repeated failures"),
        (-40, "192.168.1.15", "bob", "file_access", "Low", "Opened shared report"),
        (-35, "198.51.100.27", "svc-backup", "privilege_change", "High", "Privilege changed"),
        (-28, "198.51.100.27", "svc-backup", "file_access", "Medium", "Sensitive file accessed"),
        (-20, "192.168.1.10", "alice", "logout", "Low", "User logged out"),
        (-15, "198.51.100.27", "svc-backup", "login_failure", "Medium", "Invalid password"),
        (-14, "198.51.100.27", "svc-backup", "login_failure", "Medium", "Invalid password"),
        (-13, "198.51.100.27", "svc-backup", "login_failure", "High", "Repeated invalid password"),
        (-8, "192.0.2.77", "unknown", "file_access", "Critical", "Unexpected sensitive file access"),
        (-4, "192.0.2.77", "unknown", "privilege_change", "Critical", "Unexpected privilege change"),
    ]
    return pd.DataFrame([
        {
            "timestamp": now + pd.Timedelta(minutes=offset),
            "source_ip": ip,
            "username": user,
            "event_type": event,
            "severity": severity,
            "details": details,
        }
        for offset, ip, user, event, severity, details in rows
    ])


def normalize_logs(raw):
    """Convert common CSV column names into the dashboard's standard format."""
    df = raw.copy()
    aliases = {
        "time": "timestamp",
        "date": "timestamp",
        "datetime": "timestamp",
        "event_time": "timestamp",
        "src_ip": "source_ip",
        "ip": "source_ip",
        "ip_address": "source_ip",
        "user": "username",
        "account": "username",
        "event": "event_type",
        "action": "event_type",
        "level": "severity",
        "risk": "severity",
        "message": "details",
        "description": "details",
    }
    df.columns = [
        str(c).strip().lower().replace(" ", "_")
        for c in df.columns
    ]
    df = df.rename(columns={c: aliases.get(c, c) for c in df.columns})

    required = {
        "timestamp": pd.Timestamp.now(),
        "source_ip": "Unknown",
        "username": "Unknown",
        "event_type": "unknown_event",
        "severity": "Unknown",
        "details": "",
    }
    for col, default in required.items():
        if col not in df.columns:
            df[col] = default

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True
    ).dt.tz_convert(None)

    for col in ["source_ip", "username", "event_type", "severity", "details"]:
        df[col] = df[col].fillna("Unknown").astype(str).str.strip()

    df["severity"] = df["severity"].str.title()
    df.loc[~df["severity"].isin(COLORS), "severity"] = "Unknown"
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = [f"EVT-{i + 1:04d}" for i in range(len(df))]
    return df


def detect_findings(df, failure_threshold=3, window_minutes=10):
    """Rule-based indicators for investigation, not proof of an attack."""
    columns = ["severity", "finding", "source_ip", "username", "event_count", "evidence"]
    if df.empty:
        return pd.DataFrame(columns=columns)

    findings = []
    failures = df[
        df["event_type"].str.lower().str.contains(
            r"fail|denied|invalid", regex=True, na=False
        )
    ]

    if not failures.empty:
        for ip, group in failures.groupby("source_ip"):
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()
            max_count = 0
            for start in timestamps:
                end = start + pd.Timedelta(minutes=window_minutes)
                count = sum(start <= timestamp <= end for timestamp in timestamps)
                max_count = max(max_count, count)

            if max_count >= failure_threshold:
                findings.append({
                    "severity": "High" if max_count < failure_threshold + 2 else "Critical",
                    "finding": "Repeated authentication failures",
                    "source_ip": ip,
                    "username": ", ".join(sorted(group["username"].unique())[:3]),
                    "event_count": max_count,
                    "evidence": f"{max_count} failure events within {window_minutes} minutes",
                })

    successes = df[
        df["event_type"].str.lower().str.contains(
            r"login_success|successful_login|login success",
            regex=True,
            na=False,
        )
    ]

    for _, success in successes.iterrows():
        prior = failures[
            (failures["source_ip"] == success["source_ip"])
            & (failures["timestamp"] < success["timestamp"])
            & (
                failures["timestamp"]
                >= success["timestamp"] - pd.Timedelta(minutes=window_minutes)
            )
        ]
        if len(prior) >= failure_threshold:
            findings.append({
                "severity": "Critical",
                "finding": "Successful login after repeated failures",
                "source_ip": success["source_ip"],
                "username": success["username"],
                "event_count": len(prior) + 1,
                "evidence": f"{len(prior)} failure events followed by a successful login",
            })

    critical = df[df["severity"] == "Critical"]
    for ip, group in critical.groupby("source_ip"):
        findings.append({
            "severity": "Critical",
            "finding": "Critical-severity log event",
            "source_ip": ip,
            "username": ", ".join(sorted(group["username"].unique())[:3]),
            "event_count": len(group),
            "evidence": "; ".join(group["details"].astype(str).head(2).tolist()),
        })

    if not findings:
        return pd.DataFrame(columns=columns)

    result = pd.DataFrame(findings).drop_duplicates(
        subset=["finding", "source_ip", "username"]
    )
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    result["_sort"] = result["severity"].map(severity_order).fillna(4)
    return result.sort_values("_sort").drop(columns="_sort").reset_index(drop=True)


def style_plot(fig, title=None):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(17,30,45,0.85)",
        font=dict(family="Arial", size=14, color="#e2e8f0"),
        title=dict(text=title, font=dict(size=20, color="#5eead4")) if title else None,
        margin=dict(l=20, r=20, t=60, b=30),
        legend=dict(bgcolor="rgba(17,30,45,0.65)", font=dict(size=12, color="#dbeafe")),
        hoverlabel=dict(bgcolor="#193447", font_color="#ffffff", font_size=13),
    )
    fig.update_xaxes(gridcolor="#293b4d", zerolinecolor="#456174")
    fig.update_yaxes(gridcolor="#293b4d", zerolinecolor="#456174")
    return fig


def make_evidence_graph(df):
    graph = nx.Graph()
    for _, row in df.iterrows():
        ip = str(row["source_ip"])
        user = str(row["username"])
        event = str(row["event_type"])
        graph.add_node(ip, kind="IP")
        graph.add_node(user, kind="User")
        graph.add_node(event, kind="Event")
        graph.add_edge(ip, user, relation="seen with")
        graph.add_edge(user, event, relation="performed")

    if not graph.nodes:
        return style_plot(go.Figure(), "Evidence Relationships")

    pos = nx.spring_layout(graph, seed=7, k=0.8)
    edge_x, edge_y = [], []
    for a, b in graph.edges():
        x0, y0 = pos[a]
        x1, y1 = pos[b]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=1.5, color="#426477"),
        hoverinfo="none", showlegend=False,
    )
    xs, ys, labels, colors, symbols, hover = [], [], [], [], [], []
    for node, attrs in graph.nodes(data=True):
        x, y = pos[node]
        kind = attrs.get("kind", "Event")
        xs.append(x)
        ys.append(y)
        labels.append(str(node)[:22])
        colors.append({"IP": "#fb923c", "User": "#5eead4", "Event": "#60a5fa"}.get(kind, "#94a3b8"))
        symbols.append({"IP": "diamond", "User": "circle", "Event": "square"}.get(kind, "circle"))
        hover.append(f"{kind}: {node}")

    node_trace = go.Scatter(
        x=xs, y=ys, mode="markers+text",
        text=labels, textposition="top center",
        hovertext=hover, hoverinfo="text",
        marker=dict(size=18, color=colors, symbol=symbols,
                    line=dict(width=1, color="#e2e8f0")),
        showlegend=False,
    )
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(xaxis=dict(visible=False), yaxis=dict(visible=False), showlegend=False)
    return style_plot(fig, "Evidence Relationships")


# ====================== SIDEBAR AND DATA ======================
st.sidebar.markdown("# 🛡️ CyberTrace AI")
st.sidebar.caption("THREAT HUNTER • EVIDENCE-BASED INVESTIGATION")
st.sidebar.markdown("---")

pages = [
    "Home Dashboard",
    "Upload Security Logs",
    "Activity Analysis",
    "Attack Timeline",
    "Evidence Relationship Graph",
    "AI Investigator",
    "Incident Reports",
    "About CyberTrace AI",
]

if "nav_target" in st.session_state:
    default_page = st.session_state.pop("nav_target")
else:
    default_page = "Home Dashboard"

page = st.sidebar.radio(
    "Navigation",
    pages,
    index=pages.index(default_page) if default_page in pages else 0,
)

st.sidebar.markdown("---")
st.sidebar.caption("DEMO MODE • Findings require analyst verification")

uploaded = st.sidebar.file_uploader(
    "Quick upload security logs (CSV)",
    type=["csv"],
    key="sidebar_csv",
)

if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
        df = normalize_logs(raw)
        data_source = f"Uploaded CSV ({len(df)} events)"
    except Exception as exc:
        st.sidebar.error(f"Could not read CSV: {exc}")
        df = normalize_logs(make_sample_logs())
        data_source = "Sample demo data (upload failed)"
else:
    df = normalize_logs(make_sample_logs())
    data_source = "Fictional sample data"

findings = detect_findings(df)
high_critical = (
    findings[findings["severity"].isin(["High", "Critical"])]
    if not findings.empty else findings
)


# ====================== HOME DASHBOARD ======================
if page == "Home Dashboard":
    st.markdown("""
    <div class="hero-card">
      <div class="hero-kicker">Security Operations Center • Threat Hunter</div>
      <div class="hero-title">🛡️ CyberTrace AI</div>
      <div class="hero-subtitle">
        See the signal in your security logs. Explore suspicious activity,
        follow the event timeline, and turn evidence into a clear investigation report.
      </div>
    </div>
    """, unsafe_allow_html=True)

    status_color = "#5eead4" if "Uploaded" in data_source else "#60a5fa"
    st.markdown(
        f'<div class="section-card"><span class="mini-label">Current investigation</span><br>'
        f'<b style="color:{status_color};font-size:1.05rem">● {data_source}</b><br>'
        f'<span style="color:#94a3b8">Updated {datetime.now().strftime("%d %b %Y • %H:%M")}</span></div>',
        unsafe_allow_html=True,
    )

    st.info(
        "Analyst note: automated findings are investigation leads, not proof of compromise. "
        "Validate them against trusted source evidence."
    )

    total_events = len(df)
    unique_ips = df["source_ip"].nunique() if total_events else 0
    unique_users = df["username"].nunique() if total_events else 0
    critical_count = int((findings["severity"] == "Critical").sum()) if not findings.empty else 0
    high_count = int((findings["severity"] == "High").sum()) if not findings.empty else 0
    medium_count = int((findings["severity"] == "Medium").sum()) if not findings.empty else 0

    st.markdown("### 📡 Investigation at a glance")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("📍 Total Events", f"{total_events:,}")
    m2.metric("🌐 Source IPs", f"{unique_ips:,}")
    m3.metric("👤 Accounts Seen", f"{unique_users:,}")
    m4.metric("🚨 High / Critical", f"{high_count + critical_count:,}")

    if total_events:
        left, right = st.columns([1.15, 1])
        with left:
            st.markdown("### 📊 Event distribution")
            counts = df["event_type"].value_counts().rename_axis("Event Type").reset_index(name="Count")
            fig = px.bar(
                counts, x="Event Type", y="Count", color="Event Type", text="Count",
                color_discrete_sequence=[
                    "#5eead4", "#60a5fa", "#fbbf24", "#fb923c",
                    "#f87171", "#a78bfa", "#f472b6"
                ],
            )
            fig.update_traces(textposition="outside", marker_line_width=0, opacity=.95)
            st.plotly_chart(style_plot(fig, "Security Events by Type"), use_container_width=True)

        with right:
            st.markdown("### 🎯 Severity overview")
            sev = df["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
            fig = px.pie(
                sev, names="Severity", values="Count", hole=0.62,
                color="Severity", color_discrete_map=COLORS,
            )
            fig.update_traces(
                textposition="inside", textinfo="percent+label",
                marker=dict(line=dict(color="#101923", width=3)),
            )
            fig.add_annotation(
                text=f"{total_events}<br><span style='font-size:12px'>events</span>",
                x=.5, y=.5, showarrow=False,
                font=dict(size=23, color="#f8fafc"),
            )
            st.plotly_chart(style_plot(fig, "Severity Mix"), use_container_width=True)

        left, right = st.columns([1.15, 1])
        with left:
            st.markdown("### ⏱️ Activity over time")
            time_counts = df.set_index("timestamp").resample("5min").size().reset_index(name="Events")
            fig = px.area(time_counts, x="timestamp", y="Events", markers=True)
            fig.update_traces(
                line=dict(color="#5eead4", width=3),
                fillcolor="rgba(45,212,191,0.20)",
                marker=dict(size=7, color="#60a5fa"),
            )
            st.plotly_chart(style_plot(fig, "Event Activity Timeline"), use_container_width=True)

        with right:
            st.markdown("### 🧾 Latest events")
            latest = df.sort_values("timestamp", ascending=False)[
                ["timestamp", "source_ip", "username", "event_type", "severity"]
            ].head(7).copy()
            latest["timestamp"] = latest["timestamp"].dt.strftime("%d %b %H:%M")
            st.dataframe(latest, use_container_width=True, hide_index=True, height=310)

    st.markdown("### 🚨 Priority findings")
    if findings.empty:
        st.success("No findings matched the current detection rules.")
    else:
        st.caption(
            f"{len(findings)} rule-based finding(s) • {critical_count} critical • "
            f"{high_count} high • {medium_count} medium"
        )
        st.dataframe(findings, use_container_width=True, hide_index=True)

    st.markdown("### 🧭 Quick actions")
    q1, q2, q3 = st.columns(3)
    with q1:
        st.markdown(
            '<div class="section-card"><h3>📥 Add your logs</h3>'
            '<p>Upload a CSV and inspect the normalized event records.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Go to log upload", use_container_width=True):
            st.session_state["nav_target"] = "Upload Security Logs"
            st.rerun()
    with q2:
        st.markdown(
            '<div class="section-card"><h3>🕒 Trace activity</h3>'
            '<p>Follow events in chronological order and review source context.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open attack timeline", use_container_width=True):
            st.session_state["nav_target"] = "Attack Timeline"
            st.rerun()
    with q3:
        st.markdown(
            '<div class="section-card"><h3>📄 Export findings</h3>'
            '<p>Create a shareable report for your investigation notes.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open incident reports", use_container_width=True):
            st.session_state["nav_target"] = "Incident Reports"
            st.rerun()


# ====================== UPLOAD SECURITY LOGS ======================
elif page == "Upload Security Logs":
    st.markdown("""
    <div class="hero-card">
      <div class="hero-kicker">Evidence intake • CSV workflow</div>
      <div class="hero-title">📥 Upload Security Logs</div>
      <div class="hero-subtitle">
        Bring your event data into one clear workspace. Preview the records,
        check the columns, and download a normalized copy for your investigation.
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="upload-banner">
      <h3>⬆️ Add a security log CSV</h3>
      <p>Choose a CSV file from your device. CyberTrace AI recognizes common column names
      and prepares the data for charts, findings, and timelines.</p>
      <p><b>Recommended fields:</b> timestamp · source_ip · username · event_type · severity · details</p>
    </div>
    """, unsafe_allow_html=True)

    upload_page_file = st.file_uploader(
        "Choose CSV file",
        type=["csv"],
        key="upload_page_csv",
        help="CSV only. Remove secrets and personal data before uploading.",
    )

    if upload_page_file is not None:
        try:
            page_raw = pd.read_csv(upload_page_file)
            page_df = normalize_logs(page_raw)
            st.success(f"File loaded successfully — {len(page_df):,} valid event(s) ready to inspect.")
            st.session_state["page_upload_preview"] = page_df
        except Exception as exc:
            st.error(f"We could not read this CSV: {exc}")

    st.warning(
        "Privacy reminder: remove passwords, API keys, session tokens, personal data, "
        "and confidential information before uploading logs."
    )

    preview_df = st.session_state.get("page_upload_preview", df)
    preview_source = (
        "Newly uploaded file"
        if "page_upload_preview" in st.session_state
        else data_source
    )

    st.markdown("### 📦 Dataset overview")
    st.caption(f"Preview source: {preview_source}")
    u1, u2, u3, u4 = st.columns(4)
    u1.metric("Events", f"{len(preview_df):,}")
    u2.metric("Unique IPs", f"{preview_df['source_ip'].nunique():,}")
    u3.metric("Accounts", f"{preview_df['username'].nunique():,}")
    u4.metric("Event types", f"{preview_df['event_type'].nunique():,}")

    with st.expander("🧩 See accepted column names", expanded=False):
        st.markdown("""
        | Dashboard field | Common alternatives |
        |---|---|
        | `timestamp` | `time`, `date`, `datetime`, `event_time` |
        | `source_ip` | `src_ip`, `ip`, `ip_address` |
        | `username` | `user`, `account` |
        | `event_type` | `event`, `action` |
        | `severity` | `level`, `risk` |
        | `details` | `message`, `description` |
        """)

    st.markdown("### 👀 Clear data preview")
    st.dataframe(
        preview_df.head(100),
        use_container_width=True,
        hide_index=True,
        height=390,
    )
    st.download_button(
        "⬇️ Download normalized logs (CSV)",
        data=preview_df.to_csv(index=False).encode("utf-8"),
        file_name="cybertrace_normalized_logs.csv",
        mime="text/csv",
        use_container_width=True,
    )

    with st.expander("🧪 View the built-in sample data", expanded=False):
        st.write(
            "These are fictional demonstration events. They are not live threat "
            "intelligence or evidence from a real organization."
        )
        sample_df = normalize_logs(make_sample_logs())
        st.dataframe(sample_df, use_container_width=True, hide_index=True, height=300)
        st.download_button(
            "Download sample logs",
            data=sample_df.to_csv(index=False).encode("utf-8"),
            file_name="cybertrace_sample_logs.csv",
            mime="text/csv",
        )


# ====================== ACTIVITY ANALYSIS ======================
elif page == "Activity Analysis":
    st.title("📊 Activity Analysis")
    st.write("Explore activity by source IP, user, event type, and severity.")

    c1, c2 = st.columns(2)
    with c1:
        ips = ["All"] + sorted(df["source_ip"].unique().tolist())
        chosen_ip = st.selectbox("Filter by source IP", ips)
    with c2:
        users = ["All"] + sorted(df["username"].unique().tolist())
        chosen_user = st.selectbox("Filter by username", users)

    filtered = df.copy()
    if chosen_ip != "All":
        filtered = filtered[filtered["source_ip"] == chosen_ip]
    if chosen_user != "All":
        filtered = filtered[filtered["username"] == chosen_user]

    a, b, c = st.columns(3)
    a.metric("Matching Events", len(filtered))
    b.metric("Unique IPs", filtered["source_ip"].nunique())
    c.metric("Unique Accounts", filtered["username"].nunique())

    if not filtered.empty:
        left, right = st.columns(2)
        with left:
            event_counts = filtered["event_type"].value_counts().rename_axis("Event Type").reset_index(name="Count")
            fig = px.bar(
                event_counts, x="Event Type", y="Count",
                color="Count", color_continuous_scale=["#115e59", "#5eead4"],
            )
            st.plotly_chart(style_plot(fig, "Filtered Events by Type"), use_container_width=True)

        with right:
            ip_counts = filtered["source_ip"].value_counts().head(10).rename_axis("Source IP").reset_index(name="Count")
            fig = px.bar(
                ip_counts, x="Count", y="Source IP", orientation="h",
                color="Count", color_continuous_scale=["#155e75", "#fb923c"],
            )
            st.plotly_chart(style_plot(fig, "Top Source IPs"), use_container_width=True)

    st.dataframe(filtered, use_container_width=True, hide_index=True)


# ====================== ATTACK TIMELINE ======================
elif page == "Attack Timeline":
    st.title("🕒 Attack Timeline")
    st.write("Filter events and inspect their chronological sequence. Markers use severity colors.")

    c1, c2 = st.columns(2)
    with c1:
        users = ["All"] + sorted(df["username"].unique().tolist())
        selected_user = st.selectbox("Filter by username", users)
    with c2:
        ips = ["All"] + sorted(df["source_ip"].unique().tolist())
        selected_ip = st.selectbox("Filter by source IP", ips)

    timeline = df.copy()
    if selected_user != "All":
        timeline = timeline[timeline["username"] == selected_user]
    if selected_ip != "All":
        timeline = timeline[timeline["source_ip"] == selected_ip]

    if timeline.empty:
        st.warning("No events match these filters.")
    else:
        fig = px.scatter(
            timeline,
            x="timestamp",
            y="username",
            color="severity",
            symbol="event_type",
            hover_data=["source_ip", "event_type", "details", "event_id"],
            color_discrete_map=COLORS,
            size_max=16,
        )
        fig.update_traces(marker=dict(size=13, line=dict(width=1, color="#e2e8f0")))
        st.plotly_chart(style_plot(fig, "Chronological Security Events"), use_container_width=True)

        st.subheader("Chronological evidence log")
        st.dataframe(
            timeline.sort_values("timestamp", ascending=False)[
                ["timestamp", "event_id", "severity", "source_ip", "username", "event_type", "details"]
            ],
            use_container_width=True,
            hide_index=True,
        )
        st.download_button(
            "Download timeline CSV",
            data=timeline.to_csv(index=False).encode("utf-8"),
            file_name="cybertrace_attack_timeline.csv",
            mime="text/csv",
        )


# ====================== EVIDENCE RELATIONSHIP GRAPH ======================
elif page == "Evidence Relationship Graph":
    st.title("🕸️ Evidence Relationship Graph")
    st.write("Explore observed relationships between source IPs, usernames, and event types.")
    st.caption("Connections show co-occurrence in the uploaded logs; they do not prove malicious intent.")

    graph_fig = make_evidence_graph(df)
    st.plotly_chart(graph_fig, use_container_width=True)

    g1, g2, g3 = st.columns(3)
    g1.metric("Unique IPs", df["source_ip"].nunique())
    g2.metric("Unique Users", df["username"].nunique())
    g3.metric("Event Types", df["event_type"].nunique())

    st.subheader("Relationship source data")
    st.dataframe(
        df[["timestamp", "source_ip", "username", "event_type", "severity"]],
        use_container_width=True,
        hide_index=True,
    )


# ====================== AI INVESTIGATOR ======================
elif page == "AI Investigator":
    st.title("🤖 AI Investigator")
    st.write("Review rule-based findings and, if configured, request an AI-generated summary.")
    st.warning(
        "Only send logs to an external AI service if you have permission. "
        "Remove passwords, tokens, personal data, and confidential details first."
    )

    if findings.empty:
        st.success("No findings matched the current detection rules.")
    else:
        st.dataframe(findings, use_container_width=True, hide_index=True)

    groq_key = None
    try:
        groq_key = st.secrets.get("GROQ_API_KEY")
    except Exception:
        groq_key = os.getenv("GROQ_API_KEY")

    if st.button("Generate Investigation Summary"):
        if findings.empty:
            st.info("There are no rule-based findings to summarize.")
        elif not groq_key:
            st.info(
                "Groq is not configured yet. Add GROQ_API_KEY in Streamlit app Secrets "
                "to enable AI summaries. Do not paste your key into this file or public GitHub."
            )
            st.write("Rule-based summary:")
            st.write(f"Analyzed **{len(df)} events** and produced **{len(findings)} findings**.")
            st.write(f"High/Critical findings: **{len(high_critical)}**.")
            st.write(
                "These findings are indicators for investigation, not proof that a cyberattack occurred."
            )
        else:
            try:
                from groq import Groq

                client = Groq(api_key=groq_key)
                summary_input = findings.to_dict(orient="records")
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a cautious cybersecurity analyst. Summarize only the supplied "
                                "rule-based findings, explain uncertainty, and suggest safe defensive "
                                "validation steps. Never claim a finding proves compromise."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Summarize these findings for an incident responder in clear language: "
                                f"{summary_input}"
                            ),
                        },
                    ],
                    temperature=0.2,
                    max_tokens=700,
                )
                st.markdown(response.choices[0].message.content)
            except Exception as exc:
                st.error(f"AI summary failed: {exc}")
                st.caption("Check that GROQ_API_KEY is set correctly in Streamlit Secrets.")


# ====================== INCIDENT REPORTS ======================
elif page == "Incident Reports":
    st.title("📄 Incident Reports")
    st.write("Generate a downloadable report containing dataset context and rule-based findings.")

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [
        "# CyberTrace AI — Incident Investigation Report",
        "",
        f"Generated: {report_time}",
        f"Data source: {data_source}",
        f"Total events analyzed: {len(df)}",
        f"Unique source IPs: {df['source_ip'].nunique()}",
        f"Unique accounts: {df['username'].nunique()}",
        f"Total findings: {len(findings)}",
        "",
        "## Important interpretation note",
        "These rule-based findings are investigation leads, not proof of compromise.",
        "",
        "## Findings",
    ]

    if findings.empty:
        report_lines.append("No findings matched the configured rules.")
    else:
        for idx, row in findings.iterrows():
            report_lines.extend([
                f"### {idx + 1}. [{row['severity']}] {row['finding']}",
                f"- Source IP: {row['source_ip']}",
                f"- Username: {row['username']}",
                f"- Event count: {row['event_count']}",
                f"- Evidence: {row['evidence']}",
                "",
            ])

    report_text = "\n".join(report_lines)

    r1, r2, r3 = st.columns(3)
    r1.metric("Events Reviewed", len(df))
    r2.metric("Total Findings", len(findings))
    r3.metric("High / Critical", len(high_critical))

    st.download_button(
        "⬇️ Download Forensic Report (Markdown)",
        data=report_text.encode("utf-8"),
        file_name="cybertrace_incident_report.md",
        mime="text/markdown",
        use_container_width=True,
    )
    st.download_button(
        "⬇️ Download Findings (CSV)",
        data=findings.to_csv(index=False).encode("utf-8"),
        file_name="cybertrace_findings.csv",
        mime="text/csv",
        use_container_width=True,
    )

    with st.expander("Preview report"):
        st.markdown(report_text)


# ====================== ABOUT ======================
elif page == "About CyberTrace AI":
    st.title("ℹ️ About CyberTrace AI")
    st.markdown("""
    CyberTrace AI is a demonstration dashboard for reviewing security-event logs.

    **Included features**
    - CSV upload and common-column normalization
    - Transparent rule-based detection of repeated authentication failures
    - Detection of successful logins following repeated failures
    - Event, severity, and source-IP visualizations
    - Interactive chronological timeline
    - Relationship graph connecting IPs, users, and event types
    - Downloadable incident report and findings CSV
    - Optional Groq-powered investigation summary

    **Responsible use**

    Use only logs you are authorized to analyze. Protect sensitive information,
    verify findings against original evidence, and do not treat automated flags as
    proof of malicious activity.
    """)
    st.caption("Threat Hunter theme • Dark slate, teal, orange, and red severity colors")
```### Part 2 of 3

```python
# ====================== SIDEBAR AND DATA ======================
st.sidebar.markdown("# 🛡️ CyberTrace AI")
st.sidebar.caption("THREAT HUNTER • EVIDENCE-BASED INVESTIGATION")
st.sidebar.markdown("---")

pages = [
    "Home Dashboard",
    "Upload Security Logs",
    "Activity Analysis",
    "Attack Timeline",
    "Evidence Relationship Graph",
    "AI Investigator",
    "Incident Reports",
    "About CyberTrace AI",
]

if "nav_target" in st.session_state:
    default_page = st.session_state.pop("nav_target")
else:
    default_page = "Home Dashboard"

page = st.sidebar.radio(
    "Navigation",
    pages,
    index=pages.index(default_page) if default_page in pages else 0,
)

st.sidebar.markdown("---")
st.sidebar.caption("DEMO MODE • Findings require analyst verification")

uploaded = st.sidebar.file_uploader(
    "Quick upload security logs (CSV)",
    type=["csv"],
    key="sidebar_csv",
)

if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
        df = normalize_logs(raw)
        data_source = f"Uploaded CSV ({len(df)} events)"
    except Exception as exc:
        st.sidebar.error(f"Could not read CSV: {exc}")
        df = normalize_logs(make_sample_logs())
        data_source = "Sample demo data (upload failed)"
else:
    df = normalize_logs(make_sample_logs())
    data_source = "Fictional sample data"

findings = detect_findings(df)
high_critical = (
    findings[findings["severity"].isin(["High", "Critical"])]
    if not findings.empty else findings
)


# ====================== HOME DASHBOARD ======================
if page == "Home Dashboard":
    st.markdown("""
    <div class="hero-card">
      <div class="hero-kicker">Security Operations Center • Threat Hunter</div>
      <div class="hero-title">🛡️ CyberTrace AI</div>
      <div class="hero-subtitle">
        See the signal in your security logs. Explore suspicious activity,
        follow the event timeline, and turn evidence into a clear investigation report.
      </div>
    </div>
    """, unsafe_allow_html=True)

    status_color = "#5eead4" if "Uploaded" in data_source else "#60a5fa"
    st.markdown(
        f'<div class="section-card"><span class="mini-label">Current investigation</span><br>'
        f'<b style="color:{status_color};font-size:1.05rem">● {data_source}</b><br>'
        f'<span style="color:#94a3b8">Updated {datetime.now().strftime("%d %b %Y • %H:%M")}</span></div>',
        unsafe_allow_html=True,
    )

    st.info(
        "Analyst note: automated findings are investigation leads, not proof of compromise. "
        "Validate them against trusted source evidence."
    )

    total_events = len(df)
    unique_ips = df["source_ip"].nunique() if total_events else 0
    unique_users = df["username"].nunique() if total_events else 0
    critical_count = int((findings["severity"] == "Critical").sum()) if not findings.empty else 0
    high_count = int((findings["severity"] == "High").sum()) if not findings.empty else 0
    medium_count = int((findings["severity"] == "Medium").sum()) if not findings.empty else 0

    st.markdown("### 📡 Investigation at a glance")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("📍 Total Events", f"{total_events:,}")
    m2.metric("🌐 Source IPs", f"{unique_ips:,}")
    m3.metric("👤 Accounts Seen", f"{unique_users:,}")
    m4.metric("🚨 High / Critical", f"{high_count + critical_count:,}")

    if total_events:
        left, right = st.columns([1.15, 1])

        with left:
            st.markdown("### 📊 Event distribution")
            counts = (
                df["event_type"].value_counts()
                .rename_axis("Event Type")
                .reset_index(name="Count")
            )
            fig = px.bar(
                counts,
                x="Event Type",
                y="Count",
                color="Event Type",
                text="Count",
                color_discrete_sequence=[
                    "#5eead4", "#60a5fa", "#fbbf24",
                    "#fb923c", "#f87171", "#a78bfa", "#f472b6",
                ],
            )
            fig.update_traces(
                textposition="outside",
                marker_line_width=0,
                opacity=.95,
            )
            st.plotly_chart(
                style_plot(fig, "Security Events by Type"),
                use_container_width=True,
            )

        with right:
            st.markdown("### 🎯 Severity overview")
            sev = (
                df["severity"].value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            fig = px.pie(
                sev,
                names="Severity",
                values="Count",
                hole=0.62,
                color="Severity",
                color_discrete_map=COLORS,
            )
            fig.update_traces(
                textposition="inside",
                textinfo="percent+label",
                marker=dict(line=dict(color="#101923", width=3)),
            )
            fig.add_annotation(
                text=f"{total_events}<br><span style='font-size:12px'>events</span>",
                x=.5,
                y=.5,
                showarrow=False,
                font=dict(size=23, color="#f8fafc"),
            )
            st.plotly_chart(
                style_plot(fig, "Severity Mix"),
                use_container_width=True,
            )

        left, right = st.columns([1.15, 1])

        with left:
            st.markdown("### ⏱️ Activity over time")
            time_counts = (
                df.set_index("timestamp")
                .resample("5min")
                .size()
                .reset_index(name="Events")
            )
            fig = px.area(time_counts, x="timestamp", y="Events", markers=True)
            fig.update_traces(
                line=dict(color="#5eead4", width=3),
                fillcolor="rgba(45,212,191,0.20)",
                marker=dict(size=7, color="#60a5fa"),
            )
            st.plotly_chart(
                style_plot(fig, "Event Activity Timeline"),
                use_container_width=True,
            )

        with right:
            st.markdown("### 🧾 Latest events")
            latest = df.sort_values(
                "timestamp", ascending=False
            )[
                ["timestamp", "source_ip", "username", "event_type", "severity"]
            ].head(7).copy()

            latest["timestamp"] = latest["timestamp"].dt.strftime("%d %b %H:%M")
            st.dataframe(
                latest,
                use_container_width=True,
                hide_index=True,
                height=310,
            )

    st.markdown("### 🚨 Priority findings")
    if findings.empty:
        st.success("No findings matched the current detection rules.")
    else:
        st.caption(
            f"{len(findings)} rule-based finding(s) • "
            f"{critical_count} critical • {high_count} high • {medium_count} medium"
        )
        st.dataframe(findings, use_container_width=True, hide_index=True)

    st.markdown("### 🧭 Quick actions")
    q1, q2, q3 = st.columns(3)

    with q1:
        st.markdown(
            '<div class="section-card"><h3>📥 Add your logs</h3>'
            '<p>Upload a CSV and inspect the normalized event records.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Go to log upload", use_container_width=True):
            st.session_state["nav_target"] = "Upload Security Logs"
            st.rerun()

    with q2:
        st.markdown(
            '<div class="section-card"><h3>🕒 Trace activity</h3>'
            '<p>Follow events in chronological order and review source context.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open attack timeline", use_container_width=True):
            st.session_state["nav_target"] = "Attack Timeline"
            st.rerun()

    with q3:
        st.markdown(
            '<div class="section-card"><h3>📄 Export findings</h3>'
            '<p>Create a shareable report for your investigation notes.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open incident reports", use_container_width=True):
            st.session_state["nav_target"] = "Incident Reports"
            st.rerun()


# ====================== UPLOAD SECURITY LOGS ======================
elif page == "Upload Security Logs":
    st.markdown("""
    <div class="hero-card">
      <div class="hero-kicker">Evidence intake • CSV workflow</div>
      <div class="hero-title">📥 Upload Security Logs</div>
      <div class="hero-subtitle">
        Bring your event data into one clear workspace. Preview the records,
        check the columns, and download a normalized copy for your investigation.
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="upload-banner">
      <h3>⬆️ Add a security log CSV</h3>
      <p>Choose a CSV file from your device. CyberTrace AI recognizes common column names
      and prepares the data for charts, findings, and timelines.</p>
      <p><b>Recommended fields:</b>
      timestamp · source_ip · username · event_type · severity · details</p>
    </div>
    """, unsafe_allow_html=True)

    upload_page_file = st.file_uploader(
        "Choose CSV file",
        type=["csv"],
        key="upload_page_csv",
        help="CSV only. Remove secrets and personal data before uploading.",
    )

    if upload_page_file is not None:
        try:
            page_raw = pd.read_csv(upload_page_file)
            page_df = normalize_logs(page_raw)
            st.success(
                f"File loaded successfully — {len(page_df):,} valid event(s) ready to inspect."
            )
            st.session_state["page_upload_preview"] = page_df
        except Exception as exc:
            st.error(f"We could not read this CSV: {exc}")

    st.warning(
        "Privacy reminder: remove passwords, API keys, session tokens, personal data, "
        "and confidential information before uploading logs."
    )

    preview_df = st.session_state.get("page_upload_preview", df)
    preview_source = (
        "Newly uploaded file"
        if "page_upload_preview" in st.session_state
        else data_source
    )

    st.markdown("### 📦 Dataset overview")
    st.caption(f"Preview source: {preview_source}")
    u1, u2, u3, u4 = st.columns(4)
    u1.metric("Events", f"{len(preview_df):,}")
    u2.metric("Unique IPs", f"{preview_df['source_ip'].nunique():,}")
    u3.metric("Accounts", f"{preview_df['username'].nunique():,}")
    u4.metric("Event types", f"{preview_df['event_type'].nunique():,}")

    with st.expander("🧩 See accepted column names", expanded=False):
        st.markdown("""
        | Dashboard field | Common alternatives |
        |---|---|
        | `timestamp` | `time`, `date`, `datetime`, `event_time` |
        | `source_ip` | `src_ip`, `ip`, `ip_address` |
        | `username` | `user`, `account` |
        | `event_type` | `event`, `action` |
        | `severity` | `level`, `risk` |
        | `details` | `message`, `description` |
        """)

    st.markdown("### 👀 Clear data preview")
    st.dataframe(
        preview_df.head(100),
        use_container_width=True,
        hide_index=True,
        height=390,
    )

    st.download_button(
        "⬇️ Download normalized logs (CSV)",
        data=preview_df.to_csv(index=False).encode("utf-8"),
        file_name="cybertrace_normalized_logs.csv",
        mime="text/csv",
        use_container_width=True,
    )

    with st.expander("🧪 View the built-in sample data", expanded=False):
        st.write(
            "These are fictional demonstration events. They are not live threat "
            "intelligence or evidence from a real organization."
        )
        sample_df = normalize_logs(make_sample_logs())
        st.dataframe(
            sample_df,
            use_container_width=True,
            hide_index=True,
            height=300,
        )
        st.download_button(
            "Download sample logs",
            data=sample_df.to_csv(index=False).encode("utf-8"),
            file_name="cybertrace_sample_logs.csv",
            mime="text/csv",
        )
        # ====================== ACTIVITY ANALYSIS ======================
elif page == "Activity Analysis":
    st.title("📊 Activity Analysis")
    st.write("Explore activity by source IP, user, event type, and severity.")

    c1, c2 = st.columns(2)
    with c1:
        ips = ["All"] + sorted(df["source_ip"].unique().tolist())
        chosen_ip = st.selectbox("Filter by source IP", ips)
    with c2:
        users = ["All"] + sorted(df["username"].unique().tolist())
        chosen_user = st.selectbox("Filter by username", users)

    filtered = df.copy()
    if chosen_ip != "All":
        filtered = filtered[filtered["source_ip"] == chosen_ip]
    if chosen_user != "All":
        filtered = filtered[filtered["username"] == chosen_user]

    a, b, c = st.columns(3)
    a.metric("Matching Events", len(filtered))
    b.metric("Unique IPs", filtered["source_ip"].nunique())
    c.metric("Unique Accounts", filtered["username"].nunique())

    if not filtered.empty:
        left, right = st.columns(2)

        with left:
            event_counts = (
                filtered["event_type"].value_counts()
                .rename_axis("Event Type")
                .reset_index(name="Count")
            )
            fig = px.bar(
                event_counts,
                x="Event Type",
                y="Count",
                color="Count",
                color_continuous_scale=["#115e59", "#5eead4"],
            )
            st.plotly_chart(
                style_plot(fig, "Filtered Events by Type"),
                use_container_width=True,
            )

        with right:
            ip_counts = (
                filtered["source_ip"].value_counts().head(10)
                .rename_axis("Source IP")
                .reset_index(name="Count")
            )
            fig = px.bar(
                ip_counts,
                x="Count",
                y="Source IP",
                orientation="h",
                color="Count",
                color_continuous_scale=["#155e75", "#fb923c"],
            )
            st.plotly_chart(
                style_plot(fig, "Top Source IPs"),
                use_container_width=True,
            )

    st.dataframe(filtered, use_container_width=True, hide_index=True)


# ====================== ATTACK TIMELINE ======================
elif page == "Attack Timeline":
    st.title("🕒 Attack Timeline")
    st.write("Filter events and inspect their chronological sequence. Markers use severity colors.")

    c1, c2 = st.columns(2)
    with c1:
        users = ["All"] + sorted(df["username"].unique().tolist())
        selected_user = st.selectbox("Filter by username", users)
    with c2:
        ips = ["All"] + sorted(df["source_ip"].unique().tolist())
        selected_ip = st.selectbox("Filter by source IP", ips)

    timeline = df.copy()
    if selected_user != "All":
        timeline = timeline[timeline["username"] == selected_user]
    if selected_ip != "All":
        timeline = timeline[timeline["source_ip"] == selected_ip]

    if timeline.empty:
        st.warning("No events match these filters.")
    else:
        fig = px.scatter(
            timeline,
            x="timestamp",
            y="username",
            color="severity",
            symbol="event_type",
            hover_data=["source_ip", "event_type", "details", "event_id"],
            color_discrete_map=COLORS,
            size_max=16,
        )
        fig.update_traces(
            marker=dict(size=13, line=dict(width=1, color="#e2e8f0"))
        )
        st.plotly_chart(
            style_plot(fig, "Chronological Security Events"),
            use_container_width=True,
        )

        st.subheader("Chronological evidence log")
        st.dataframe(
            timeline.sort_values("timestamp", ascending=False)[
                [
                    "timestamp", "event_id", "severity", "source_ip",
                    "username", "event_type", "details",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download timeline CSV",
            data=timeline.to_csv(index=False).encode("utf-8"),
            file_name="cybertrace_attack_timeline.csv",
            mime="text/csv",
        )


# ====================== EVIDENCE RELATIONSHIP GRAPH ======================
elif page == "Evidence Relationship Graph":
    st.title("🕸️ Evidence Relationship Graph")
    st.write("Explore observed relationships between source IPs, usernames, and event types.")
    st.caption(
        "Connections show co-occurrence in the uploaded logs; they do not prove malicious intent."
    )

    graph_fig = make_evidence_graph(df)
    st.plotly_chart(graph_fig, use_container_width=True)

    g1, g2, g3 = st.columns(3)
    g1.metric("Unique IPs", df["source_ip"].nunique())
    g2.metric("Unique Users", df["username"].nunique())
    g3.metric("Event Types", df["event_type"].nunique())

    st.subheader("Relationship source data")
    st.dataframe(
        df[["timestamp", "source_ip", "username", "event_type", "severity"]],
        use_container_width=True,
        hide_index=True,
    )


# ====================== AI INVESTIGATOR ======================
elif page == "AI Investigator":
    st.title("🤖 AI Investigator")
    st.write("Review rule-based findings and, if configured, request an AI-generated summary.")
    st.warning(
        "Only send logs to an external AI service if you have permission. "
        "Remove passwords, tokens, personal data, and confidential details first."
    )

    if findings.empty:
        st.success("No findings matched the current detection rules.")
    else:
        st.dataframe(findings, use_container_width=True, hide_index=True)

    groq_key = None
    try:
        groq_key = st.secrets.get("GROQ_API_KEY")
    except Exception:
        groq_key = os.getenv("GROQ_API_KEY")

    if st.button("Generate Investigation Summary"):
        if findings.empty:
            st.info("There are no rule-based findings to summarize.")
        elif not groq_key:
            st.info(
                "Groq is not configured yet. Add GROQ_API_KEY in Streamlit app Secrets "
                "to enable AI summaries. Do not paste your key into this file or public GitHub."
            )
            st.write("Rule-based summary:")
            st.write(
                f"Analyzed **{len(df)} events** and produced **{len(findings)} findings**."
            )
            st.write(f"High/Critical findings: **{len(high_critical)}**.")
            st.write(
                "These findings are indicators for investigation, not proof that a cyberattack occurred."
            )
        else:
            try:
                from groq import Groq

                client = Groq(api_key=groq_key)
                summary_input = findings.to_dict(orient="records")

                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a cautious cybersecurity analyst. Summarize only the supplied "
                                "rule-based findings, explain uncertainty, and suggest safe defensive "
                                "validation steps. Never claim a finding proves compromise."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Summarize these findings for an incident responder in clear language: "
                                f"{summary_input}"
                            ),
                        },
                    ],
                    temperature=0.2,
                    max_tokens=700,
                )

                st.markdown(response.choices[0].message.content)

            except Exception as exc:
                st.error(f"AI summary failed: {exc}")
                st.caption("Check that GROQ_API_KEY is set correctly in Streamlit Secrets.")


# ====================== INCIDENT REPORTS ======================
elif page == "Incident Reports":
    st.title("📄 Incident Reports")
    st.write("Generate a downloadable report containing dataset context and rule-based findings.")

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [
        "# CyberTrace AI — Incident Investigation Report",
        "",
        f"Generated: {report_time}",
        f"Data source: {data_source}",
        f"Total events analyzed: {len(df)}",
        f"Unique source IPs: {df['source_ip'].nunique()}",
        f"Unique accounts: {df['username'].nunique()}",
        f"Total findings: {len(findings)}",
        "",
        "## Important interpretation note",
        "These rule-based findings are investigation leads, not proof of compromise.",
        "",
        "## Findings",
    ]

    if findings.empty:
        report_lines.append("No findings matched the configured rules.")
    else:
        for idx, row in findings.iterrows():
            report_lines.extend([
                f"### {idx + 1}. [{row['severity']}] {row['finding']}",
                f"- Source IP: {row['source_ip']}",
                f"- Username: {row['username']}",
                f"- Event count: {row['event_count']}",
                f"- Evidence: {row['evidence']}",
                "",
            ])

    report_text = "\n".join(report_lines)

    r1, r2, r3 = st.columns(3)
    r1.metric("Events Reviewed", len(df))
    r2.metric("Total Findings", len(findings))
    r3.metric("High / Critical", len(high_critical))

    st.download_button(
        "⬇️ Download Forensic Report (Markdown)",
        data=report_text.encode("utf-8"),
        file_name="cybertrace_incident_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

    st.download_button(
        "⬇️ Download Findings (CSV)",
        data=findings.to_csv(index=False).encode("utf-8"),
        file_name="cybertrace_findings.csv",
        mime="text/csv",
        use_container_width=True,
    )

    with st.expander("Preview report"):
        st.markdown(report_text)


# ====================== ABOUT ======================
elif page == "About CyberTrace AI":
    st.title("ℹ️ About CyberTrace AI")
    st.markdown("""
    CyberTrace AI is a demonstration dashboard for reviewing security-event logs.

    **Included features**
    - CSV upload and common-column normalization
    - Transparent rule-based detection of repeated authentication failures
    - Detection of successful logins following repeated failures
    - Event, severity, and source-IP visualizations
    - Interactive chronological timeline
    - Relationship graph connecting IPs, users, and event types
    - Downloadable incident report and findings CSV
    - Optional Groq-powered investigation summary

    **Responsible use**

    Use only logs you are authorized to analyze. Protect sensitive information,
    verify findings against original evidence, and do not treat automated flags as
    proof of malicious activity.
    """)
    st.caption(
        "Threat Hunter theme • Dark slate, teal, orange, and red severity colors"
    )
