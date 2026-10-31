from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from ir_workbench.data import DATA_PATH, SEVERITIES, load_incidents
from ir_workbench.reports import build_incident_report
from ir_workbench.services import (
    build_timeline,
    recommend_escalation,
    scope_incident,
    triage_incidents,
    verify_sha256,
)


ROOT = Path(__file__).resolve().parent
EVIDENCE_PATH = ROOT / "data" / "evidence" / "SYNTHETIC_auth_events.txt"
HASH_COLORS = {
    "Critical": "#ff5b67",
    "High": "#ff9f43",
    "Medium": "#f4d35e",
    "Low": "#8fa3b8",
    "Informational": "#49dcb1",
}

st.set_page_config(
    page_title="Enterprise IR Workbench",
    page_icon="◢",
    layout="wide",
    initial_sidebar_state="expanded",
)


def apply_styles() -> None:
    st.markdown(
        """
        <style>
        :root { --lime: #b6f247; --lime-soft: #d3ff78; --muted: #8d9996; }
        html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
        .stApp { background: radial-gradient(ellipse at 70% 0%, #142018 0%, #0c100e 38%, #090b0a 78%); color: #eef3ed; }
        [data-testid="stSidebar"] { background: linear-gradient(180deg, #101612 0%, #0c100e 100%); border-right: 1px solid #29342b; }
        [data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
        h1, h2, h3 { letter-spacing: -0.035em; }
        h1 { font-size: 2rem !important; }
        h2 { font-size: 1.3rem !important; }
        .eyebrow { color: var(--lime); font: 500 0.72rem 'DM Mono', monospace; letter-spacing: .14em; text-transform: uppercase; }
        .brand { font-weight: 800; font-size: 1.05rem; letter-spacing: -.04em; color: #f3f7ef; margin: 0 0 .1rem; }
        .brand-mark { color: var(--lime); font-family: 'DM Mono', monospace; }
        .muted { color: var(--muted); font-size: .84rem; }
        .kpi-card, .panel, .case-card {
          background: linear-gradient(145deg, rgba(24,32,27,.94), rgba(15,20,17,.92));
          border: 1px solid #2a362d; border-radius: 17px; padding: 1.05rem 1.15rem;
          box-shadow: 0 12px 30px rgba(0,0,0,.18), inset 0 1px rgba(255,255,255,.025);
        }
        .kpi-label { color: #9daaa0; font-size: .76rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
        .kpi-value { color: #f4f8f2; font-size: 2rem; font-weight: 800; letter-spacing: -.055em; margin: .25rem 0 .05rem; }
        .kpi-foot { color: #819087; font-size: .75rem; }
        .lime { color: var(--lime); }
        .mono { font-family: 'DM Mono', monospace; }
        div[data-testid="stMetric"] { background: transparent; }
        .stButton > button, .stDownloadButton > button {
          border: 1px solid #526b34; border-radius: 10px; background: #b6f247; color: #11170d;
          font-weight: 800; transition: all .15s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover { border-color: #d3ff78; background: #c8ff6d; color: #11170d; }
        div[data-testid="stDataFrame"] { border: 1px solid #29342b; border-radius: 12px; overflow: hidden; }
        div[data-baseweb="select"] > div, div[data-baseweb="input"] > div { background: #131a15; border-color: #354238; border-radius: 9px; }
        hr { border-color: #263129; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str, note: str) -> None:
    st.markdown(
        f'<div class="kpi-card"><div class="kpi-label">{label}</div>'
        f'<div class="kpi-value">{value}</div><div class="kpi-foot">{note}</div></div>',
        unsafe_allow_html=True,
    )


def plotly_theme(fig, height: int = 310):
    fig.update_layout(
        height=height,
        margin=dict(l=12, r=12, t=26, b=12),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Manrope, sans-serif", color="#bdc8bf", size=11),
        legend=dict(bgcolor="rgba(0,0,0,0)", title_text=""),
        xaxis=dict(gridcolor="#263129", zerolinecolor="#263129"),
        yaxis=dict(gridcolor="#263129", zerolinecolor="#263129"),
    )
    return fig


def render_header(all_incidents: pd.DataFrame):
    min_date = all_incidents["detected_at"].min().date()
    max_date = all_incidents["detected_at"].max().date()
    title_col, search_col, date_col, status_col = st.columns([4.3, 2.6, 2.5, 1.5])
    with title_col:
        st.markdown('<div class="eyebrow">Security operations / incident response</div>', unsafe_allow_html=True)
        st.title("Incident Workbench")
    with search_col:
        st.markdown("<div style='height: 1.05rem'></div>", unsafe_allow_html=True)
        query = st.text_input("Search incidents", placeholder="Search ID, asset, account…", label_visibility="collapsed")
    with date_col:
        st.markdown("<div style='height: 1.05rem'></div>", unsafe_allow_html=True)
        date_range = st.date_input(
            "Detection window",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date,
            format="YYYY-MM-DD",
            label_visibility="collapsed",
        )
    with status_col:
        st.markdown(
            "<div style='height: 1.55rem'></div><div class='muted' style='text-align:right'>"
            "<span style='color:#b6f247'>●</span> SYNTHETIC FEED<br>🔔 0 &nbsp; Analyst · IR Desk</div>",
            unsafe_allow_html=True,
        )

    if isinstance(date_range, tuple):
        start_date, end_date = date_range
    else:
        start_date = end_date = date_range
    if start_date > end_date:
        st.error("The start date must be on or before the end date.")
        return query, start_date, end_date, False
    return query, start_date, end_date, True


def incident_table(incidents: pd.DataFrame, height: int = 350) -> None:
    visible = incidents[
        ["incident_id", "detected_at", "title", "severity", "status", "category", "owner"]
    ].copy()
    visible["detected_at"] = visible["detected_at"].dt.strftime("%b %d · %H:%M UTC")
    visible.columns = ["Incident", "Detected", "Alert", "Severity", "Status", "Category", "Analyst"]
    styled = (
        visible.style.map(
            lambda value: f"color: {HASH_COLORS.get(value, '#bdc8bf')}; font-weight: 700",
            subset=["Severity"],
        ).map(
            lambda value: (
                "color: #b6f247; font-weight: 600"
                if value in {"Investigating", "Escalated"}
                else "color: #8fd9a2; font-weight: 600"
                if value in {"Contained", "Resolved"}
                else "color: #bdc8bf; font-weight: 600"
            ),
            subset=["Status"],
        )
    )
    st.dataframe(
        styled,
        use_container_width=True,
        hide_index=True,
        height=height,
        column_config={
            "Incident": st.column_config.TextColumn(help="Synthetic incident identifier"),
            "Severity": st.column_config.TextColumn(),
            "Status": st.column_config.TextColumn(),
        },
    )


def render_overview(incidents: pd.DataFrame) -> None:
    all_assets = {
        asset.strip()
        for value in incidents["assets"]
        for asset in str(value).split("|")
        if asset.strip()
    }
    kpi_cols = st.columns(4)
    with kpi_cols[0]:
        metric_card("Total alerts", f"{len(incidents):,}", "In the selected detection window")
    with kpi_cols[1]:
        metric_card("Affected assets", f"{len(all_assets):,}", "Distinct assets in visible incidents")
    with kpi_cols[2]:
        critical_count = int(incidents["severity"].eq("Critical").sum())
        metric_card("Critical incidents", f"{critical_count:02,}", "Requires priority review")
    with kpi_cols[3]:
        high_count = int(incidents["severity"].eq("High").sum())
        metric_card("High-severity incidents", f"{high_count:02,}", "Expedited coordination")

    st.markdown("<div style='height:.9rem'></div>", unsafe_allow_html=True)
    chart_col, severity_col = st.columns([1.8, 1])
    with chart_col:
        st.markdown('<div class="eyebrow">Incident lifecycle</div>', unsafe_allow_html=True)
        st.subheader("Incident timeline")
        timeline = build_timeline(incidents)
        if timeline.empty:
            st.info("No lifecycle events match the current filters.")
        else:
            timeline["event_label"] = timeline["event"] + " · " + timeline["incident_id"]
            fig = px.scatter(
                timeline,
                x="event_time",
                y="incident_id",
                color="severity",
                symbol="event",
                hover_name="event_label",
                hover_data={"event_time": "|%b %d, %H:%M UTC", "severity": True, "incident_id": False},
                color_discrete_map=HASH_COLORS,
                category_orders={"severity": list(SEVERITIES)},
            )
            fig.update_traces(marker=dict(size=10, line=dict(width=1, color="#101510")))
            fig.update_layout(
                height=350,
                margin=dict(l=5, r=12, t=10, b=8),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Manrope, sans-serif", color="#bdc8bf", size=10),
                legend=dict(orientation="h", y=1.12, x=0, bgcolor="rgba(0,0,0,0)", title_text=""),
                xaxis=dict(gridcolor="#263129", title="", tickformat="%b %d<br>%H:%M"),
                yaxis=dict(gridcolor="#263129", title="", autorange="reversed"),
            )
            st.plotly_chart(fig, use_container_width=True)
    with severity_col:
        st.markdown('<div class="eyebrow">Queue composition</div>', unsafe_allow_html=True)
        st.subheader("Threat severity")
        counts = incidents["severity"].value_counts().reindex(SEVERITIES, fill_value=0).rename_axis("Severity").reset_index(name="Incidents")
        counts = counts.loc[counts["Incidents"] > 0]
        if counts.empty:
            st.info("No incidents match the current filters.")
        else:
            fig = px.pie(
                counts,
                values="Incidents",
                names="Severity",
                hole=0.72,
                color="Severity",
                color_discrete_map=HASH_COLORS,
            )
            fig.update_traces(textinfo="percent", textfont=dict(color="#f3f7ef", size=12), marker=dict(line=dict(color="#101510", width=3)))
            fig.update_layout(
                height=310,
                margin=dict(l=8, r=8, t=10, b=8),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Manrope, sans-serif", color="#bdc8bf", size=10),
                legend=dict(orientation="h", y=-.06, x=.05, bgcolor="rgba(0,0,0,0)", title_text=""),
                annotations=[dict(text=f"<b>{len(incidents)}</b><br>alerts", x=.5, y=.5, showarrow=False, font=dict(size=18, color="#eef3ed"))],
            )
            st.plotly_chart(fig, use_container_width=True)

    trend_col, queue_col = st.columns([1, 1.8])
    with trend_col:
        st.markdown('<div class="eyebrow">Detection volume</div>', unsafe_allow_html=True)
        st.subheader("Incident trend")
        if incidents.empty:
            st.info("No trend data in this date range.")
        else:
            trend = incidents.assign(day=incidents["detected_at"].dt.floor("D")).groupby("day").size().reset_index(name="Incidents")
            fig = px.area(trend, x="day", y="Incidents")
            fig.update_traces(line=dict(color="#b6f247", width=2), fillcolor="rgba(182,242,71,.12)")
            st.plotly_chart(plotly_theme(fig, 260), use_container_width=True)
    with queue_col:
        st.markdown('<div class="eyebrow">Analyst workspace</div>', unsafe_allow_html=True)
        st.subheader("Priority incident queue")
        priority = incidents.loc[incidents["severity"].isin(["Critical", "High"])].head(6)
        if priority.empty:
            st.info("No critical or high incidents in the current view.")
        else:
            incident_table(priority, height=260)


def render_queue(incidents: pd.DataFrame) -> None:
    st.markdown('<div class="eyebrow">Triage workspace</div>', unsafe_allow_html=True)
    st.title("Incident queue")
    severities = st.multiselect("Severity", SEVERITIES, default=list(SEVERITIES), key="queue_severities")
    available_statuses = sorted(incidents["status"].dropna().unique().tolist())
    statuses = st.multiselect("Investigation status", available_statuses, default=available_statuses, key="queue_statuses")
    queue = incidents.loc[
        incidents["severity"].isin(severities) & incidents["status"].isin(statuses)
    ].copy()
    st.caption(f"{len(queue)} incident(s) in the current queue · synthetic training records")
    incident_table(queue, height=450)
    if not queue.empty:
        selected_id = st.selectbox("Open incident details", queue["incident_id"].tolist())
        selected = queue.loc[queue["incident_id"] == selected_id].iloc[0]
        left, right = st.columns([1.4, 1])
        with left:
            st.markdown(f"### {selected['title']}")
            st.write(selected["summary"])
            st.caption(f"{selected['category']} · {selected['source']} · Assigned to {selected['owner']}")
        with right:
            recommendation = recommend_escalation(selected)
            st.markdown(f"**{recommendation['level']}**")
            st.write(recommendation["rationale"])
            st.caption(recommendation["notice"])


def render_scoping(incidents: pd.DataFrame) -> None:
    st.markdown('<div class="eyebrow">Entity relationships</div>', unsafe_allow_html=True)
    st.title("Incident scoping")
    if incidents.empty:
        st.info("No incidents are available for scoping under the current filters.")
        return
    incident_id = st.selectbox("Select a case to scope", incidents["incident_id"].tolist(), key="scope_incident")
    scope = scope_incident(incidents, incident_id)
    case = incidents.loc[incidents["incident_id"] == incident_id].iloc[0]
    metrics = st.columns(3)
    metrics[0].metric("Related incidents", len(scope["related_incidents"]))
    metrics[1].metric("Assets", len(scope["assets"]))
    metrics[2].metric("Indicators", len(scope["iocs"]))
    st.markdown(f"### {case['title']}")
    st.caption("Matches below are based on shared assets, accounts, or indicators in the synthetic dataset.")
    entity_col, related_col = st.columns([1, 1.8])
    with entity_col:
        st.markdown("**Observed entities**")
        for label, key in (("Assets", "assets"), ("Accounts", "accounts"), ("Indicators", "iocs")):
            values = scope[key]
            st.markdown(f"**{label}**")
            st.write(", ".join(values) if values else "None recorded")
    with related_col:
        st.markdown("**Potentially related incidents**")
        if scope["related_incidents"].empty:
            st.info("No shared entities found.")
        else:
            st.dataframe(scope["related_incidents"], use_container_width=True, hide_index=True)

    recommendation = recommend_escalation(case)
    st.markdown("### CSIRT coordination recommendation")
    st.markdown(f"**{recommendation['level']}** — {recommendation['rationale']}")
    if recommendation["indicators"]:
        st.write("Impact indicators: " + " · ".join(recommendation["indicators"]))
    st.write("Review checklist")
    for item in recommendation["review_checklist"]:
        st.markdown(f"- {item}")
    st.caption(recommendation["notice"])


def render_evidence() -> None:
    st.markdown('<div class="eyebrow">Evidence handling aid</div>', unsafe_allow_html=True)
    st.title("Evidence integrity")
    st.warning(
        "Training utility only. A matching digest confirms byte-for-byte equality with the expected hash; "
        "it does not establish evidence authenticity or chain of custody."
    )
    source = st.radio("Evidence source", ["Built-in synthetic sample", "Upload a file"], horizontal=True)
    content = None
    filename = None
    expected_hash = ""
    if source == "Built-in synthetic sample":
        try:
            content = EVIDENCE_PATH.read_bytes()
            filename = EVIDENCE_PATH.name
            expected_hash = (EVIDENCE_PATH.with_suffix(".sha256").read_text(encoding="utf-8").split()[0])
        except (OSError, IndexError) as exc:
            st.error(f"Could not load the built-in synthetic evidence sample or its checksum: {exc}")
            return
        st.caption("SYNTHETIC EDUCATIONAL EVIDENCE — not a real security log")
    else:
        uploaded = st.file_uploader("Choose evidence file", type=None, help="Files are hashed in memory and are not uploaded to an external service.")
        if uploaded is not None:
            content = uploaded.getvalue()
            filename = uploaded.name
        expected_hash = st.text_input("Expected SHA-256 (optional)", placeholder="64 hexadecimal characters")

    if content is None:
        st.info("Choose the synthetic sample or upload a file to calculate its SHA-256 digest.")
        return
    try:
        verification = verify_sha256(content, expected_hash)
    except (TypeError, ValueError) as exc:
        st.error(f"Evidence validation failed: {exc}")
        return

    st.markdown(f"**File:** `{filename}` · **Size:** {len(content):,} bytes")
    st.code(verification["sha256"], language=None)
    if verification["matches"] is True:
        st.success("Integrity check passed: calculated SHA-256 matches the expected digest.")
    elif verification["matches"] is False:
        st.error("Integrity check failed: calculated SHA-256 does not match the expected digest.")
    else:
        st.info("Digest calculated. Enter a trusted expected SHA-256 value to compare integrity.")


def render_reports(incidents: pd.DataFrame) -> None:
    st.markdown('<div class="eyebrow">Export center</div>', unsafe_allow_html=True)
    st.title("Investigation reports")
    if incidents.empty:
        st.info("No incidents are available to report under the current filters.")
        return
    incident_id = st.selectbox("Incident report", incidents["incident_id"].tolist(), key="report_incident")
    report = build_incident_report(incidents, incident_id)
    st.download_button(
        "Download investigation report · Markdown",
        data=report.encode("utf-8"),
        file_name=f"{incident_id.lower()}-investigation-report.md",
        mime="text/markdown",
        use_container_width=True,
    )
    report_incident = incidents.loc[incidents["incident_id"] == incident_id].iloc[0]
    recommendation = recommend_escalation(report_incident)
    st.markdown(f"**{recommendation['level']}**")
    st.write(recommendation["rationale"])
    st.caption(recommendation["notice"])
    with st.expander("Preview report", expanded=True):
        st.markdown(report)
    queue_csv = incidents.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download current filtered incident queue · CSV",
        data=queue_csv,
        file_name="synthetic-incident-queue.csv",
        mime="text/csv",
    )


def main() -> None:
    apply_styles()
    try:
        incidents = load_incidents()
    except (FileNotFoundError, ValueError) as exc:
        st.error(f"Unable to load incident data: {exc}")
        st.stop()

    with st.sidebar:
        st.markdown('<div class="brand"><span class="brand-mark">◢</span> IR / WORKBENCH</div>', unsafe_allow_html=True)
        st.markdown('<div class="muted">Enterprise incident response</div>', unsafe_allow_html=True)
        st.markdown("---")
        page = st.radio(
            "Workspace",
            ["Overview", "Incident queue", "Incident scoping", "Evidence integrity", "Reports"],
            label_visibility="collapsed",
        )
        st.markdown("---")
        st.markdown('<div class="eyebrow">Dataset</div>', unsafe_allow_html=True)
        st.caption(f"{len(incidents)} synthetic incidents · CSV")
        st.caption(f"Source: {DATA_PATH.name}")
        st.markdown("---")
        severity_filter = st.multiselect("Global severity filter", SEVERITIES, default=list(SEVERITIES))

    query, start_date, end_date, valid_range = render_header(incidents)
    if not valid_range:
        visible = incidents.iloc[0:0].copy()
    else:
        visible = triage_incidents(
            incidents,
            query=query,
            severities=severity_filter,
            start_date=start_date,
            end_date=end_date,
        )
    if page == "Overview":
        render_overview(visible)
    elif page == "Incident queue":
        render_queue(visible)
    elif page == "Incident scoping":
        render_scoping(visible)
    elif page == "Evidence integrity":
        render_evidence()
    else:
        render_reports(visible)


if __name__ == "__main__":
    main()
