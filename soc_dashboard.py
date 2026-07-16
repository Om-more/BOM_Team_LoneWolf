import time
from pathlib import Path

import pandas as pd
import streamlit as st

from agent_llm import analyze_threat
from correlation_engine import (
    ThreatCorrelationEngine,
    load_models,
    load_stream,
    score_models,
)


BASE_DIR = Path(__file__).resolve().parent
STREAM_PATH = BASE_DIR / "sample_stream_full_1000.json"


def initialize_state():
    defaults = {
        "running": False,
        "cursor": 0,
        "history": [],
        "agent_feed": [],
        "blocked_ips": set(),
        "frozen_accounts": set(),
        "last_alert_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


@st.cache_resource(show_spinner="Loading ML models...")
def cached_models():
    return load_models()


@st.cache_data(show_spinner="Loading simulated stream...")
def cached_stream():
    return load_stream(STREAM_PATH)


def apply_firewall_action(agent_json):
    action = agent_json.get("action")
    target = agent_json.get("target_value")

    if not target:
        return
    if action == "BLOCK_IP":
        st.session_state.blocked_ips.add(target)
    elif action == "FREEZE_ACCOUNT":
        st.session_state.frozen_accounts.add(target)


def process_next_event(event, models, engine):
    transaction_id = event.get("TransactionID")
    user_id = event.get("user") or event.get("user_id")
    src_ip = event.get("src_ip")

    if src_ip in st.session_state.blocked_ips:
        return {
            "TransactionID": transaction_id,
            "user": user_id,
            "src_ip": src_ip,
            "scenario": event.get("scenario"),
            "fraud_score": None,
            "cyber_score": None,
            "quantum_score": None,
            "Threat_Tier": 0,
            "Context_Tag": "BLOCKED_BY_FIREWALL",
            "Status": "BLOCKED_IP",
        }, None

    if user_id in st.session_state.frozen_accounts:
        return {
            "TransactionID": transaction_id,
            "user": user_id,
            "src_ip": src_ip,
            "scenario": event.get("scenario"),
            "fraud_score": None,
            "cyber_score": None,
            "quantum_score": None,
            "Threat_Tier": 0,
            "Context_Tag": "BLOCKED_BY_FIREWALL",
            "Status": "FROZEN_ACCOUNT",
        }, None

    scores = score_models(event, models)
    tier, tag = engine.correlate(
        scores["fraud_score"],
        scores["cyber_score"],
        scores["quantum_score"],
    )

    row = {
        "TransactionID": transaction_id,
        "user": user_id,
        "src_ip": src_ip,
        "scenario": event.get("scenario"),
        **scores,
        "Threat_Tier": tier,
        "Context_Tag": tag,
        "Status": "ALLOWED",
    }

    agent_json = None
    if tier >= 3:
        payload = {
            "TransactionID": transaction_id,
            **scores,
            "Threat_Tier": tier,
            "Context_Tag": tag,
        }
        agent_json = analyze_threat(payload, event)
        apply_firewall_action(agent_json)
        st.session_state.last_alert_id = transaction_id

    return row, agent_json


def style_transactions(df):
    def row_style(row):
        if row["Context_Tag"] == "BLOCKED_BY_FIREWALL":
            return ["background-color: #eceff1; color: #455a64"] * len(row)
        if int(row["Threat_Tier"] or 0) >= 3:
            return ["background-color: #ffebee; color: #7f0000"] * len(row)
        if int(row["Threat_Tier"] or 0) == 2:
            return ["background-color: #fff8e1; color: #5d4037"] * len(row)
        return [""] * len(row)

    return df.style.apply(row_style, axis=1)


def render_agent_card(alert, newest=False):
    flash_class = "flash-alert" if newest else ""
    st.markdown(
        f"""
        <div class="agent-card {flash_class}">
            <div class="agent-title">{alert['action']} -> {alert['target_value']}</div>
            <div class="agent-meta">Transaction {alert['TransactionID']} | Tier {alert['Threat_Tier']} | {alert['Context_Tag']}</div>
            <div><b>MITRE:</b> {alert['tactics']}</div>
            <div><b>Summary:</b> {alert['explanation']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_firewall_status():
    st.subheader("Status")
    st.metric("Blocked IPs", len(st.session_state.blocked_ips))
    st.metric("Frozen Accounts", len(st.session_state.frozen_accounts))

    st.caption("Blocked IPs")
    if st.session_state.blocked_ips:
        st.dataframe(
            pd.DataFrame({"src_ip": sorted(st.session_state.blocked_ips)}),
            use_container_width=True,
            hide_index=True,
            height=180,
        )
    else:
        st.info("No IPs blocked.")

    st.caption("Frozen Accounts")
    if st.session_state.frozen_accounts:
        st.dataframe(
            pd.DataFrame({"user": sorted(st.session_state.frozen_accounts)}),
            use_container_width=True,
            hide_index=True,
            height=180,
        )
    else:
        st.info("No accounts frozen.")


def render_dashboard():
    st.set_page_config(
        page_title="Real-Time AI SOC Dashboard",
        page_icon="",
        layout="wide",
    )
    initialize_state()

    st.markdown(
        """
        <style>
        .block-container {padding-top: 2.5rem; padding-bottom: 1rem;}
        .soc-title {font-size: 1.8rem; font-weight: 750; line-height: 1.25; margin-bottom: .15rem;}
        .soc-subtitle {color: #5f6368; margin-bottom: .9rem;}
        .agent-card {border-left: 6px solid #c62828; border-radius: 8px; padding: .75rem .85rem; margin-bottom: .7rem;}
        .agent-title {font-weight: 750;}
        .agent-meta {font-size: .84rem; color: #5f6368; margin: .15rem 0 .35rem;}
        @keyframes redFlash {
            0% {box-shadow: 0 0 0 rgba(198,40,40,0);}
            50% {box-shadow: 0 0 22px rgba(198,40,40,.5);}
            100% {box-shadow: 0 0 0 rgba(198,40,40,0);}
        }
        .flash-alert {animation: redFlash 1s ease-in-out 2;}
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<div class="soc-title">QTT-Shield SOC Dashboard</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="soc-subtitle">Live stream scoring, agentic response, and simulated firewall enforcement.</div>',
        unsafe_allow_html=True,
    )

    models = cached_models()
    events = cached_stream()
    engine = ThreatCorrelationEngine()

    delay = 0.25
    max_events = len(events)

    controls = st.columns([1, 1, 1])
    with controls[0]:
        if st.button("Start", use_container_width=True):
            st.session_state.running = True
    with controls[1]:
        if st.button("Pause", use_container_width=True):
            st.session_state.running = False
    with controls[2]:
        if st.button("Reset", use_container_width=True):
            st.session_state.running = False
            st.session_state.cursor = 0
            st.session_state.history = []
            st.session_state.agent_feed = []
            st.session_state.blocked_ips = set()
            st.session_state.frozen_accounts = set()
            st.session_state.last_alert_id = None

    if st.session_state.running and st.session_state.cursor < max_events:
        event = events[st.session_state.cursor]
        try:
            row, agent_json = process_next_event(event, models, engine)
            st.session_state.history.append(row)
            if agent_json:
                st.session_state.agent_feed.insert(
                    0,
                    {
                        "TransactionID": row["TransactionID"],
                        "Threat_Tier": row["Threat_Tier"],
                        "Context_Tag": row["Context_Tag"],
                        **agent_json,
                    },
                )
        except Exception as exc:
            st.session_state.history.append(
                {
                    "TransactionID": event.get("TransactionID"),
                    "user": event.get("user"),
                    "src_ip": event.get("src_ip"),
                    "scenario": event.get("scenario"),
                    "fraud_score": None,
                    "cyber_score": None,
                    "quantum_score": None,
                    "Threat_Tier": 0,
                    "Context_Tag": f"SCORING_ERROR: {exc}",
                    "Status": "ERROR",
                }
            )
        st.session_state.cursor += 1
    elif st.session_state.cursor >= max_events:
        st.session_state.running = False

    history = pd.DataFrame(st.session_state.history)
    metric_cols = st.columns(4)
    metric_cols[0].metric("Processed", len(st.session_state.history))
    metric_cols[1].metric("Alerts", len(st.session_state.agent_feed))

    tx_col, alert_col, firewall_col = st.columns([1.55, 1, 0.8], gap="large")

    with tx_col:
        st.subheader("Live Transactions")
        table_cols = [
            "TransactionID",
            "user",
            "src_ip",
            "scenario",
            "fraud_score",
            "cyber_score",
            "quantum_score",
            "Threat_Tier",
            "Context_Tag",
            "Status",
        ]
        if history.empty:
            st.info("Press Start to begin live replay.")
        else:
            view = history.reindex(columns=table_cols).tail(35).iloc[::-1]
            st.dataframe(
                style_transactions(view),
                use_container_width=True,
                height=620,
                hide_index=True,
            )

    with alert_col:
        st.subheader("Agent Alert Feed")
        if not st.session_state.agent_feed:
            st.info("Tier 3 and Tier 4 events will appear here.")
        for alert in st.session_state.agent_feed[:12]:
            render_agent_card(
                alert,
                newest=alert["TransactionID"] == st.session_state.last_alert_id,
            )

    with firewall_col:
        render_firewall_status()

    if st.session_state.running:
        time.sleep(delay)
        st.rerun()


if __name__ == "__main__":
    render_dashboard()
