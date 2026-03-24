from __future__ import annotations

import statistics

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from benchmark_runner import run_benchmark
from config import HIGH_THRESHOLD, LOW_THRESHOLD, QBER_THRESHOLD

st.set_page_config(page_title="Benchmark Lab", page_icon="Q", layout="wide")

st.markdown(
    """
    <style>
    .bench-shell {
      border: 1px solid #1f2937;
      border-radius: 14px;
      background: linear-gradient(180deg, #0b1220 0%, #111827 100%);
      padding: 0.8rem 1rem;
      margin-bottom: 0.8rem;
    }
    .bench-title {
      color: #e5e7eb;
      font-size: 1.2rem;
      font-weight: 800;
      margin-bottom: 0.15rem;
    }
    .bench-sub {
      color: #bfdbfe;
      font-size: 0.9rem;
    }
    </style>
    <div class='bench-shell'>
      <div class='bench-title'>Benchmark Lab</div>
      <div class='bench-sub'>Single professional benchmark workflow. No Research/Benchmark toggle noise.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.session_state.setdefault("lab_bench", None)

ctrl1, ctrl2 = st.columns([1.0, 1.0])
with ctrl1:
    sessions = st.number_input("Benchmark sessions", min_value=5, max_value=100, value=24, step=1)
with ctrl2:
    warmup = st.checkbox("Warmup preview run (5 sessions)", value=True)

if st.button("Run professional benchmark", type="primary"):
    with st.spinner("Running benchmark suite..."):
        if warmup:
            run_benchmark(num_sessions=5)
        st.session_state.lab_bench = run_benchmark(num_sessions=int(sessions))

bench = st.session_state.lab_bench
if bench:
    modes_used = bench.get("modes_used", {})
    modes_list = bench.get("modes_list", [])
    threat_scores = bench.get("threat_scores", [])
    latencies = bench.get("latencies", [])
    sec_scores = bench.get("security_scores", [])
    qbers = [q for q in bench.get("qkd_qbers", []) if isinstance(q, (int, float))]
    pqc_times = bench.get("pqc_times", [])
    qkd_times = bench.get("qkd_times", [])

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Sessions", len(latencies))
    k2.metric("Mean latency", f"{statistics.mean(latencies):.4f}s" if latencies else "N/A")
    k3.metric("Mean security", f"{statistics.mean(sec_scores):.1f}" if sec_scores else "N/A")
    k4.metric("Mean QBER", f"{statistics.mean(qbers):.4f}" if qbers else "N/A")

    tab1, tab2, tab3 = st.tabs(["Performance", "Threat and Integrity", "Mode Distribution"])

    with tab1:
        p1, p2 = st.columns(2)
        with p1:
            box = px.box(
                pd.DataFrame({"mode": modes_list, "latency": latencies}),
                x="mode",
                y="latency",
                color="mode",
                points="all",
                title="Latency by mode",
            )
            st.plotly_chart(box, width="stretch")
        with p2:
            scat = px.scatter(
                pd.DataFrame({"latency": latencies, "security": sec_scores, "mode": modes_list}),
                x="latency",
                y="security",
                color="mode",
                title="Security vs latency",
            )
            st.plotly_chart(scat, width="stretch")

        t = go.Figure(data=[
            go.Bar(name="PQC", x=list(range(1, len(pqc_times) + 1)), y=pqc_times, marker_color="#0ea5e9"),
            go.Bar(name="QKD", x=list(range(1, len(qkd_times) + 1)), y=qkd_times, marker_color="#a855f7"),
        ])
        t.update_layout(barmode="group", title="Per-session crypto timings", xaxis_title="session", yaxis_title="seconds")
        st.plotly_chart(t, width="stretch")

    with tab2:
        t1, t2 = st.columns(2)
        with t1:
            h = px.histogram(x=threat_scores, nbins=16, title="Threat score distribution")
            h.add_vline(x=LOW_THRESHOLD, line_dash="dash", line_color="#22c55e")
            h.add_vline(x=HIGH_THRESHOLD, line_dash="dash", line_color="#ef4444")
            st.plotly_chart(h, width="stretch")
        with t2:
            qh = px.histogram(x=qbers, nbins=14, title="QBER distribution")
            qh.add_vline(x=QBER_THRESHOLD, line_dash="dash", line_color="#ef4444")
            st.plotly_chart(qh, width="stretch")

    with tab3:
        d1, d2 = st.columns(2)
        with d1:
            pie = px.pie(names=list(modes_used.keys()), values=list(modes_used.values()), hole=0.4, title="Mode share")
            st.plotly_chart(pie, width="stretch")
        with d2:
            df = pd.DataFrame({"mode": list(modes_used.keys()), "count": list(modes_used.values())})
            bars = px.bar(df, x="mode", y="count", color="mode", title="Mode counts")
            st.plotly_chart(bars, width="stretch")

    st.success("Benchmark complete. Use this page as the single analytics source for evaluation demos.")
else:
    st.info("Run the benchmark to populate professional analytics panels.")
