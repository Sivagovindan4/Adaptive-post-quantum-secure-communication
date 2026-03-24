from __future__ import annotations

import math
from typing import Any

import pandas as pd
import streamlit as st

from visualization.bloch_composer import build_bloch_figure
from visualization.composer_sim import (
    bloch_from_rho,
    build_circuit_lane,
    build_probability_bars,
    format_amplitude,
    initial_state,
    probabilities,
    reduced_density_matrix,
    simulate,
    to_compact_ops,
)

st.set_page_config(page_title="Quantum Composer Lab", page_icon="Q", layout="wide")

st.markdown(
    """
    <style>
        /* Tighten Streamlit chrome to reduce scroll */
        .block-container { padding-top: 0.8rem; padding-bottom: 1rem; }
        header[data-testid="stHeader"] { background: rgba(0,0,0,0); }

    .qc-shell {
      border: 1px solid #1f2937;
      border-radius: 14px;
      background: linear-gradient(180deg, #0b1220 0%, #111827 100%);
      padding: 0.8rem 1rem;
      margin-bottom: 0.8rem;
    }
    .qc-title {
      color: #e5e7eb;
      font-size: 1.2rem;
      font-weight: 800;
      margin-bottom: 0.12rem;
    }
    .qc-sub {
      color: #93c5fd;
      font-size: 0.9rem;
      margin-bottom: 0.2rem;
    }
    .qc-chip {
      display:inline-block;
      padding:.2rem .55rem;
      border-radius:999px;
      margin-right:.35rem;
      background:#1f2937;
      color:#cbd5e1;
      border:1px solid #334155;
      font-size:.74rem;
      font-weight:700;
    }

    .qc-panel {
      border: 1px solid #1f2937;
      border-radius: 12px;
      background: #0b1220;
      padding: 0.75rem 0.75rem;
    }

    .qc-label {
      color: #94a3b8;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: .02em;
      text-transform: uppercase;
      margin-bottom: .35rem;
    }
    </style>
    <div class='qc-shell'>
      <div class='qc-title'>Quantum Composer Lab</div>
      <div class='qc-sub'>Composer-style circuit workspace: operations panel, alignment modes, timeline inspector, and probabilities.</div>
      <span class='qc-chip'>multi-qubit lane</span>
      <span class='qc-chip'>layer / left / freeform</span>
      <span class='qc-chip'>inspector + probabilities</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---- Session state ----
st.session_state.setdefault("composer_ops", [])
st.session_state.setdefault("composer_step", 0)
st.session_state.setdefault("composer_alignment", "layer")
st.session_state.setdefault("composer_n_qubits", 3)
st.session_state.setdefault("composer_init", "|0...0>")
st.session_state.setdefault("composer_target", 0)
st.session_state.setdefault("composer_control", 0)
st.session_state.setdefault("composer_target2", 1)
st.session_state.setdefault("composer_inspect_qubit", 0)
st.session_state.setdefault("composer_freeform_col", 1)


def _sanitize_ops(ops: list[dict[str, Any]], n_qubits: int) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for op in ops:
        gate = str(op.get("gate", ""))
        targets = [int(t) for t in (op.get("targets") or []) if str(t).isdigit()]
        controls = [int(c) for c in (op.get("controls") or []) if str(c).isdigit()]
        targets = [t for t in targets if 0 <= t < n_qubits]
        controls = [c for c in controls if 0 <= c < n_qubits]

        if gate in {"CX", "CZ"}:
            if len(controls) != 1 or len(targets) != 1 or controls[0] == targets[0]:
                continue
        if gate == "SWAP":
            if len(targets) != 2 or targets[0] == targets[1]:
                continue
        if gate in {"H", "X", "Y", "Z", "S", "T", "I", "Rx", "Ry", "Rz", "M"}:
            if gate not in {"SWAP"} and not targets:
                continue

        cleaned.append(
            {
                "gate": gate,
                "targets": targets,
                "controls": controls,
                "angle": op.get("angle"),
                "col": op.get("col"),
            }
        )
    return cleaned


def _add_op(gate: str, targets: list[int], controls: list[int] | None = None, angle: float | None = None) -> None:
    controls = controls or []
    op: dict[str, Any] = {"gate": gate, "targets": targets, "controls": controls}
    if angle is not None:
        op["angle"] = float(angle)
    if st.session_state.composer_alignment == "freeform":
        op["col"] = int(st.session_state.composer_freeform_col)
    st.session_state.composer_ops.append(op)
    st.session_state.composer_step = len(st.session_state.composer_ops)


# ---- Top bar (layout + alignment) ----
top_l, top_c, top_r = st.columns([0.9, 1.3, 0.9])
with top_l:
    n_qubits = st.select_slider("Qubits", options=[1, 2, 3, 4], value=int(st.session_state.composer_n_qubits))
    st.session_state.composer_n_qubits = int(n_qubits)
with top_c:
    align_label = st.selectbox(
        "Alignment",
        ["Layer alignment", "Left alignment", "Freeform"],
        index={"layer": 0, "left": 1, "freeform": 2}.get(str(st.session_state.composer_alignment), 0),
    )
    st.session_state.composer_alignment = {"Layer alignment": "layer", "Left alignment": "left", "Freeform": "freeform"}[align_label]
with top_r:
    init_choice = st.selectbox("Start state", ["|0...0>", "|+...+>"], index=0)
    st.session_state.composer_init = init_choice

st.session_state.composer_ops = _sanitize_ops(st.session_state.composer_ops, int(st.session_state.composer_n_qubits))

# ---- Main workspace: Operations | Lane | Inspector ----
ops_col, lane_col, insp_col = st.columns([0.85, 2.35, 1.05])

with ops_col:
    st.markdown("<div class='qc-panel'>", unsafe_allow_html=True)
    st.markdown("<div class='qc-label'>Operations</div>", unsafe_allow_html=True)

    q_opts = list(range(int(st.session_state.composer_n_qubits)))
    st.session_state.composer_target = st.selectbox("Target qubit", q_opts, index=min(int(st.session_state.composer_target), len(q_opts) - 1))
    st.session_state.composer_inspect_qubit = st.selectbox(
        "Inspect qubit",
        q_opts,
        index=min(int(st.session_state.composer_inspect_qubit), len(q_opts) - 1),
        help="Bloch + inspector are for this qubit (computed via partial trace).",
    )

    if st.session_state.composer_alignment == "freeform":
        st.session_state.composer_freeform_col = st.number_input("Column (freeform)", min_value=1, max_value=64, value=int(st.session_state.composer_freeform_col), step=1)

    st.markdown("<div class='qc-label'>Single-qubit</div>", unsafe_allow_html=True)
    r1 = st.columns(4)
    if r1[0].button("H", use_container_width=True):
        _add_op("H", [int(st.session_state.composer_target)])
    if r1[1].button("X", use_container_width=True):
        _add_op("X", [int(st.session_state.composer_target)])
    if r1[2].button("Y", use_container_width=True):
        _add_op("Y", [int(st.session_state.composer_target)])
    if r1[3].button("Z", use_container_width=True):
        _add_op("Z", [int(st.session_state.composer_target)])

    r2 = st.columns(4)
    if r2[0].button("S", use_container_width=True):
        _add_op("S", [int(st.session_state.composer_target)])
    if r2[1].button("T", use_container_width=True):
        _add_op("T", [int(st.session_state.composer_target)])
    if r2[2].button("I", use_container_width=True):
        _add_op("I", [int(st.session_state.composer_target)])
    if r2[3].button("M", use_container_width=True):
        _add_op("M", [int(st.session_state.composer_target)])

    st.markdown("<div class='qc-label'>Rotations</div>", unsafe_allow_html=True)
    deg = st.slider("Angle (deg)", min_value=0, max_value=360, value=90, step=5)
    ang = math.radians(float(deg))
    r3 = st.columns(3)
    if r3[0].button("Rx", use_container_width=True):
        _add_op("Rx", [int(st.session_state.composer_target)], angle=ang)
    if r3[1].button("Ry", use_container_width=True):
        _add_op("Ry", [int(st.session_state.composer_target)], angle=ang)
    if r3[2].button("Rz", use_container_width=True):
        _add_op("Rz", [int(st.session_state.composer_target)], angle=ang)

    st.markdown("<div class='qc-label'>Two-qubit</div>", unsafe_allow_html=True)
    cq, tq = st.columns(2)
    with cq:
        st.session_state.composer_control = st.selectbox("Control", q_opts, index=min(int(st.session_state.composer_control), len(q_opts) - 1))
    with tq:
        st.session_state.composer_target2 = st.selectbox("Target", q_opts, index=min(int(st.session_state.composer_target2), len(q_opts) - 1))

    r4 = st.columns(3)
    if r4[0].button("CX (•⊕)", use_container_width=True):
        _add_op("CX", [int(st.session_state.composer_target2)], controls=[int(st.session_state.composer_control)])
    if r4[1].button("CZ (•Z)", use_container_width=True):
        _add_op("CZ", [int(st.session_state.composer_target2)], controls=[int(st.session_state.composer_control)])
    if r4[2].button("SWAP (××)", use_container_width=True):
        _add_op("SWAP", [int(st.session_state.composer_control), int(st.session_state.composer_target2)])

    cta1, cta2, cta3 = st.columns(3)
    if cta1.button("Undo", use_container_width=True):
        if st.session_state.composer_ops:
            st.session_state.composer_ops.pop()
            st.session_state.composer_step = min(int(st.session_state.composer_step), len(st.session_state.composer_ops))
    if cta2.button("Clear", use_container_width=True):
        st.session_state.composer_ops = []
        st.session_state.composer_step = 0
    if cta3.button("Reset |0...0>", use_container_width=True):
        st.session_state.composer_ops = []
        st.session_state.composer_step = 0
        st.session_state.composer_init = "|0...0>"

    st.markdown("</div>", unsafe_allow_html=True)

with lane_col:
    n_qubits_int = int(st.session_state.composer_n_qubits)
    init = initial_state(n_qubits_int, str(st.session_state.composer_init))
    history = simulate(n_qubits_int, list(st.session_state.composer_ops), init=init)
    max_step = max(0, len(history) - 1)
    if max_step > 0:
        st.session_state.composer_step = st.slider(
            "Timeline step",
            min_value=0,
            max_value=max_step,
            value=min(int(st.session_state.composer_step), max_step),
            help="One timeline drives lane highlight + inspector + probabilities.",
        )
    else:
        st.session_state.composer_step = 0
        st.caption("Timeline step: 0 (add operations to enable timeline scrubber)")

    step_idx = int(st.session_state.composer_step)
    highlight = step_idx if step_idx > 0 else None
    lane_fig = build_circuit_lane(
        list(st.session_state.composer_ops),
        n_qubits=n_qubits_int,
        mode=str(st.session_state.composer_alignment),
        highlight_step=highlight,
    )
    st.plotly_chart(lane_fig, width="stretch")

    with st.expander("Edit operations (freeform columns + quick delete)", expanded=False):
        if st.session_state.composer_ops:
            rows = []
            for i, op in enumerate(st.session_state.composer_ops, start=1):
                rows.append(
                    {
                        "step": i,
                        "gate": op.get("gate"),
                        "targets": ",".join(str(t) for t in (op.get("targets") or [])),
                        "controls": ",".join(str(c) for c in (op.get("controls") or [])),
                        "angle": op.get("angle"),
                        "col": op.get("col"),
                    }
                )
            df = pd.DataFrame(rows)
            edited = st.data_editor(
                df,
                hide_index=True,
                column_config={
                    "step": st.column_config.NumberColumn("step", disabled=True),
                    "gate": st.column_config.TextColumn("gate", disabled=True),
                    "targets": st.column_config.TextColumn("targets", disabled=True),
                    "controls": st.column_config.TextColumn("controls", disabled=True),
                    "angle": st.column_config.NumberColumn("angle", format="%.4f"),
                    "col": st.column_config.NumberColumn("col", help="Used only in Freeform alignment"),
                },
                use_container_width=True,
            )
            # Apply column/angle edits back
            new_ops = []
            for i, op in enumerate(st.session_state.composer_ops):
                row = edited.iloc[i].to_dict()
                new_op = dict(op)
                new_op["col"] = row.get("col")
                new_op["angle"] = row.get("angle")
                new_ops.append(new_op)
            st.session_state.composer_ops = _sanitize_ops(new_ops, n_qubits_int)

            d1, d2 = st.columns([1.0, 1.0])
            with d1:
                del_idx = st.number_input("Delete step", min_value=1, max_value=len(st.session_state.composer_ops), value=len(st.session_state.composer_ops), step=1)
            with d2:
                if st.button("Delete", type="secondary", use_container_width=True):
                    i = int(del_idx) - 1
                    if 0 <= i < len(st.session_state.composer_ops):
                        st.session_state.composer_ops.pop(i)
                        st.session_state.composer_step = min(int(st.session_state.composer_step), len(st.session_state.composer_ops))
        else:
            st.caption("No operations to edit yet.")

with insp_col:
    st.markdown("<div class='qc-panel'>", unsafe_allow_html=True)
    st.markdown("<div class='qc-label'>Inspector</div>", unsafe_allow_html=True)
    state = history[step_idx]
    p = probabilities(state)
    labels = [format(i, f"0{n_qubits_int}b") for i in range(2**n_qubits_int)]

    basis_pick = st.selectbox("Basis state", labels, index=0)
    basis_i = int(basis_pick, 2)
    amp = complex(state[basis_i])
    st.metric("P(state)", f"{float(p[basis_i]):.4f}")
    st.code(
        "\n".join(
            [
                f"Amplitude |{basis_pick}>: {format_amplitude(amp)}",
                f"Ops: {len(st.session_state.composer_ops)} | Step: {step_idx}/{max_step}",
                f"Alignment: {st.session_state.composer_alignment}",
            ]
        ),
        language="text",
    )

    iq = int(st.session_state.composer_inspect_qubit)
    rho = reduced_density_matrix(state, n_qubits_int, iq)
    bloch = bloch_from_rho(rho)
    mx, my, mz = st.columns(3)
    mx.metric("X", f"{bloch[0]:+.3f}")
    my.metric("Y", f"{bloch[1]:+.3f}")
    mz.metric("Z", f"{bloch[2]:+.3f}")

    st.markdown("<div class='qc-label'>Circuit summary</div>", unsafe_allow_html=True)
    st.code(to_compact_ops(st.session_state.composer_ops), language="text")
    st.markdown("</div>", unsafe_allow_html=True)


# ---- Bottom row: Probabilities + Bloch ----
prob_col, bloch_col = st.columns([1.25, 1.0])
with prob_col:
    st.plotly_chart(build_probability_bars(p, n_qubits_int), width="stretch")

with bloch_col:
    # compute history for inspected qubit up to the current step
    bloch_hist = [
        bloch_from_rho(reduced_density_matrix(s, n_qubits_int, int(st.session_state.composer_inspect_qubit))) for s in history[: step_idx + 1]
    ]
    fig = build_bloch_figure(
        bloch_hist[-1],
        title=f"Bloch (q[{int(st.session_state.composer_inspect_qubit)}]) at step {step_idx}",
        history=bloch_hist,
        measurement_basis="Z",
    )
    st.plotly_chart(fig, width="stretch")


with st.expander("BB84 mapping (why this page exists)", expanded=False):
    st.markdown(
        """
- BB84 uses $Z$/$X$ basis choices to prepare and measure qubits; basis mismatch creates probabilistic outcomes.
- The bar chart here is your computational-basis probability distribution $|\psi|^2$ at a timeline step.
- The Bloch inspector shows a *single qubit* view (partial trace) even when the circuit has multiple qubits.
        """
    )
