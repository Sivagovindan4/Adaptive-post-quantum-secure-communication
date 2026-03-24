"""Minimal multi-qubit circuit simulator + IBM-composer-like lane rendering.

This is intentionally small and self-contained:
- Supports up to ~4 qubits comfortably (statevector size 16).
- Gates: I, H, X, Y, Z, S, T, Rx, Ry, Rz, CX, CZ, SWAP, M (marker).
- Alignment modes for the lane: left (sequential), layer (packed), freeform (user columns).

The goal is a clear educational UI, not a full drag-and-drop composer.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Literal

import numpy as np
import plotly.graph_objects as go

AlignmentMode = Literal["left", "layer", "freeform"]


def gate_symbol(name: str) -> str:
    symbols = {
        "I": "I",
        "H": "H",
        "X": "X",
        "Y": "Y",
        "Z": "Z",
        "S": "S",
        "T": "T",
        "Rx": "Rx",
        "Ry": "Ry",
        "Rz": "Rz",
        "CX": "CX",
        "CZ": "CZ",
        "SWAP": "SWAP",
        "M": "M",
    }
    return symbols.get(name, name)


def basis_labels(n_qubits: int) -> list[str]:
    return [format(i, f"0{n_qubits}b") for i in range(2**n_qubits)]


def ket_index(label_bits: str) -> int:
    return int(label_bits, 2)


def initial_state(n_qubits: int, preset: str = "|0...0>") -> np.ndarray:
    dim = 2**n_qubits
    psi = np.zeros((dim,), dtype=np.complex128)

    if preset == "|0...0>":
        psi[0] = 1.0 + 0j
        return psi

    if preset == "|+...+>":
        amp = 1.0 / math.sqrt(dim)
        psi[:] = amp + 0j
        return psi

    if preset.startswith("|") and preset.endswith(">") and len(preset) == n_qubits + 2:
        # Accept |0101> style
        bits = preset[1:-1]
        idx = ket_index(bits)
        psi[idx] = 1.0 + 0j
        return psi

    # Fallback
    psi[0] = 1.0 + 0j
    return psi


def _u_single(gate: str, angle: float | None = None) -> np.ndarray:
    g = gate
    if g == "I":
        return np.eye(2, dtype=np.complex128)
    if g == "H":
        inv = 1.0 / math.sqrt(2)
        return inv * np.array([[1, 1], [1, -1]], dtype=np.complex128)
    if g == "X":
        return np.array([[0, 1], [1, 0]], dtype=np.complex128)
    if g == "Y":
        return np.array([[0, -1j], [1j, 0]], dtype=np.complex128)
    if g == "Z":
        return np.array([[1, 0], [0, -1]], dtype=np.complex128)
    if g == "S":
        return np.array([[1, 0], [0, 1j]], dtype=np.complex128)
    if g == "T":
        return np.array([[1, 0], [0, np.exp(1j * math.pi / 4)]], dtype=np.complex128)

    t = float(angle or 0.0)
    if g == "Rx":
        c = math.cos(t / 2)
        s = math.sin(t / 2)
        return np.array([[c, -1j * s], [-1j * s, c]], dtype=np.complex128)
    if g == "Ry":
        c = math.cos(t / 2)
        s = math.sin(t / 2)
        return np.array([[c, -s], [s, c]], dtype=np.complex128)
    if g == "Rz":
        return np.array([[np.exp(-1j * t / 2), 0], [0, np.exp(1j * t / 2)]], dtype=np.complex128)

    return np.eye(2, dtype=np.complex128)


def apply_single_qubit_gate(state: np.ndarray, n_qubits: int, qubit: int, gate: str, angle: float | None = None) -> np.ndarray:
    """Apply a 2x2 unitary to `qubit` (0 is top wire q[0])."""
    u = _u_single(gate, angle)
    psi = state.reshape((2,) * n_qubits)

    # Axis index: q[0] is axis 0, q[1] axis 1, ...
    # tensordot over the target axis.
    psi2 = np.tensordot(u, psi, axes=([1], [qubit]))

    # tensordot moves the output qubit axis to the front; restore original axis order
    # Result axes are: [new_qubit_axis] + [old axes excluding `qubit` in ascending order]
    perm = list(range(1, n_qubits))
    perm.insert(qubit, 0)
    psi2 = np.transpose(psi2, perm)

    return psi2.reshape((-1,))


def apply_cx(state: np.ndarray, n_qubits: int, control: int, target: int) -> np.ndarray:
    """Apply controlled-X using bit swaps (fast, no large matrices)."""
    psi = state.copy()
    dim = psi.shape[0]

    control_mask = 1 << (n_qubits - 1 - control)
    target_mask = 1 << (n_qubits - 1 - target)

    for i in range(dim):
        if (i & control_mask) and not (i & target_mask):
            j = i | target_mask
            psi[i], psi[j] = psi[j], psi[i]

    return psi


def apply_cz(state: np.ndarray, n_qubits: int, control: int, target: int) -> np.ndarray:
    psi = state.copy()
    dim = psi.shape[0]

    control_mask = 1 << (n_qubits - 1 - control)
    target_mask = 1 << (n_qubits - 1 - target)

    for i in range(dim):
        if (i & control_mask) and (i & target_mask):
            psi[i] = -psi[i]

    return psi


def apply_swap(state: np.ndarray, n_qubits: int, q1: int, q2: int) -> np.ndarray:
    if q1 == q2:
        return state

    psi = state.copy()
    dim = psi.shape[0]

    m1 = 1 << (n_qubits - 1 - q1)
    m2 = 1 << (n_qubits - 1 - q2)

    for i in range(dim):
        b1 = 1 if (i & m1) else 0
        b2 = 1 if (i & m2) else 0
        if b1 != b2:
            j = i ^ (m1 | m2)
            if i < j:
                psi[i], psi[j] = psi[j], psi[i]

    return psi


def simulate(
    n_qubits: int,
    ops: list[dict[str, Any]],
    init: np.ndarray | None = None,
) -> list[np.ndarray]:
    """Return a state history, including step 0 = initial state."""
    if init is None:
        init = initial_state(n_qubits, "|0...0>")

    history = [init]
    state = init

    for op in ops:
        g = str(op.get("gate", ""))
        targets = list(op.get("targets", []))
        controls = list(op.get("controls", []))
        angle = op.get("angle")

        if g in {"M", "MEASURE"}:
            history.append(state)
            continue

        if g in {"CX", "CNOT"}:
            if controls and targets:
                state = apply_cx(state, n_qubits, int(controls[0]), int(targets[0]))
            history.append(state)
            continue

        if g == "CZ":
            if controls and targets:
                state = apply_cz(state, n_qubits, int(controls[0]), int(targets[0]))
            history.append(state)
            continue

        if g == "SWAP":
            if len(targets) >= 2:
                state = apply_swap(state, n_qubits, int(targets[0]), int(targets[1]))
            history.append(state)
            continue

        # Single-qubit
        if targets:
            state = apply_single_qubit_gate(state, n_qubits, int(targets[0]), g, float(angle) if angle is not None else None)

        history.append(state)

    return history


def probabilities(state: np.ndarray) -> np.ndarray:
    p = np.abs(state) ** 2
    s = float(p.sum())
    if s > 0:
        p = p / s
    return p


def reduced_density_matrix(state: np.ndarray, n_qubits: int, qubit: int) -> np.ndarray:
    """Return 2x2 reduced density matrix for `qubit` by partial trace."""
    psi = state.reshape((2,) * n_qubits)
    psi = np.moveaxis(psi, qubit, 0)
    psi = psi.reshape((2, -1))
    rho = psi @ np.conjugate(psi).T
    return rho


def bloch_from_rho(rho: np.ndarray) -> list[float]:
    sx = np.array([[0, 1], [1, 0]], dtype=np.complex128)
    sy = np.array([[0, -1j], [1j, 0]], dtype=np.complex128)
    sz = np.array([[1, 0], [0, -1]], dtype=np.complex128)

    x = float(np.real(np.trace(rho @ sx)))
    y = float(np.real(np.trace(rho @ sy)))
    z = float(np.real(np.trace(rho @ sz)))
    return [x, y, z]


def format_amplitude(z: complex) -> str:
    return f"{z.real:+.4f}{z.imag:+.4f}i"


def _op_qubits(op: dict[str, Any]) -> set[int]:
    qs: set[int] = set(int(q) for q in op.get("targets", []) if isinstance(q, (int, float, str)))
    qs |= set(int(q) for q in op.get("controls", []) if isinstance(q, (int, float, str)))
    return qs


def assign_columns(ops: list[dict[str, Any]], n_qubits: int, mode: AlignmentMode) -> list[int]:
    if mode == "left":
        return list(range(1, len(ops) + 1))

    if mode == "freeform":
        cols: list[int] = []
        max_col = 0
        for op in ops:
            c = op.get("col")
            try:
                v = int(c) if c is not None else None
            except Exception:
                v = None
            if v is None or v < 1:
                v = max_col + 1
            max_col = max(max_col, v)
            cols.append(v)
        return cols

    # layer: packed scheduling
    next_free = [1] * n_qubits
    cols = []
    for op in ops:
        qs = sorted(q for q in _op_qubits(op) if 0 <= q < n_qubits)
        if not qs:
            cols.append(1)
            continue
        c = max(next_free[q] for q in qs)
        cols.append(c)
        for q in qs:
            next_free[q] = c + 1
    return cols


def build_circuit_lane(
    ops: list[dict[str, Any]],
    n_qubits: int,
    mode: AlignmentMode = "layer",
    highlight_step: int | None = None,
) -> go.Figure:
    """Plotly figure resembling a composer lane, for multiple qubits."""

    cols = assign_columns(ops, n_qubits, mode)
    depth = max(cols, default=1)

    fig = go.Figure()

    # wires
    for q in range(n_qubits):
        y = -q
        fig.add_shape(
            type="line",
            x0=0.5,
            y0=y,
            x1=depth + 0.5,
            y1=y,
            line=dict(color="#334155", width=4),
        )
        fig.add_annotation(
            x=0.15,
            y=y,
            text=f"q[{q}]",
            showarrow=False,
            xref="x",
            yref="y",
            font=dict(color="#94a3b8", size=12),
        )

    gate_fill = {
        "H": "#2563eb",
        "X": "#ef4444",
        "Y": "#0ea5e9",
        "Z": "#10b981",
        "S": "#06b6d4",
        "T": "#22c55e",
        "Rx": "#f59e0b",
        "Ry": "#fb7185",
        "Rz": "#8b5cf6",
        "CX": "#eab308",
        "CZ": "#eab308",
        "SWAP": "#a3a3a3",
        "M": "#64748b",
    }

    for idx, (op, col) in enumerate(zip(ops, cols), start=1):
        g = str(op.get("gate", "?"))
        targets = [int(x) for x in op.get("targets", [])] if op.get("targets") else []
        controls = [int(x) for x in op.get("controls", [])] if op.get("controls") else []
        color = gate_fill.get(g, "#64748b")
        active = (highlight_step is not None and idx == highlight_step)
        outline = "#e5e7eb" if active else "#0f172a"
        outline_w = 3 if active else 1

        if g in {"CX", "CZ"} and controls and targets:
            c_q = controls[0]
            t_q = targets[0]
            y0 = -c_q
            y1 = -t_q
            fig.add_shape(type="line", x0=col, y0=y0, x1=col, y1=y1, line=dict(color="#94a3b8", width=3))
            fig.add_trace(
                go.Scatter(
                    x=[col],
                    y=[y0],
                    mode="markers",
                    marker=dict(size=14, color="#0f172a", line=dict(color="#e5e7eb", width=2)),
                    hovertemplate=f"Step {idx}: control q[{c_q}]<extra></extra>",
                    showlegend=False,
                )
            )
            if g == "CX":
                fig.add_trace(
                    go.Scatter(
                        x=[col],
                        y=[y1],
                        mode="markers",
                        marker=dict(symbol="circle", size=18, color="#0f172a", line=dict(color="#e5e7eb", width=2)),
                        hovertemplate=f"Step {idx}: target q[{t_q}]<extra></extra>",
                        showlegend=False,
                    )
                )
                # plus sign
                fig.add_annotation(x=col, y=y1, text="⊕", showarrow=False, font=dict(color="#e5e7eb", size=16, family="monospace"))
            else:
                fig.add_trace(
                    go.Scatter(
                        x=[col],
                        y=[y1],
                        mode="markers+text",
                        marker=dict(symbol="square", size=26, color=color, line=dict(color=outline, width=outline_w)),
                        text=["Z"],
                        textfont=dict(color="white", size=14),
                        hovertemplate=f"Step {idx}: CZ q[{c_q}]→q[{t_q}]<extra></extra>",
                        showlegend=False,
                    )
                )
            continue

        if g == "SWAP" and len(targets) >= 2:
            q1, q2 = targets[0], targets[1]
            y1, y2 = -q1, -q2
            fig.add_shape(type="line", x0=col, y0=y1, x1=col, y1=y2, line=dict(color="#94a3b8", width=3))
            for y in (y1, y2):
                fig.add_annotation(x=col, y=y, text="×", showarrow=False, font=dict(color="#e5e7eb", size=18, family="monospace"))
            continue

        if g in {"M", "MEASURE"} and targets:
            q = targets[0]
            y = -q
            fig.add_trace(
                go.Scatter(
                    x=[col],
                    y=[y],
                    mode="markers+text",
                    marker=dict(symbol="square", size=26, color=gate_fill.get("M"), line=dict(color=outline, width=outline_w)),
                    text=["M"],
                    textfont=dict(color="white", size=14),
                    hovertemplate=f"Step {idx}: Measure q[{q}]<extra></extra>",
                    showlegend=False,
                )
            )
            continue

        if targets:
            q = targets[0]
            y = -q
            label = gate_symbol(g)
            ang = op.get("angle")
            angle_text = ""
            if isinstance(ang, (int, float)) and g in {"Rx", "Ry", "Rz"}:
                angle_text = f" ({float(ang):.2f} rad)"
            fig.add_trace(
                go.Scatter(
                    x=[col],
                    y=[y],
                    mode="markers+text",
                    marker=dict(symbol="square", size=28, color=color, line=dict(color=outline, width=outline_w)),
                    text=[label],
                    textfont=dict(color="white", size=13),
                    hovertemplate=f"Step {idx}: {g} q[{q}]{angle_text}<extra></extra>",
                    showlegend=False,
                )
            )

    fig.update_layout(
        height=max(240, 80 + 55 * n_qubits),
        margin=dict(l=10, r=10, t=28, b=10),
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(range=[0.0, depth + 0.8], visible=False),
        yaxis=dict(range=[-(n_qubits - 1) - 0.9, 0.9], visible=False),
    )
    fig.add_annotation(
        x=0.5,
        y=1.04,
        xref="paper",
        yref="paper",
        text=f"Composer lane ({mode} alignment)",
        showarrow=False,
        font=dict(size=14, color="#94a3b8"),
    )

    return fig


def build_probability_bars(p: np.ndarray, n_qubits: int) -> go.Figure:
    labels = basis_labels(n_qubits)
    y = p.tolist()

    fig = go.Figure(data=[go.Bar(x=labels, y=y, marker_color="#60a5fa")])
    fig.update_layout(
        height=310,
        margin=dict(l=10, r=10, t=34, b=70),
        title="Measurement probabilities (computational basis)",
        yaxis=dict(range=[0, max(0.001, float(max(y))) * 1.15], title="Probability"),
        xaxis=dict(tickangle=-60, title="Basis state"),
        showlegend=False,
    )
    return fig


def to_compact_ops(ops: Iterable[dict[str, Any]]) -> str:
    """Readable circuit summary (not OpenQASM)."""
    lines: list[str] = []
    for i, op in enumerate(ops, start=1):
        g = str(op.get("gate", "?"))
        targets = [f"q[{int(t)}]" for t in (op.get("targets") or [])]
        controls = [f"q[{int(c)}]" for c in (op.get("controls") or [])]
        ang = op.get("angle")

        if g in {"CX", "CZ"}:
            line = f"{i:02d}. {g} {controls[0]} -> {targets[0]}" if controls and targets else f"{i:02d}. {g}"
        elif g == "SWAP":
            line = f"{i:02d}. SWAP {targets[0]} <-> {targets[1]}" if len(targets) >= 2 else f"{i:02d}. SWAP"
        elif g in {"Rx", "Ry", "Rz"}:
            line = f"{i:02d}. {g}({float(ang or 0.0):.3f} rad) {targets[0] if targets else ''}".rstrip()
        else:
            line = f"{i:02d}. {g} {targets[0] if targets else ''}".rstrip()

        lines.append(line)
    return "\n".join(lines) if lines else "(no operations)"
