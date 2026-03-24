"""IBM Composer-like qubit visualizations using Plotly."""

from __future__ import annotations

import math
from typing import Any

import plotly.graph_objects as go


def amplitudes_to_bloch(amplitudes: tuple[complex, complex]) -> list[float]:
    """Convert |psi> = a|0> + b|1> to Bloch coordinates."""
    a, b = amplitudes
    x = 2.0 * (a.conjugate() * b).real
    y = 2.0 * (a.conjugate() * b).imag
    z = (abs(a) ** 2) - (abs(b) ** 2)
    return [float(x), float(y), float(z)]


def _sphere_mesh(resolution: int = 30) -> tuple[list[list[float]], list[list[float]], list[list[float]]]:
    theta_steps = [i * math.pi / resolution for i in range(resolution + 1)]
    phi_steps = [i * 2.0 * math.pi / resolution for i in range(resolution + 1)]

    xs: list[list[float]] = []
    ys: list[list[float]] = []
    zs: list[list[float]] = []

    for theta in theta_steps:
        row_x: list[float] = []
        row_y: list[float] = []
        row_z: list[float] = []
        for phi in phi_steps:
            row_x.append(math.sin(theta) * math.cos(phi))
            row_y.append(math.sin(theta) * math.sin(phi))
            row_z.append(math.cos(theta))
        xs.append(row_x)
        ys.append(row_y)
        zs.append(row_z)

    return xs, ys, zs


def build_bloch_figure(
    vector: list[float],
    title: str,
    history: list[list[float]] | None = None,
    measurement_basis: str = "Z",
) -> go.Figure:
    """Build an interactive 3D Bloch sphere with basis axes and optional history trail."""
    x_s, y_s, z_s = _sphere_mesh(26)

    fig = go.Figure()
    fig.add_trace(
        go.Surface(
            x=x_s,
            y=y_s,
            z=z_s,
            opacity=0.12,
            showscale=False,
            colorscale=[[0.0, "#cbd5e1"], [1.0, "#cbd5e1"]],
            hoverinfo="skip",
        )
    )

    axes = [
        ([0, 1.05], [0, 0], [0, 0], "#ef4444", "X basis"),
        ([0, 0], [0, 1.05], [0, 0], "#06b6d4", "Y basis"),
        ([0, 0], [0, 0], [0, 1.05], "#22c55e", "Z basis"),
    ]
    for x, y, z, color, name in axes:
        width = 7 if name.startswith(measurement_basis) else 4
        fig.add_trace(
            go.Scatter3d(
                x=x,
                y=y,
                z=z,
                mode="lines",
                line=dict(color=color, width=width),
                name=name,
                hoverinfo="skip",
                showlegend=False,
            )
        )

    if history and len(history) > 1:
        fig.add_trace(
            go.Scatter3d(
                x=[p[0] for p in history],
                y=[p[1] for p in history],
                z=[p[2] for p in history],
                mode="lines+markers",
                marker=dict(size=3, color="#94a3b8"),
                line=dict(color="#64748b", width=3, dash="dot"),
                name="State path",
                showlegend=False,
            )
        )

    fig.add_trace(
        go.Scatter3d(
            x=[0, vector[0]],
            y=[0, vector[1]],
            z=[0, vector[2]],
            mode="lines+markers",
            marker=dict(size=5, color="#ec4899"),
            line=dict(color="#ec4899", width=8),
            name="Current qubit state",
            showlegend=False,
        )
    )

    fig.update_layout(
        title=title,
        height=400,
        margin=dict(l=0, r=0, t=50, b=0),
        scene=dict(
            xaxis=dict(range=[-1.1, 1.1], title="X", showbackground=False, showgrid=False, zeroline=False),
            yaxis=dict(range=[-1.1, 1.1], title="Y", showbackground=False, showgrid=False, zeroline=False),
            zaxis=dict(range=[-1.1, 1.1], title="Z", showbackground=False, showgrid=False, zeroline=False),
            aspectmode="cube",
            camera=dict(eye=dict(x=1.45, y=1.35, z=1.0)),
        ),
        showlegend=False,
    )
    return fig


def build_gate_lane(gate_seq: list[dict[str, Any]]) -> go.Figure:
    """Render a single-qubit gate lane similar to Composer workflow."""
    fig = go.Figure()

    if not gate_seq:
        fig.add_annotation(
            text="No gates yet. Add gates to compose qubit evolution.",
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
            font=dict(size=14, color="#64748b"),
        )
        fig.update_layout(height=150, margin=dict(l=10, r=10, t=24, b=10))
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
        return fig

    gate_colors = {
        "H": "#2563eb",
        "X": "#ef4444",
        "Z": "#10b981",
        "Rx": "#f59e0b",
        "Rz": "#8b5cf6",
    }

    x_values = list(range(1, len(gate_seq) + 1))
    for i, gate_step in enumerate(gate_seq, start=1):
        gate = str(gate_step.get("gate", "?"))
        angle = gate_step.get("angle")
        angle_text = ""
        if isinstance(angle, (int, float)):
            angle_text = f"<br>{angle:.2f} rad"

        fig.add_trace(
            go.Scatter(
                x=[i],
                y=[0],
                mode="markers+text",
                marker=dict(
                    symbol="square",
                    size=54,
                    color=gate_colors.get(gate, "#64748b"),
                    line=dict(color="#0f172a", width=1),
                ),
                text=[f"<b>{gate}</b>"],
                textposition="middle center",
                textfont=dict(color="white", size=16),
                hovertemplate=f"Step {i}: {gate}{angle_text}<extra></extra>",
                showlegend=False,
            )
        )

    fig.add_shape(type="line", x0=0.5, y0=0, x1=len(gate_seq) + 0.5, y1=0, line=dict(color="#94a3b8", width=6))
    fig.update_layout(
        title="Composer lane (q[0])",
        height=145,
        margin=dict(l=10, r=10, t=36, b=22),
        xaxis=dict(
            range=[0.5, len(gate_seq) + 0.5],
            tickvals=x_values,
            ticktext=[f"t{i}" for i in x_values],
            title="Gate step",
        ),
        yaxis=dict(visible=False, range=[-0.7, 0.7]),
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_measurement_bars(vector: list[float], basis: str) -> go.Figure:
    """Compute measurement probabilities for chosen basis and render as bars."""
    x, _y, z = vector
    b = basis.upper()

    if b == "X":
        p0 = (1.0 + x) / 2.0
    elif b == "Y":
        p0 = (1.0 + vector[1]) / 2.0
    else:
        p0 = (1.0 + z) / 2.0

    p0 = max(0.0, min(1.0, p0))
    p1 = 1.0 - p0

    fig = go.Figure(
        data=[
            go.Bar(name="Outcome 0", x=["0"], y=[p0], marker_color="#22c55e"),
            go.Bar(name="Outcome 1", x=["1"], y=[p1], marker_color="#ef4444"),
        ]
    )
    fig.update_layout(
        title=f"Measurement probabilities in {b}-basis",
        height=280,
        yaxis=dict(range=[0, 1], title="Probability"),
        showlegend=False,
        margin=dict(l=10, r=10, t=48, b=30),
    )
    return fig


def format_statevector(amplitudes: tuple[complex, complex]) -> str:
    """Return a compact ket string for UI inspector panels."""
    a, b = amplitudes
    return (
        f"|psi> = ({a.real:+.3f}{a.imag:+.3f}i)|0> + "
        f"({b.real:+.3f}{b.imag:+.3f}i)|1>"
    )
