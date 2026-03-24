"""
Quantum Threat Index (QTI) Module
==================================
Evaluates quantum-era risk based on real-world threat indicators
rather than pure random generation.

Threat factors considered:
  1. Estimated adversary qubit count (logical qubits)
  2. Key age – how long the encrypted data must remain secret
  3. Algorithm vulnerability (RSA/ECC key sizes in use)
  4. Network exposure level
  5. QBER from latest QKD session (if available)

Output: (score 0.0–1.0, level LOW/MEDIUM/HIGH)
"""

import time
import math
import random
from dataclasses import dataclass, field
from config import LOW_THRESHOLD, HIGH_THRESHOLD


@dataclass
class ThreatEnvironment:
    """
    Represents the current threat environment.
    In production, these would be fed from external intelligence feeds,
    network monitoring, or configuration.
    """
    # Estimated adversary logical qubit count (public research frontier)
    adversary_qubits: int = 1000
    # Years the data must remain confidential
    data_secrecy_years: int = 10
    # Weakest symmetric key in use (bits). Grover applies here.
    weakest_symmetric_key_bits: int = 256
    # Weakest asymmetric key in use (bits). Shor applies here.
    weakest_asymmetric_key_bits: int = 2048
    # Network exposure: 0.0 (air-gapped) to 1.0 (public internet)
    network_exposure: float = 0.7
    # Latest QKD QBER (None if QKD not active)
    last_qber: float = None
    # Detected intercept attempts (from IDS / QKD monitoring)
    intercept_events_24h: int = 0


# ---------------------------------------------------------------------------
# Shor's algorithm threshold estimate
# ---------------------------------------------------------------------------
def _shor_risk(adversary_qubits: int, asymmetric_key_bits: int) -> float:
    """
    Estimate the risk that Shor's algorithm can break the given classical
    key size with the adversary's qubit count.

    RSA-2048 needs ~4096 logical qubits to break.
    ECC-256 needs ~2330 logical qubits.
    AES-256 is not vulnerable to Shor (returns 0).
    """
    # Shor applies to asymmetric primitives (RSA/ECC). We use a simplified
    # qubit threshold heuristic that is explainable in a hackathon setting.
    if asymmetric_key_bits <= 0:
        return 0.0

    qubits_needed = max(1, int(asymmetric_key_bits * 1.8))  # practical approximation
    if adversary_qubits >= qubits_needed:
        return 1.0
    ratio = adversary_qubits / qubits_needed
    return min(1.0, ratio)  # linear ramp for better operational sensitivity


def _grover_risk(key_bits: int) -> float:
    """
    Estimate Grover's algorithm threat to symmetric keys.
    Grover needs 2^(n/2) operations → AES-256 → 2^128 still infeasible.
    But if key_bits < 128, risk increases.
    """
    if key_bits <= 0:
        return 0.0
    effective_security = key_bits / 2
    if effective_security >= 128:
        return 0.18  # residual strategic risk for long-horizon data
    if effective_security >= 112:
        return 0.28
    if effective_security >= 80:
        return 0.5
    return 0.8


def _data_longevity_factor(years: int) -> float:
    """Longer secrecy requirements → higher threat (harvest-now-decrypt-later)."""
    if years <= 1:
        return 0.1
    elif years <= 5:
        return 0.3
    elif years <= 15:
        return 0.55
    elif years <= 30:
        return 0.85
    return 1.0


def _qber_factor(qber: float) -> float:
    """
    High QBER may indicate eavesdropping on the quantum channel.
    Maps QBER → threat contribution.
    """
    if qber is None:
        return 0.0  # QKD not active
    if qber < 0.02:
        return 0.05  # residual channel concern
    elif qber < 0.08:
        return 0.2  # slightly elevated
    elif qber < 0.15:
        return 0.5  # suspicious
    return 1.0  # probable intercept


def _network_and_intercept_factor(exposure: float, events: int) -> float:
    """Combine network exposure with detected intercept events."""
    base = exposure * 0.5
    if events > 0:
        base += min(0.5, events * 0.1)
    return min(1.0, base)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def evaluate_qti(env: ThreatEnvironment = None):
    """
    Evaluate the Quantum Threat Index.

    Parameters
    ----------
    env : ThreatEnvironment, optional
        Current threat parameters. If None, uses sensible defaults with
        slight randomization to simulate real-time intelligence updates.

    Returns
    -------
    (threat_score: float, threat_level: str)
    """
    if env is None:
        # Simulate varying real-world conditions
        env = ThreatEnvironment(
            adversary_qubits=random.randint(200, 4500),
            data_secrecy_years=random.choice([1, 5, 10, 15, 25]),
            weakest_symmetric_key_bits=random.choice([128, 256]),
            weakest_asymmetric_key_bits=random.choice([2048, 3072]),
            network_exposure=random.uniform(0.2, 1.0),
            last_qber=random.uniform(0.0, 0.2) if random.random() > 0.3 else None,
            intercept_events_24h=random.choices([0, 0, 0, 1, 2, 5],
                                                weights=[50, 20, 10, 10, 7, 3])[0],
        )

    # Back-compat: some callers may still construct ThreatEnvironment with the
    # old attribute name. If present, map it into the appropriate bucket.
    if hasattr(env, "weakest_classical_key_bits"):
        try:
            v = int(getattr(env, "weakest_classical_key_bits"))
            if v <= 256:
                env.weakest_symmetric_key_bits = v
            else:
                env.weakest_asymmetric_key_bits = v
        except Exception:
            pass

    # Compute individual factors
    w_shor = 0.30
    w_grover = 0.10
    w_longevity = 0.25
    w_qber = 0.20
    w_network = 0.15

    shor = _shor_risk(env.adversary_qubits, env.weakest_asymmetric_key_bits)
    grover = _grover_risk(env.weakest_symmetric_key_bits)
    longevity = _data_longevity_factor(env.data_secrecy_years)
    qber = _qber_factor(env.last_qber)
    network = _network_and_intercept_factor(env.network_exposure,
                                            env.intercept_events_24h)

    threat_score = (w_shor * shor
                    + w_grover * grover
                    + w_longevity * longevity
                    + w_qber * qber
                    + w_network * network)

    threat_score = max(0.0, min(1.0, threat_score))

    if threat_score < LOW_THRESHOLD:
        level = "LOW"
    elif threat_score < HIGH_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return threat_score, level


def evaluate_qti_detailed(env: ThreatEnvironment = None) -> dict:
    """
    Extended version returning full breakdown for analysis / logging.
    """
    if env is None:
        env = ThreatEnvironment(
            adversary_qubits=random.randint(200, 4500),
            data_secrecy_years=random.choice([1, 5, 10, 15, 25]),
            weakest_symmetric_key_bits=random.choice([128, 256]),
            weakest_asymmetric_key_bits=random.choice([2048, 3072]),
            network_exposure=random.uniform(0.2, 1.0),
            last_qber=random.uniform(0.0, 0.2) if random.random() > 0.3 else None,
            intercept_events_24h=random.choices([0, 0, 0, 1, 2, 5],
                                                weights=[50, 20, 10, 10, 7, 3])[0],
        )

    if hasattr(env, "weakest_classical_key_bits"):
        try:
            v = int(getattr(env, "weakest_classical_key_bits"))
            if v <= 256:
                env.weakest_symmetric_key_bits = v
            else:
                env.weakest_asymmetric_key_bits = v
        except Exception:
            pass

    score, level = evaluate_qti(env)

    return {
        "score": score,
        "level": level,
        "environment": {
            "adversary_qubits": env.adversary_qubits,
            "data_secrecy_years": env.data_secrecy_years,
            "weakest_symmetric_key_bits": env.weakest_symmetric_key_bits,
            "weakest_asymmetric_key_bits": env.weakest_asymmetric_key_bits,
            "network_exposure": round(env.network_exposure, 3),
            "last_qber": round(env.last_qber, 4) if env.last_qber else None,
            "intercept_events_24h": env.intercept_events_24h,
        },
        "factors": {
            "shor_risk": round(_shor_risk(env.adversary_qubits,
                                          env.weakest_asymmetric_key_bits), 4),
            "grover_risk": round(_grover_risk(env.weakest_symmetric_key_bits), 4),
            "longevity": round(_data_longevity_factor(env.data_secrecy_years), 4),
            "qber": round(_qber_factor(env.last_qber), 4),
            "network": round(_network_and_intercept_factor(
                env.network_exposure, env.intercept_events_24h), 4),
        },
    }