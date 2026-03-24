"""encryption_layer.qkd_bb84_qiskit

BB84 Quantum Key Distribution (QKD)
==================================

For hackathon demos we want *parameter-sensitive* behavior:
- Toggle/scale Eve (intercept-resend) and see QBER rise.
- Add channel noise and see QBER rise.
- Allow a seed so results are reproducible during evaluation.

This implementation uses a physics-faithful *stochastic BB84 model* that
captures basis mismatch + measurement collapse effects, without depending on
optional simulator noise models.

We keep the public API `bb84_qkd()` backward-compatible for the rest of the
project.
"""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import QBER_THRESHOLD, QKD_MODE, QKD_QUBITS_BENCHMARK, QKD_QUBITS_RESEARCH


def _privacy_amplification(sifted_key_bits: list[int]) -> bytes:
    bit_string = "".join(map(str, sifted_key_bits))
    raw_bytes = hashlib.sha512(bit_string.encode()).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qkd-bb84-privacy-amplified-key-v1",
    ).derive(raw_bytes)


def _rand_bits(rng: random.Random, n: int) -> list[int]:
    return [rng.randint(0, 1) for _ in range(n)]


def _rand_bases(rng: random.Random, n: int) -> list[str]:
    return [rng.choice(["Z", "X"]) for _ in range(n)]


def _measure_bit(
    *,
    prepared_bit: int,
    prepared_basis: str,
    measure_basis: str,
    rng: random.Random,
    channel_flip_prob: float,
) -> int:
    """Measure a prepared BB84 qubit.

    If bases match, measurement equals prepared bit (optionally flipped by
    channel noise). If bases mismatch, measurement is random.
    """
    if prepared_basis == measure_basis:
        bit = prepared_bit
    else:
        bit = rng.randint(0, 1)

    if channel_flip_prob > 0 and rng.random() < channel_flip_prob:
        bit ^= 1
    return bit


def bb84_qkd(
    n: int | None = None,
    *,
    seed: int | None = None,
    eve_intercept_prob: float = 0.0,
    channel_flip_prob: float = 0.0,
    return_details: bool = False,
) -> dict[str, Any]:
    """Run a BB84 session with optional Eve + channel noise.

    Parameters
    ----------
    n:
        Number of qubits to send. If None, uses config based on QKD_MODE.
    seed:
        Seed for reproducible runs.
    eve_intercept_prob:
        Probability per qubit that Eve performs intercept-resend.
        With 1.0 (always intercept), idealized expected QBER on sifted key
        tends toward ~25%.
    channel_flip_prob:
        Probability per measurement (after basis effect) that the bit flips.
    return_details:
        If True, includes basis/bit arrays for visualization.

    Returns
    -------
    dict containing at minimum:
      secure, qber, key, raw_key_bits, time, qubits_sent
    """
    start_time = time.perf_counter()

    if n is None:
        n = QKD_QUBITS_RESEARCH if QKD_MODE == "RESEARCH" else QKD_QUBITS_BENCHMARK

    eve_intercept_prob = max(0.0, min(1.0, float(eve_intercept_prob)))
    channel_flip_prob = max(0.0, min(1.0, float(channel_flip_prob)))

    rng = random.Random(seed)

    alice_bits = _rand_bits(rng, n)
    alice_bases = _rand_bases(rng, n)
    bob_bases = _rand_bases(rng, n)

    eve_intercepted: list[bool] = []
    eve_bases: list[str | None] = []
    eve_bits: list[int | None] = []

    bob_results: list[int] = []
    for i in range(n):
        a_bit = alice_bits[i]
        a_basis = alice_bases[i]
        b_basis = bob_bases[i]

        if rng.random() < eve_intercept_prob:
            # Eve intercepts: she measures in random basis and resends.
            e_basis = rng.choice(["Z", "X"]) 
            e_bit = _measure_bit(
                prepared_bit=a_bit,
                prepared_basis=a_basis,
                measure_basis=e_basis,
                rng=rng,
                channel_flip_prob=0.0,
            )

            # Bob measures Eve's resent qubit.
            b_bit = _measure_bit(
                prepared_bit=e_bit,
                prepared_basis=e_basis,
                measure_basis=b_basis,
                rng=rng,
                channel_flip_prob=channel_flip_prob,
            )
            eve_intercepted.append(True)
            eve_bases.append(e_basis)
            eve_bits.append(e_bit)
        else:
            b_bit = _measure_bit(
                prepared_bit=a_bit,
                prepared_basis=a_basis,
                measure_basis=b_basis,
                rng=rng,
                channel_flip_prob=channel_flip_prob,
            )
            eve_intercepted.append(False)
            eve_bases.append(None)
            eve_bits.append(None)

        bob_results.append(b_bit)

    matched = [alice_bases[i] == bob_bases[i] for i in range(n)]
    sifted_idx = [i for i in range(n) if matched[i]]
    sifted_alice = [alice_bits[i] for i in sifted_idx]
    sifted_bob = [bob_results[i] for i in sifted_idx]

    sifted_len = len(sifted_alice)
    check_len = max(1, sifted_len // 2) if sifted_len else 0
    check_indices = sorted(rng.sample(range(sifted_len), min(check_len, sifted_len))) if sifted_len else []

    errors = sum(1 for idx in check_indices if sifted_alice[idx] != sifted_bob[idx])
    qber = errors / len(check_indices) if check_indices else 0.0

    remaining_indices = [i for i in range(sifted_len) if i not in set(check_indices)]
    raw_key_bits_list = [sifted_alice[i] for i in remaining_indices]

    secure = qber < QBER_THRESHOLD
    derived_key = _privacy_amplification(raw_key_bits_list) if secure and raw_key_bits_list else None

    duration = time.perf_counter() - start_time

    result: dict[str, Any] = {
        "secure": secure,
        "qber": qber,
        "key": derived_key,
        "raw_key_bits": len(raw_key_bits_list),
        "time": duration,
        "qubits_sent": n,
        # Extra metrics for dashboards / evaluation
        "sifted_bits": sifted_len,
        "check_bits": len(check_indices),
        "key_rate": (len(raw_key_bits_list) / n) if n else 0.0,
        "eve_intercept_prob": eve_intercept_prob,
        "channel_flip_prob": channel_flip_prob,
        "seed": seed,
    }

    if return_details:
        result["details"] = {
            "alice_bits": alice_bits,
            "alice_bases": alice_bases,
            "bob_bases": bob_bases,
            "bob_bits": bob_results,
            "matched": matched,
            "sifted_idx": sifted_idx,
            "sifted_alice": sifted_alice,
            "sifted_bob": sifted_bob,
            "check_indices": check_indices,
            "eve_intercepted": eve_intercepted,
            "eve_bases": eve_bases,
            "eve_bits": eve_bits,
        }

    return result