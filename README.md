# QtHack04 – Problem 21 (Major) + 16 (Minor)

This repo is an interactive visual simulator for an **adaptive quantum-safe communication session**:
- **Problem 21 (major):** BB84 QKD + key sifting + QBER estimation + privacy amplification (HKDF)
- **Problem 16 (minor):** Bloch sphere visualization + gate-stepper state evolution

The UI is a Streamlit dashboard.

## Quick start (Windows)

1) Create & activate a venv

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Install dashboard dependencies

```powershell
pip install -r requirements_dashboard.txt
```

3) Run the dashboard

```powershell
streamlit run dashboard.py
```

If Streamlit asks for an email on first run, you can press Enter to skip.

## “Wow demo” settings (what judges should try)

In the left sidebar (BB84 channel parameters):
- **Eve intercept probability**:
  - `0.00` → QBER should be near 0 (secure)
  - `1.00` → QBER rises strongly (often trends toward ~25% on sifted key in ideal intercept-resend)
- **Channel bit-flip probability**:
  - `0.00` → clean channel
  - `0.05` → visibly noisier channel (QBER rises)
- **BB84 seed**: set to a fixed value (e.g. `7`) for reproducible evaluation runs

In **Section 2 (BB84)**, go to **Step 4 (QBER Estimation)** to see:
- extracted metrics (sifted bits, raw key bits, key rate)
- a mini sweep plot: **QBER vs Eve intercept probability**

In **Section 5 (Live Demo)**, click **Run Secure Session** and verify:
- Threat Radar sliders affect the mode selection (AUTO) and the live run uses the same environment
- If QKD mode is active and Eve/noise is high, the session will reflect insecure/noisy QKD conditions

## Optional PQC (Kyber) via liboqs

The project supports Kyber-1024 via `liboqs` if your system has the native library.
On many Windows machines this is not available by default.

- By default the dashboard install does **not** require `oqs`.
- If you have liboqs installed and want real Kyber, install `oqs` manually:

```powershell
pip install oqs
```

If `oqs` fails to load, the project falls back to **X25519-ECDH** automatically.

## Files to know

- `dashboard.py` – Streamlit UI
- `main_controller.py` – end-to-end secure session orchestration
- `encryption_layer/qkd_bb84_qiskit.py` – BB84 simulation (Eve/noise/seed)
- `threat_model/quantum_threat_index.py` – QTI model + factor breakdown
- `encryption_layer/hybrid_combiner.py` – HKDF key combining (MAX uses SHA256 + SHA512 XOR)
