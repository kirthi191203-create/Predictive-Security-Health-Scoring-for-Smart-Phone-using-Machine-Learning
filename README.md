<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║     🛡  S H I E L D S C A N                                 ║
║     Predictive Security Health Scoring for Smartphones       ║
║     Real-Time ADB Analysis · ML Risk Classification          ║
╚══════════════════════════════════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![ADB](https://img.shields.io/badge/ADB-Android%20Debug%20Bridge-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/tools/adb)
[![License](https://img.shields.io/badge/License-MIT-6366F1?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-34D399?style=flat-square)]()

**ShieldScan** is a real-time Android device security scanner that connects to your phone via ADB, extracts live system data, computes a 0–100 security score, classifies risk using ML-inspired thresholds, detects anomalies, and surfaces actionable recommendations — all through a sleek Streamlit dashboard.

[Features](#-features) · [Architecture](#-system-architecture) · [Modules](#-10-functional-modules) · [Installation](#-installation) · [Usage](#-usage) · [Screenshots](#-dashboard-preview)

</div>

---

## 🔍 What is ShieldScan?

Most Android users have no idea whether their device is truly secure. Signature-based antivirus tools miss configuration risks; manual checklists are tedious; enterprise MDM solutions are overkill for personal devices.

**ShieldScan bridges that gap.** It speaks directly to your device over ADB, reads the actual live state of every critical security parameter, and gives you a single clear score along with prioritised steps to fix what's broken — no technical expertise required.

> Built as a final-year B.E. Computer Science & Engineering project at Sri Bhagya Lakshmi College of Engineering and Technology.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔴 **Real-Time ADB Extraction** | Live data pulled directly from device — no static datasets |
| 📊 **100-Point Security Score** | Weighted penalty engine across 5 critical security vectors |
| 🤖 **ML Risk Classification** | Low / Medium / High risk tiers via threshold-based classifier |
| 🔬 **Anomaly Detection** | Multi-variable pattern analysis for hidden threat combinations |
| 💡 **Recommendation Engine** | Severity-ranked, step-by-step fix instructions with exact navigation paths |
| 📦 **Package Breakdown** | System / Play Store / Sideloaded app counts with sideload ratio |
| 🎯 **Detection Accuracy** | Per-feature ADB signal confidence scores |
| ⚡ **Auto-Refresh Dashboard** | Configurable poll interval (2s / 5s / 10s / 30s / Manual) |
| 🌐 **Wireless Monitoring** | ADB-over-Wi-Fi support — no USB cable required |
| 🚨 **Alert Banners** | Automatic critical/warning alerts when score drops below thresholds |

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Android Device (ADB)                   │
└────────────────────┬────────────────────────────────────┘
                     │  USB / Wi-Fi
┌────────────────────▼────────────────────────────────────┐
│              Module 1: ADB Data Extraction               │
│   subprocess → adb shell getprop / settings / dumpsys   │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Module 2: Data Processing                   │
│         re + pandas → clean structured dataset           │
└────┬───────────────┬──────────────────┬─────────────────┘
     │               │                  │
┌────▼────┐    ┌─────▼──────┐    ┌──────▼──────┐
│Module 3 │    │  Module 4  │    │  Module 5   │
│Security │    │   Risk     │    │  Anomaly    │
│ Scoring │    │Classifica- │    │ Detection   │
│ 0–100   │    │    tion    │    │             │
└────┬────┘    └─────┬──────┘    └──────┬──────┘
     └───────────────┴──────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Module 6: Recommendation Engine             │
│         Severity-ranked, context-sensitive fixes         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│          Module 7: Streamlit Dashboard (UI)              │
│   Score ring · Risk cards · Chips · Flags · Alerts       │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 10 Functional Modules

<details>
<summary><strong>Module 1 — ADB Data Extraction</strong></summary>

Establishes real-time communication with the Android device via ADB. Uses Python's `subprocess` module to execute shell commands and extract:

- OS version & security patch level
- Screen lock type (None / PIN / Pattern / Biometric)
- Unknown sources status (global + secure settings + per-app `appops` check)
- Dangerous permission count
- Installed package list with installer source
- USB debugging, developer options, Bluetooth, Wi-Fi states
- Device encryption status, battery level, build ID

</details>

<details>
<summary><strong>Module 2 — Data Processing</strong></summary>

Transforms raw ADB text output into a clean, structured dataset using Python's `re` library and `pandas`:

- Strips terminal noise and parses key-value pairs
- Converts binary flags (ON/OFF) to numerical representations
- Aggregates sideloaded package counts by matching against trusted installer signatures
- Handles missing/malformed data with graceful fallback values

</details>

<details>
<summary><strong>Module 3 — Security Scoring</strong></summary>

Computes a **0–100 security score** using a weighted penalty engine:

| Risk Factor | Max Penalty |
|---|---|
| OS version lag (`lag × 6`, capped) | −25 pts |
| Unknown sources enabled | −25 pts |
| No screen lock | −20 pts |
| Excessive dangerous permissions | −20 pts |
| Sideloaded apps (on low-score device) | −10 pts |

</details>

<details>
<summary><strong>Module 4 — Risk Classification</strong></summary>

Translates the numerical score into three qualitative tiers:

| Score | Risk Level | Meaning |
|---|---|---|
| ≥ 70 | 🟢 Low Risk | Strong security posture |
| 40 – 69 | 🟡 Medium Risk | Moderate vulnerabilities, attention needed |
| < 40 | 🔴 High Risk | Critical exposure, immediate action required |

</details>

<details>
<summary><strong>Module 5 — Anomaly Detection</strong></summary>

Detects multi-variable threat combinations that single-parameter checks miss:

- **Developer Options + USB Debug + Sideloads** → data exfiltration pathway
- **Excessive dangerous permissions** (> 40) → data access anomaly
- **Unknown Sources + Sideloads present** → elevated infection vector

</details>

<details>
<summary><strong>Module 6 — Recommendation Engine</strong></summary>

Generates personalised, severity-ranked corrective actions:

- **Critical** → Unknown Sources, no screen lock, no encryption, severely outdated OS
- **Moderate** → USB debugging on, stale security patch, high permissions
- **Advisory** → Sideloaded app verification, developer options, Bluetooth

Each recommendation includes the **exact navigation path** within Android Settings.

</details>

<details>
<summary><strong>Module 7 — User Interface (Streamlit)</strong></summary>

Interactive dark-theme web dashboard featuring:

- SVG score ring with dynamic colour-coding
- Device info panel (model, serial, Android version, patch, battery)
- 6 metric chips: OS, Unknown Sources, Screen Lock, Permissions, Malware, Packages
- Colour-coded Active Risk Vectors section
- Device State flags (Encryption, USB Debug, Dev Options, Wi-Fi, Bluetooth)
- Package breakdown donut (System / Play / Sideloaded)
- Detection accuracy confidence bars
- Anomaly detection cards
- Step-by-step recommendation panel

</details>

<details>
<summary><strong>Module 8 — Historical Logging & Trend Analysis</strong></summary>

Logs each evaluation snapshot (score, risk tier, anomalies, recommendations, timestamp) to a structured local database. Generates trend visualisations to track security posture over time — enabling users to measure improvement after applying updates or configuration changes.

</details>

<details>
<summary><strong>Module 9 — Wireless Connectivity & Remote Monitoring</strong></summary>

Automates ADB-over-Wi-Fi pairing, eliminating USB cable dependency. Supports sequential auditing of multiple Android devices — ideal for lab environments, enterprise compliance audits, and QA testing. Manages IP resolution, port negotiation, and device authentication.

</details>

<details>
<summary><strong>Module 10 — Automated Alert & Notification</strong></summary>

Continuously monitors Risk Classification and Anomaly Detection outputs against critical thresholds:

- **Score < 30** → 🚨 Critical danger alert banner
- **Score 30–49** → ⚠️ High-visibility warning banner

Ensures severe vulnerabilities are never missed between manual review cycles.

</details>

---

## 🚀 Installation

### Prerequisites

- Python 3.10+
- [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) installed and on your `PATH`
- An Android device with **USB Debugging** enabled

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/shieldscan.git
cd shieldscan
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify ADB is working

```bash
adb devices
```

You should see your device listed with status `device`. If it shows `unauthorized`, check your phone screen and tap **Allow**.

---

## 📋 Requirements

```
streamlit>=1.32.0
pandas>=2.0.0
```

> ADB must be installed separately. Download from [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools).

---

## 🖥 Usage

### Run the dashboard

```bash
streamlit run mobile_sender_final.py
```

The app will open automatically at `http://localhost:8501`.

### Connect your device

1. Enable **Developer Options** on your Android device  
   *(Settings → About Phone → tap Build Number 7 times)*
2. Enable **USB Debugging** inside Developer Options
3. Connect via USB and tap **Allow** on the authorization popup
4. Select your device from the sidebar dropdown
5. ShieldScan begins scanning automatically

### Wireless mode (ADB over Wi-Fi)

```bash
# Connect via USB first, then run:
adb tcpip 5555
adb connect <device-ip>:5555
# Disconnect USB — ShieldScan will pick up the wireless connection
```

---

## 📊 Scoring Methodology

```
Security Score = 100
  − min(25, OS_lag × 6)              ← OS version penalty
  − 25 × unknown_sources_enabled     ← sideload vector
  − 20 × (1 − screen_lock_present)   ← physical access risk
  − round((perm_ratio) × 20)         ← permission exposure
  − 10 × malware_detected            ← confirmed sideload risk

Final Score ∈ [0, 100]
```

| Score | Grade | Risk Level |
|---|---|---|
| 80 – 100 | EXCELLENT | 🟢 Low |
| 65 – 79 | GOOD | 🟢 Low |
| 50 – 64 | MODERATE | 🟡 Medium |
| 30 – 49 | POOR | 🔴 High |
| 0 – 29 | CRITICAL | 🔴 High |

---

## 🔐 Privacy

- **No data leaves your machine.** All ADB communication happens locally.
- **No accounts, no cloud, no telemetry.** ShieldScan runs entirely offline.
- Raw ADB data is processed in-memory and never written to disk (unless the Historical Logging module is enabled).

---

## 🗂 Project Structure

```
shieldscan/
├── mobile_sender_final.py   # Main application (all modules)
├── requirements.txt         # Python dependencies
├── README.md                # This file
└── LICENSE                  # MIT License
```

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| UI Framework | Streamlit |
| Device Communication | Android Debug Bridge (ADB) |
| Data Parsing | `re`, `pandas` |
| System Interface | `subprocess` |
| Visualisation | SVG (inline), Streamlit native |
| Fonts | Syne, JetBrains Mono, Outfit (Google Fonts) |

---

## 👩‍💻 Authors

| Name | Role |
|---|---|
| **Kiruthika** | Lead Developer |
| **S Bhagya Lakshmi** | Co-Developer |

**Department:** Computer Science & Engineering  
**Institution:** Sri Bhagya Lakshmi College of Engineering and Technology  
**Guide:** [Supervisor Name]

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with 🛡 and Python · ShieldScan v2.0

*"Real-time awareness is the first line of defence."*

</div>
