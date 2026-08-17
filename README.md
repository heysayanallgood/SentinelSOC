# 🛡️⚡ SENTINELSOC

<div align="center">

<img src="https://img.shields.io/badge/SENTINELSOC-BLUE%20TEAM%20COMMAND%20CENTER-red?style=for-the-badge&logo=shield&logoColor=white">

<img src="https://img.shields.io/badge/PYTHON-3.10%2B-orange?style=for-the-badge&logo=python&logoColor=white">

<img src="https://img.shields.io/badge/LINUX-SUPPORTED-black?style=for-the-badge&logo=linux&logoColor=FCC624">

<img src="https://img.shields.io/badge/TERMUX-SUPPORTED-black?style=for-the-badge&logo=android&logoColor=white">

<img src="https://img.shields.io/badge/BLUE%20TEAM-DEFENSIVE-red?style=for-the-badge">

<img src="https://img.shields.io/badge/DFIR-ENABLED-b22222?style=for-the-badge">

<img src="https://img.shields.io/badge/MITRE%20ATT%26CK-INTEGRATED-8b0000?style=for-the-badge">

<img src="https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge">

<br><br>

# 🔥 SENTINELSOC

## `THE BLUE TEAM COMMAND DECK`

### Observe. Detect. Correlate. Investigate. Respond. Preserve. Report.

**A modular, portable defensive-security platform for SOC operations, incident response, digital forensics, threat intelligence, security monitoring and automated reporting.**

<br>

[![GitHub stars](https://img.shields.io/github/stars/heysayanallgood/SentinelSOC?style=social)](https://github.com/heysayanallgood/SentinelSOC)
[![GitHub forks](https://img.shields.io/github/forks/heysayanallgood/SentinelSOC?style=social)](https://github.com/heysayanallgood/SentinelSOC)
[![GitHub watchers](https://img.shields.io/github/watchers/heysayanallgood/SentinelSOC?style=social)](https://github.com/heysayanallgood/SentinelSOC)

</div>

---

# 🟥 COMIC DOSSIER // PROJECT ORIGIN

> **Every SOC needs a Sentinel.**

**SentinelSOC** is an independent open-source defensive cybersecurity toolkit designed to bring the workflow of a Security Operations Center into a single portable command environment.

Instead of forcing an analyst to jump between disconnected scripts and utilities, SentinelSOC combines:

- 🖥️ System monitoring
- 🌐 Network analysis
- 🛡️ Threat intelligence
- 📜 Log analysis
- 🔍 Digital forensics
- 🚨 Incident response
- 🎯 MITRE ATT&CK correlation
- 🧬 IOC analysis
- 📊 Security reporting
- 👤 IAM-oriented reporting
- ⚙️ Persistent configuration
- 🧪 Security event monitoring

into one modular defensive platform.

---

# ⚡ THE SENTINEL MISSION

SentinelSOC follows a complete defensive security lifecycle:

```text
                    ┌──────────────┐
                    │   OBSERVE    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   COLLECT    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  NORMALIZE   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    DETECT    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   CORRELATE  │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ INVESTIGATE  │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   RESPOND    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   PRESERVE   │
                    │   EVIDENCE   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   REPORT     │
                    └──────────────┘


---

🧬 SYSTEM ARCHITECTURE

flowchart TD

    A["🛡️ SentinelSOC Command Deck"]

    A --> B["🖥️ Dashboard"]
    A --> C["🌐 Network Analysis"]
    A --> D["🛡️ Threat Intelligence"]
    A --> E["📜 Log Analysis"]
    A --> F["🔍 Digital Forensics"]
    A --> G["🚨 Incident Response"]
    A --> H["📊 Reporting"]
    A --> I["⚙️ Settings"]
    A --> J["📖 About / Project Dossier"]

    C --> K["Network Collectors"]
    D --> L["IOC Engine"]
    E --> M["Log Normalizer"]
    F --> N["Evidence Engine"]
    G --> O["Incident Case Engine"]

    K --> P["Security Event Store"]
    L --> P
    M --> P
    N --> P
    O --> P

    P --> Q["Alert Engine"]
    Q --> R["Risk Scoring"]
    R --> S["IOC Correlation"]
    S --> T["MITRE ATT&CK"]

    T --> U["Incident Workflow"]
    U --> V["Reporting Engine"]

    V --> W["HTML"]
    V --> X["PDF"]
    V --> Y["JSON"]
    V --> Z["CSV"]
    V --> AA["IAM"]


---

🧠 SECURITY PIPELINE

RAW TELEMETRY
      │
      ▼
┌──────────────────────┐
│   EVENT NORMALIZER   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ SECURITY CLASSIFIER  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    RISK ENGINE       │
└──────────┬───────────┘
           │
     ┌─────┼─────┐
     │     │     │
     ▼     ▼     ▼
    LOW  MEDIUM HIGH
           │
           ▼
┌──────────────────────┐
│      IOC ENGINE      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   MITRE ATT&CK       │
│    CORRELATION       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    ALERT ENGINE      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ INCIDENT RESPONSE    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ DIGITAL FORENSICS    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    REPORT ENGINE     │
└──────────────────────┘


---

🎯 COMMAND DECK

SentinelSOC provides a centralized command interface for defensive security operations.

╔══════════════════════════════════════════════════════╗
║                    SENTINELSOC                       ║
║              BLUE TEAM COMMAND DECK                  ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  1  🖥️ Dashboard                                     ║
║  2  🌐 Network Analysis                              ║
║  3  🛡️ Threat Intelligence                           ║
║  4  📜 Log Analysis                                  ║
║  5  🔍 Digital Forensics                             ║
║  6  🚨 Incident Response                             ║
║  7  📊 Reporting                                     ║
║  8  ⚙️ Settings                                      ║
║  9  📖 About                                         ║
║  0  🚪 Exit                                          ║
║                                                      ║
╚══════════════════════════════════════════════════════╝


---

🖥️ SYSTEM DASHBOARD

The dashboard provides a centralized view of the local security environment.

Capabilities

🖥️ Operating-system information

⚙️ CPU information

🧠 Memory information

💾 Disk information

🔄 Running-process information

🌐 Network status

📡 Network connections

📊 Runtime statistics

🔐 Security-relevant system information


The dashboard is designed to give the analyst an immediate overview before deeper investigation.


---

🌐 NETWORK ANALYSIS

SentinelSOC provides multiple defensive network investigation capabilities.

Capability	Purpose

🔎 Port Scanner	Identify reachable services
🛰️ Host Discovery	Discover live network hosts
🌐 DNS Lookup	Resolve domain information
🔁 Reverse DNS	Resolve IP addresses
👤 WHOIS	Investigate domain registration information
🧾 HTTP Headers	Inspect HTTP response headers
🔐 SSL Inspection	Inspect TLS certificate information
📡 Ping	Connectivity verification
🛣️ Traceroute	Network path analysis
🔌 Connection Analysis	Inspect active connections
👂 Listening Ports	Identify listening services


Network Investigation Flow

TARGET
  │
  ├── DNS
  │
  ├── WHOIS
  │
  ├── HTTP
  │
  ├── TLS
  │
  ├── PORTS
  │
  ├── CONNECTIONS
  │
  └── NETWORK PATH
          │
          ▼
       ANALYST


---

🛡️ THREAT INTELLIGENCE

Threat intelligence capabilities help enrich investigations with external and contextual security information.

Capabilities

🔑 Hash investigation

🌐 URL investigation

📡 IP investigation

🧬 IOC investigation

🐛 CVE investigation

🎯 MITRE ATT&CK investigation

🔎 IOC normalization

🧩 Threat correlation

🛡️ Reputation-oriented workflows


Threat intelligence is integrated into the investigation workflow rather than existing as an isolated lookup tool.


---

🎯 MITRE ATT&CK

SentinelSOC integrates MITRE ATT&CK concepts into its defensive investigation workflow.

SECURITY EVENT
      │
      ▼
NORMALIZED EVENT
      │
      ▼
BEHAVIOR / PATTERN
      │
      ▼
MITRE TECHNIQUE
      │
      ├── Technique ID
      ├── Technique Name
      ├── Tactic
      └── Context

Example techniques:

T1059
Command and Scripting Interpreter

T1082
System Information Discovery

T1049
System Network Connections Discovery

The purpose is to transform raw security observations into recognizable adversarial behavior categories.


---

🚨 ALERT ENGINE

SentinelSOC contains an event-oriented alert and risk workflow.

EVENT
  │
  ├── Timestamp
  ├── Type
  ├── Severity
  ├── Source
  ├── Context
  └── Security Fields
          │
          ▼
     RISK ENGINE
          │
          ├── INFO
          ├── LOW
          ├── MEDIUM
          ├── HIGH
          └── CRITICAL

The alert engine can feed subsequent IOC, MITRE, incident-response and reporting workflows.


---

📱 ANDROID / LOGCAT MONITORING

SentinelSOC includes Android/logcat-oriented security monitoring capabilities where the runtime environment permits them.

ANDROID LOGCAT
      │
      ▼
RAW EVENT STREAM
      │
      ▼
NORMALIZATION
      │
      ▼
SECURITY CLASSIFICATION
      │
      ├── SYSTEM EVENTS
      ├── PERMISSION EVENTS
      ├── SECURITY EVENTS
      ├── APPLICATION EVENTS
      └── OTHER EVENTS
      │
      ▼
RISK ENGINE
      │
      ▼
IOC / MITRE
      │
      ▼
ALERT

The monitoring layer is designed to separate useful security events from noisy platform output.


---

📜 LOG ANALYSIS

SentinelSOC provides defensive log-analysis capabilities.

Features

📜 SSH log parsing

🔐 Authentication-event analysis

❌ Failed-login detection

🚨 Suspicious-IP identification

🕒 Timeline generation

📡 Live log monitoring

🔎 Security-event filtering

🧠 Event classification

📊 Log-derived reporting


Log Workflow

LOG SOURCE
    │
    ▼
PARSER
    │
    ▼
NORMALIZER
    │
    ▼
CLASSIFIER
    │
    ▼
CORRELATION
    │
    ▼
ALERT / INVESTIGATION


---

🔍 DIGITAL FORENSICS

SentinelSOC provides a dedicated digital-forensics workflow.

Forensic capabilities

📄 File metadata extraction

🔐 SHA-256 hashing

🔑 MD5 hashing

🧬 File integrity verification

🖼️ EXIF analysis

🌐 Browser-artifact workflows

📁 Evidence discovery

🕒 Timeline generation

📦 File-type-aware analysis

🧾 Evidence inventory

🔎 Artifact investigation

📑 Forensic reporting


DFIR Flow

EVIDENCE SOURCE
      │
      ▼
COLLECTION
      │
      ▼
HASHING
      │
      ▼
METADATA
      │
      ▼
ARTIFACT ANALYSIS
      │
      ▼
TIMELINE
      │
      ▼
CORRELATION
      │
      ▼
FORENSIC REPORT


---

🚨 INCIDENT RESPONSE

SentinelSOC contains a dedicated incident-response subsystem.

╔══════════════════════════════════════════════════╗
║              INCIDENT RESPONSE                   ║
╠══════════════════════════════════════════════════╣
║  1  Live Incident Triage                         ║
║  2  Process Inventory                             ║
║  3  Network Connections                           ║
║  4  Listening Ports                               ║
║  5  Persistence Review                            ║
║  6  Suspicious Processes                          ║
║  7  IOC Sweep                                     ║
║  8  Create Incident Case                          ║
║  9  Collect Case Evidence                         ║
║ 10  Collect File Evidence                         ║
║ 11  Response Simulation                            ║
║ 12  Generate Incident Report                      ║
║ 13  Case List                                     ║
║ 14  Latest Case                                   ║
║ 15  SOC Live Watch                                ║
║ 16  Alert + MITRE Correlation                     ║
╚══════════════════════════════════════════════════╝

Incident Lifecycle

DETECTION
   │
   ▼
TRIAGE
   │
   ▼
CASE CREATION
   │
   ▼
EVIDENCE COLLECTION
   │
   ▼
ANALYSIS
   │
   ▼
CORRELATION
   │
   ▼
RESPONSE
   │
   ▼
REPORT
   │
   ▼
CASE HISTORY


---

📂 CASE MANAGEMENT

Incident cases provide structure around security investigations.

A typical case can connect:

CASE
 │
 ├── Incident metadata
 ├── Security events
 ├── IOC information
 ├── MITRE mappings
 ├── Process information
 ├── Network information
 ├── Evidence
 ├── Investigation notes
 └── Reports

This allows a security event to become a complete investigation rather than an isolated terminal message.


---

🧬 IOC ENGINE

The IOC layer can identify and organize security-relevant indicators such as:

🌐 IP addresses

🔗 URLs

🌍 Domains

🔐 Hashes

📦 Application/package identifiers

📁 Suspicious filesystem references

🧾 Security-related strings


Conceptually:

RAW EVENT
   │
   ▼
IOC EXTRACTION
   │
   ├── IP
   ├── URL
   ├── DOMAIN
   ├── HASH
   └── OTHER INDICATOR
         │
         ▼
   CORRELATION
         │
         ▼
   MITRE / ALERT / REPORT


---

📊 REPORTING ENGINE

SentinelSOC includes a dynamic reporting subsystem.

╔══════════════════════════════════════════════════╗
║                 REPORTING ENGINE                 ║
╠══════════════════════════════════════════════════╣
║  1  HTML Report                                  ║
║  2  PDF Report                                   ║
║  3  JSON Report                                  ║
║  4  CSV Report                                   ║
║  5  IAM Report                                   ║
║  6  Generate ALL Reports                         ║
║  7  Report History                               ║
║  8  Latest Report                                ║
║  9  Live Report Summary                          ║
╚══════════════════════════════════════════════════╝

Supported Formats

Format	Purpose

🌐 HTML	Human-readable security report
📄 PDF	Portable investigation report
🧾 JSON	Machine-readable security data
📊 CSV	Structured tabular analysis
👤 IAM	Identity/access-oriented reporting



---

📊 REPORTING ARCHITECTURE

flowchart TD

A["Live SentinelSOC State"]

A --> B["Process Inventory"]
A --> C["Network Inventory"]
A --> D["Listening Ports"]
A --> E["Persistence"]
A --> F["Security Events"]
A --> G["IOC Inventory"]
A --> H["Incident Cases"]
A --> I["MITRE Correlation"]

B --> J["Report Builder"]
C --> J
D --> J
E --> J
F --> J
G --> J
H --> J
I --> J

J --> K["HTML"]
J --> L["PDF"]
J --> M["JSON"]
J --> N["CSV"]
J --> O["IAM"]


---

👤 IAM REPORTING

The IAM-oriented reporting layer can summarize identity and access-related information exposed by the runtime environment.

This provides an additional perspective for:

account visibility

identity-oriented review

access-related analysis

privileged-access awareness

security reporting



---

⚙️ SETTINGS CONTROL CENTER

SentinelSOC includes a persistent dynamic Settings module.

╔══════════════════════════════════════════════════╗
║          SENTINELSOC CONTROL CENTER             ║
╠══════════════════════════════════════════════════╣
║  1  Appearance & Animation                       ║
║  2  Monitoring & Collection                      ║
║  3  Reporting Engine                             ║
║  4  Logging & Audit                              ║
║  5  Privacy & Data Protection                    ║
║  6  Security & Safety                            ║
║  7  Live Configuration                           ║
║  8  Live System Information                      ║
║  9  Reset Configuration                           ║
║  0  Back                                         ║
╚══════════════════════════════════════════════════╝

Configuration Features

🎨 Theme selection

✨ Animation control

⚡ Performance mode

🔄 Monitoring intervals

📊 Reporting defaults

📝 Logging level

🔐 Privacy controls

🛡️ Safety controls

🔔 Notification controls

📁 Evidence locations

🖥️ Runtime information

💾 Persistent configuration



---

🦸 ABOUT // SENTINEL UNIVERSE

SentinelSOC includes a comic-inspired About dossier designed to make security concepts memorable.

Fictional threat archetypes

Archetype	Security Concept

🦹 Dr. Doom	Sophisticated threat actor
🤖 Ultron	Automation / autonomous adversary
🌀 Loki	Deception / defense evasion
☠️ Thanos	High-impact destructive activity
🐍 Hydra	Persistent coordinated threat network


These are fictional storytelling metaphors for real security concepts such as:

persistence

privilege escalation

credential access

command execution

defense evasion

lateral movement

command-and-control

impact



---

🛡️ THE SENTINEL PHILOSOPHY

SentinelSOC is built around several principles.

01 — REAL TELEMETRY

Where possible, security information should originate from the actual runtime environment rather than fabricated demonstrations.

02 — MODULAR DESIGN

Each major security capability is separated into a dedicated module.

03 — CORRELATION

A raw event becomes more valuable when connected to:

EVENT
 +
SEVERITY
 +
RISK
 +
IOC
 +
MITRE
 +
INCIDENT
 +
EVIDENCE

04 — PORTABILITY

The toolkit is designed to work across Linux and Termux environments where supported.

05 — DEFENSIVE FIRST

The primary focus is:

MONITOR
INVESTIGATE
DETECT
RESPOND
PRESERVE
REPORT


---

🧱 TECHNOLOGY STACK

Technology	Purpose

🐍 Python	Core application
🐧 Linux	Primary platform
📱 Termux	Portable environment
🎨 Rich	Terminal UI
🌐 Requests	HTTP/API integration
⚙️ Psutil	System/process monitoring
🔍 Nmap	Network scanning
🗃️ SQLite	Local persistence
📝 Git	Version control
☁️ GitHub	Source repository
🎯 MITRE ATT&CK	Adversary behavior correlation


Some modules depend on operating-system capabilities, installed tools, permissions and API availability.


---

🗂️ PROJECT STRUCTURE

SentinelSOC/
│
├── assets/
│   ├── config/
│   ├── mitre/
│   ├── incident_response/
│   └── reports/
│
├── core/
│   ├── router.py
│   ├── MITRE components
│   ├── parsers
│   └── core utilities
│
├── modules/
│   ├── android_logcat.py
│   ├── alert_engine.py
│   ├── digital_forensics.py
│   ├── event_store.py
│   ├── incident_response.py
│   ├── ioc_engine.py
│   ├── log_analysis.py
│   ├── mitre_attack.py
│   ├── network modules
│   ├── reporting.py
│   ├── settings.py
│   └── about.py
│
├── reports/
├── tests/
├── main.py
├── requirements.txt
├── LICENSE
└── README.md


---

🚀 INSTALLATION

🐧 Linux

git clone https://github.com/heysayanallgood/SentinelSOC.git
cd SentinelSOC

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python main.py


---

📱 TERMUX

pkg update
pkg upgrade

pkg install python git

git clone https://github.com/heysayanallgood/SentinelSOC.git
cd SentinelSOC

pip install -r requirements.txt

python main.py

Some security-monitoring and forensic functionality depends on Android permissions and available system interfaces.


---

🎮 FIRST LAUNCH

Start SentinelSOC with:

python main.py

Then enter the command deck.

1 → Dashboard
2 → Network Analysis
3 → Threat Intelligence
4 → Log Analysis
5 → Digital Forensics
6 → Incident Response
7 → Reporting
8 → Settings
9 → About
0 → Exit


---

🔬 EXAMPLE DEFENSIVE INVESTIGATION

SECURITY EVENT
                           │
          