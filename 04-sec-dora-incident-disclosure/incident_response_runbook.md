# Enterprise Regulatory Cyber Incident Response Runbook

## Protocol: SEC Form 8-K (Item 1.05), EU DORA, and NIS2 Incident Triage

### 1. Incident Detection & Containment (Hour 0 - Hour 4)
* **Lead:** SOC Incident Commander & Principal Security Engineer
* **Actions:**
  1. Isolate compromised compute/IAM sessions and revoke impacted credentials.
  2. Snapshot volatile memory, forensic disks, and audit trail buckets.
  3. Establish an out-of-band communication bridge (Signal / dedicated emergency channel).
  4. Initiate automated evidence preservation protocol.
  5. **Timestamp Recording:** Formally record technical `discovery_time` (triggers SEC requirement to reach materiality determination "without unreasonable delay") and `awareness_time` (triggers DORA 24-hour outer limit and NIS2 early warning clocks).

### 2. Regulatory Triage & Screening Working Group (Hour 4 - Hour 12)
* **Attendees:** CISO, General Counsel (Legal), Chief Financial Officer (CFO), Head of GRC, Disclosure Committee Chair.
* **Objective:** Run `materiality_calculator.py` to evaluate incident facts and support counsel and executive decision-making.
* **Parallel Assessment Tracks:**
  * **Track A — SEC Materiality Determination (Item 1.05):**
    * *Quantitative Impact:* Direct revenue loss + response costs (forensics, remediation, legal counsel, customer notification, PR) compared against baseline materiality thresholds (e.g. 0.5% annual revenue). No speculative reputation multipliers.
    * *Qualitative Factors:* Core customer-facing infrastructure offline, sensitive customer PII or intellectual property exfiltrated, systemic financial contagion risks.
    * *Timing Requirement:* Determination must be made without unreasonable delay; elapsed time between discovery and determination is tracked for legal review.
  * **Track B — EU DORA Major Incident Classification (RTS (EU) 2024/1772):**
    * Assessed independently of SEC materiality against DORA criteria (clients/transactions affected, duration, data loss, geographic spread, criticality of services, economic impact).
  * **Track C — EU NIS2 Significance Assessment (Directive (EU) 2022/2555 Art. 23):**
    * Assessed against national implementing criteria for in-scope essential and important entities (financial entities subject to DORA follow DORA as *lex specialis*).

### 3. Regulatory Notification Timelines & Clocks

```
                      [Incident Discovered / Entity Aware]
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
 [U.S. SEC Item 1.05]         [EU DORA RTS Art. 5]          [EU NIS2 Art. 23]
  Determination required       Awareness starts 24h outer    Awareness of significance
  without unreasonable delay   limit for initial alert       starts 24h early warning
        │                              │                              │
        ▼                              ▼                              ▼
 [Materiality Determined]     [Classified Major]            [Assessed Significant]
  File Form 8-K within         Initial notification:         • Early warning: < 24h
  4 business days (in ET,      min(4h from classification,   • Incident notice: < 72h
  skipping federal holidays)   24h from awareness)*          • Final report: < 1 month
                               • Intermediate: < 72h
                               • Final report: < 1 month
```

*\*Note: Under DORA RTS (EU) 2025/301 Art. 5, if major classification occurs after 24h of awareness, initial notification is due within 4h of classification. Weekend and bank-holiday relief under Art. 5(4)–(6) is unmodeled in internal tooling and unavailable to excluded entities under Art. 5(5).*

### 4. Board Communication & Governance
* **Notification Window:** Immediate (< 12 hours from Materiality Determination or Major Incident Classification).
* **Briefing Pack:**
  1. Executive Summary & root-cause forensic timeline.
  2. Blast radius (impacted records, customer systems, critical services, and geographies).
  3. FAIR quantitative financial loss exposure estimate ($ ALE / P90 tail risk).
  4. Status of SEC Form 8-K draft and external legal counsel concurrence.

---

> **Disclaimer:** *This runbook is an operational reference guide for cross-functional incident response and triage. It does not constitute formal legal advice or legal determination. All regulatory filings and materiality determinations must be coordinated with and approved by corporate legal counsel and the Disclosure Committee.*
