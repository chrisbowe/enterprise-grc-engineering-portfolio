# Enterprise Regulatory Cyber Incident Response Runbook

## Protocol: SEC Form 8-K (Item 1.05) & EU DORA Incident Triage

### 1. Incident Detection & Containment (Hour 0 - Hour 4)
* **Lead:** SOC Incident Commander & Principal Security Engineer
* **Actions:**
  1. Isolate compromised compute/IAM sessions.
  2. Snapshot volatile memory, forensic disks, and audit trail buckets.
  3. Establish an out-of-band communication bridge (Signal / dedicated emergency channel).
  4. Initiate automated evidence preservation protocol.

### 2. Materiality Assessment Working Group (Hour 4 - Hour 12)
* **Attendees:** CISO, General Counsel (Legal), Chief Financial Officer (CFO), Head of GRC.
* **Objective:** Run `materiality_calculator.py` to determine quantitative and qualitative materiality.
* **Evaluation Criteria:**
  * **Quantitative:** Does the total projected financial impact (direct loss + legal/forensics + customer churn) exceed 0.5% of annual revenue?
  * **Qualitative:** Is critical customer-facing infrastructure offline? Was sensitive customer PII or intellectual property exfiltrated? Is there potential for systemic financial sector contagion?

### 3. Regulatory Notification Timelines
```
[Incident Occurs] ──> [Detection] ──> [MATERIALITY DETERMINED]
                                                │
       ┌────────────────────────────────────────┴────────────────────────────────────────┐
       ▼                                                                                 ▼
[EU DORA / NIS2 Initial Notification]                                      [SEC Form 8-K Filing]
  • Initial Alert: < 24 Hours                                                • Must file within 4 business days
  • Intermediate Report: < 72 Hours                                            of materiality determination
  • Final Assessment: < 1 Month                                              • Item 1.05 disclosure details
```

### 4. Board Communication
* **Notification Window:** Immediate (< 12 hours from Materiality Determination).
* **Briefing Pack:**
  1. Executive Summary & root-cause timeline.
  2. Blast radius (impacted records, systems, and geographies).
  3. FAIR financial risk exposure estimate.
  4. Status of SEC Form 8-K draft and external legal counsel concurrence.
