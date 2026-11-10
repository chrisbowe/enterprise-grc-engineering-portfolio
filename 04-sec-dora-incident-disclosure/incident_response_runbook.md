# Enterprise Regulatory Cyber Incident Response Runbook

## Protocol: SEC Form 8-K (Item 1.05), EU DORA, and NIS2 Incident Triage

### 🏛️ Regulatory Regime Applicability
Not all regimes apply to every incident or organization. Assess jurisdiction and scope during initial triage:
* **U.S. SEC Form 8-K (Item 1.05):** Applies to public reporting companies (registrants) subject to the Securities Exchange Act of 1934.
* **EU DORA (Regulation (EU) 2022/2554 & RTS (EU) 2025/301):** Sector-specific regime applying to regulated EU financial entities (credit institutions, investment firms, payment providers, etc.) and their critical ICT third-party service providers.
* **EU NIS2 Directive (Directive (EU) 2022/2555):** Applies to essential and important entities across covered sectors (energy, transport, healthcare, digital infrastructure, etc.). For financial entities in scope of DORA, DORA governs incident reporting as *lex specialis*.

---

### 1. Incident Detection & Containment (Hour 0 - Hour 4)
* **Lead:** SOC Incident Commander & Principal Security Engineer
* **Actions:**
  1. Isolate compromised compute/IAM sessions and revoke impacted credentials.
  2. Snapshot volatile memory, forensic disks, and audit trail buckets.
  3. Establish an out-of-band communication bridge (Signal / dedicated emergency channel).
  4. Initiate automated evidence preservation protocol.
  5. **Timestamp Recording:** 
     * Formally record technical `discovery_time` (triggers the SEC requirement to reach a materiality determination "without unreasonable delay").
     * Formally record `awareness_time`. *(Note on regime differences: DORA's 24-hour outer limit runs from awareness of the ICT-related incident itself; NIS2 Art. 23(4)(a) early warning runs from awareness that the incident is significant. In the screening aid, `awareness_time` is used conservatively for both; in operational response, log both initial detection and the moment significance is recognized).*

### 2. Regulatory Triage & Screening Working Group (Hour 4 - Hour 12)
* **Attendees:** CISO, General Counsel (Legal), Chief Financial Officer (CFO), Head of GRC, Disclosure Committee Chair.
* **Objective:** Run `materiality_calculator.py` to evaluate incident facts and support counsel and executive decision-making.
* **Parallel Assessment Tracks:**
  * **Track A — SEC Materiality Determination (Item 1.05):**
    * *Quantitative Impact:* Direct revenue loss + incident response costs (forensics, remediation, legal counsel, customer notification, PR) compared against corporate screening baselines (e.g. 0.5% annual revenue; this threshold is an internal company heuristic, not an SEC-mandated statutory safe harbor). Reputational harm is evaluated qualitatively under SEC factors, not modeled as a speculative cost multiplier.
    * *Qualitative Factors:* Evaluated strictly against the four qualitative factors named in SEC Adopting Release 33-11216:
      1. `reputational_harm` (harm to brand standing or public trust)
      2. `customer_or_vendor_relationship_harm` (contractual default, customer loss, partner churn)
      3. `competitive_harm` (exfiltration of source code, trade secrets, strategic roadmap)
      4. `litigation_or_regulatory_action` (potential class actions, regulatory investigations, statutory fines)
    * *Timing Requirement:* Materiality determination must be reached without unreasonable delay following discovery. Elapsed time between discovery and determination is tracked for legal counsel review.
  * **Track B — EU DORA Major Incident Classification (RTS (EU) 2024/1772):**
    * Evaluated independently of SEC materiality against DORA criteria (clients/transactions affected, duration, data loss, geographic spread, criticality of services, economic impact).
  * **Track C — EU NIS2 Significance Assessment (Directive (EU) 2022/2555 Art. 23):**
    * Evaluated against national implementing criteria for in-scope essential and important entities (financial entities subject to DORA follow DORA as *lex specialis*).

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
* **Internal Governance Target:** Immediate (< 12 hours from Materiality Determination or Major Incident Classification).
* **Briefing Pack:**
  1. Executive Summary & root-cause forensic timeline.
  2. Blast radius (impacted records, customer systems, critical services, and geographies).
  3. FAIR quantitative financial loss exposure estimate ($ ALE / P90 tail risk).
  4. Status of SEC Form 8-K draft and external legal counsel concurrence.

---

> **Disclaimer:** *This runbook is an operational reference guide for cross-functional incident response and triage. It does not constitute formal legal advice or legal determination. All regulatory filings and materiality determinations must be coordinated with and approved by corporate legal counsel and the Disclosure Committee.*
