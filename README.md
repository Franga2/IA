# GDPR Cross-Border Data Transfer Validator

A production-grade Python tool for auditing cross-border data flows against **GDPR Chapter V (Arts. 44–50)**, built as a response to the [Yuno Engineering Challenge](https://yuno-challenge.vercel.app/challenge/cmmmqjmvl0004lnjswx8qfrew).

---

## What It Does

Given a JSON/YAML description of a system architecture (services, vendors, and data flows), this tool automatically:

1. **Detects cross-border transfers** — identifies which flows originate in the EU/EEA and reach a third country.
2. **Validates legal basis** — checks whether each transfer has a valid GDPR Chapter V mechanism (adequacy decision, SCC, BCR, derogation, etc.).
3. **Flags TIA requirements** — post-*Schrems II*, transfers to high-risk jurisdictions (US, China, Russia) require a Transfer Impact Assessment.
4. **Generates an Article 30 inventory** — produces a Record of Processing Activities (RoPA) for each cross-border transfer.
5. **Analyzes data minimization** — identifies data categories shared with an excessive number of recipients.
6. **Detects GDPR/PCI DSS conflicts** — surfaces tensions between GDPR data minimization/deletion rights and PCI DSS retention requirements.
7. **Produces audit-ready reports** — HTML (human-readable) and JSON (machine-readable) outputs.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a full audit
python -m gdpr_validator validate --input data/yuno_architecture.json --format all --output reports/

# List cross-border flows only
python -m gdpr_validator list-flows --input data/yuno_architecture.json --cross-border-only

# Check a country's adequacy status
python -m gdpr_validator check-country US
python -m gdpr_validator check-country JP
```

---

## Project Structure

```
gdpr-validator-yuno/
├── data/
│   └── yuno_architecture.json      # Sample architecture: 10 services, 20 flows, 8 vendors
├── gdpr_validator/
│   ├── __init__.py
│   ├── __main__.py                 # Entry point for python -m gdpr_validator
│   ├── models.py                   # Dataclasses: Service, DataFlow, Finding, etc.
│   ├── validator.py                # Core GDPR engine + ArchitectureLoader
│   ├── reporter.py                 # HTML, JSON, and console reporters
│   └── cli.py                     # Click-based CLI
├── tests/
│   └── test_validator.py          # 37 unit tests (pytest)
├── reports/                        # Generated audit reports (git-ignored)
├── requirements.txt
├── setup.py
└── README.md
```

---

## Sample Architecture

The included `data/yuno_architecture.json` models a realistic payment platform:

| Service | Country | Role |
|---|---|---|
| `payment-api-eu` | Ireland | Controller — EU payment gateway |
| `fraud-detection-service` | United States | Processor — ML fraud scoring |
| `payment-api-latam` | Brazil | Processor — LatAm gateway |
| `payment-api-apac` | Singapore | Processor — APAC gateway |
| `kyc-verification-service` | Ireland | Controller — identity verification |
| `analytics-platform` | Ireland | Controller — business analytics |
| `notification-service` | Ireland | Processor — comms dispatch |
| `audit-log-service` | Ireland | Controller — compliance logging |
| `data-warehouse` | Netherlands | Processor — EU data lake |
| `admin-portal` | Ireland | Internal — ops dashboard |

**Third-party vendors:** Stripe (US), dLocal (Brazil), Xendit (Singapore), Adyen (UK), Tableau (US), SendGrid (US), Twilio (US), SumSub (US), Splunk (US), Datadog (US).

---

## Compliance Reasoning

### 1. Cross-Border Detection (Art. 44)

A transfer is classified as **cross-border** if and only if:
- The **origin service** is located in an EU/EEA country (including Iceland, Liechtenstein, Norway), **and**
- The **destination** (service or vendor) is located **outside** the EU/EEA.

Intra-EEA flows (e.g., Ireland → Netherlands) are marked `NOT_APPLICABLE` for Chapter V — they are subject to GDPR but not to the transfer restrictions.

> **Legal basis:** GDPR Art. 44 — "Any transfer of personal data to a third country or an international organisation shall take place only if [...] the conditions laid down in this Chapter are complied with."

### 2. Adequacy Decisions (Art. 45)

Countries with a **valid adequacy decision** as of February 2026:

| Country | Notes |
|---|---|
| Andorra | |
| Argentina | |
| Brazil | LGPD adequacy (2023) |
| Canada | PIPEDA — commercial transfers only |
| Faroe Islands | |
| Guernsey | |
| Israel | |
| Isle of Man | |
| Japan | Mutual recognition with APPI |
| Jersey | |
| New Zealand | |
| Republic of Korea | |
| Switzerland | Updated 2023 |
| United Kingdom | Post-Brexit adequacy |
| Uruguay | |

Transfers to these countries are **compliant without additional safeguards**, though the tool still recommends monitoring for adequacy revocations.

### 3. Standard Contractual Clauses (Art. 46(2)(c))

SCCs are the most common mechanism for transfers to non-adequate countries (e.g., US, Singapore, India). The tool validates:

- **Version:** Only the 2021 EU SCCs (Commission Decision 2021/914) are accepted. Pre-2021 SCCs are flagged as deprecated.
- **TIA requirement:** Post-*Schrems II* (CJEU C-311/18, July 2020), SCCs alone are insufficient for transfers to high-risk jurisdictions. A **Transfer Impact Assessment** must document whether the destination country's legal framework undermines the SCC protections.
- **Supplementary measures:** For US transfers, EDPB Recommendations 01/2020 require additional technical measures (end-to-end encryption, pseudonymization) if the TIA reveals problematic government access laws (e.g., FISA 702, EO 12333).

### 4. Transfer Impact Assessment (TIA) — Post-Schrems II

The tool automatically flags TIA requirements for:

- **High-risk jurisdictions:** United States, China, Russia, India (surveillance legislation with broad government access).
- **Sensitive data categories:** Biometric data, health data, financial data — regardless of destination.

A TIA must assess:
1. The destination country's legal framework (surveillance laws, rule of law index).
2. Whether the chosen safeguard (SCC, BCR) is effectively enforceable.
3. Whether supplementary measures (encryption, access controls) can fill any gaps.

> **Legal basis:** CJEU C-311/18 (*Schrems II*), July 2020; EDPB Recommendations 01/2020 on supplementary measures.

### 5. Derogations (Art. 49)

The tool evaluates Art. 49(1)(b) necessity derogations using EDPB guidance:

- **Valid:** Per-transaction flows (`per_transaction`, `per_onboarding`, `per_event`) — each individual transfer is necessary for a specific contract.
- **Invalid:** Continuous or batch flows — derogations must be "occasional and non-repetitive." Systematic transfers require SCCs or BCRs.

### 6. Data Minimization (Art. 5(1)(c))

The tool identifies **minimization concerns** when a data category is shared with an excessive number of recipients:

- **High concern (≥ 5 recipients):** Severity MEDIUM — review whether all recipients genuinely need the data.
- **Very high concern (≥ 8 recipients):** Severity HIGH — strong recommendation to implement data partitioning.

### 7. GDPR / PCI DSS Conflicts

Payment processors face a structural tension between:

- **GDPR Art. 17** (right to erasure) and **Art. 5(1)(e)** (storage limitation) — data must be deleted when no longer necessary.
- **PCI DSS Requirement 10.7** — audit logs must be retained for at least 12 months (3 months immediately available).
- **PCI DSS Requirement 3.2** — cardholder data must be retained for the period needed to complete the transaction.

The tool flags flows involving `transaction_data`, `cardholder_data`, or `audit_logs` to third-party processors in non-adequate countries, recommending:
1. A documented legal basis for retention (e.g., legal obligation under Art. 6(1)(c)).
2. Contractual clauses in the DPA specifying the retention period and deletion schedule.
3. Legal review to confirm that the PCI retention period satisfies the GDPR storage limitation principle.

---

## Sample Output

```
======================================================================
  GDPR CROSS-BORDER TRANSFER AUDIT — Yuno Payments
======================================================================
  Generated: 2026-03-12T21:21:48Z
  SUMMARY
  Total flows:          20
  Cross-border:         17
  Compliant:             8
  TIA Required:          7
  Non-Compliant:         2
  Total Findings:       13
  Critical Findings:     2 ⚠️

  ❌ NON-COMPLIANT FLOWS
    • flow-003: payment-api-eu → payment-api-apac (Singapore)
      CRITICAL: MISSING_LEGAL_BASIS
    • flow-006: payment-api-eu → XenditSEA (Singapore)
      CRITICAL: MISSING_LEGAL_BASIS

  ⚠️  TIA REQUIRED
    • flow-001: payment-api-eu → fraud-detection-service (United States)
    • flow-011: analytics-platform → TableauUS (United States)
    • flow-013: notification-service → SendGridUS (United States)
    • flow-014: notification-service → TwilioUS (United States)
    • flow-015: kyc-verification-service → SumSubVerification (United States)
    • flow-017: audit-log-service → SplunkUS (United States)
    • flow-020: payment-api-eu → DatadogUS (United States)

  ⚡ COMPLIANCE CONFLICTS: 2 (GDPR vs PCI DSS)
    • flow-001: payment-api-eu → fraud-detection-service
    • flow-017: audit-log-service → SplunkUS
======================================================================
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

**37 tests** covering:
- Cross-border detection (EEA/non-EEA, edge cases)
- Legal basis validation (SCC, BCR, adequacy, missing)
- TIA requirement detection (high-risk jurisdictions, sensitive data)
- Adequacy decision lookup (17 countries)
- Derogation validity (per-transaction vs. continuous)
- Full pipeline end-to-end (real architecture file)
- JSON report structure and consistency
- Edge cases (empty flows, unknown services, intra-EEA)

---

## CLI Reference

```
Commands:
  validate      Run full GDPR audit on an architecture file.
  list-flows    List all data flows (optionally filter cross-border only).
  check-country Show GDPR transfer status for a specific country.

Options (validate):
  --input    PATH    Input JSON/YAML architecture file [required]
  --format   TEXT    Output format: console, json, html, all [default: console]
  --output   DIR     Output directory for reports [default: ./reports]
  --org      TEXT    Override organization name
  --verbose          Show detailed findings for each flow
```

---

## Input Format

```json
{
  "organization": {
    "name": "Yuno Payments",
    "country": "Ireland",
    "dpo_contact": "dpo@yuno.com"
  },
  "services": [
    {
      "name": "payment-api-eu",
      "display_name": "EU Payment API",
      "region": "eu-west-1",
      "country": "Ireland",
      "cloud_provider": "AWS",
      "data_categories": ["contact_details", "transaction_data"],
      "data_subjects": ["customers", "merchants"],
      "purpose": "Payment processing and routing",
      "retention_period": "5 years (PCI DSS)",
      "legal_basis_processing": "contract",
      "is_controller": true
    }
  ],
  "third_party_vendors": [
    {
      "name": "StripeUS",
      "country": "United States",
      "purpose": "Payment processing",
      "data_categories": ["contact_details", "transaction_data"],
      "legal_basis": "SCC",
      "dpf_certified": true,
      "processor_agreement": true
    }
  ],
  "data_flows": [
    {
      "id": "flow-001",
      "from": "payment-api-eu",
      "to": "StripeUS",
      "to_country": "United States",
      "data_categories": ["contact_details", "transaction_data"],
      "purpose": "Payment processing",
      "legal_basis": "SCC",
      "tia_conducted": true,
      "volume": "high",
      "frequency": "continuous"
    }
  ]
}
```

---

## Design Decisions & Compliance Reasoning

This section addresses the interpretive choices made when translating ambiguous GDPR requirements into automated logic.

### 1. The Necessity Derogation Dilemma (Art. 49)

This is the most contested area of Chapter V. Art. 49(1)(b) permits transfers "necessary for the performance of a contract" without additional safeguards. The ambiguity: payment processors routinely send transaction data to US vendors in real-time — is each individual transfer "necessary for the contract"?

**EDPB's position (Opinion 1/2018, Rec. 01/2020 §111-116):** Art. 49 derogations are *residual exceptions*, not general authorizations. They must be:
- **Occasional** — not systematic or repetitive
- **Necessary** — not merely useful or convenient
- **Proportionate** — limited to what is strictly required

**Our decision:** We distinguish by transfer frequency:
- `per_transaction`, `per_onboarding`, `per_event` → Accept as Art. 49 derogation (each transfer is tied to a specific contract performance)
- `continuous`, `batch`, `real-time` → Reject Art. 49 and flag as requiring SCC/BCR

**Why this matters for Yuno:** A payment gateway sending transaction data to Stripe continuously cannot rely on Art. 49 — this is a systematic transfer that requires SCCs. The EDPB explicitly rejected the argument that each individual payment constitutes a separate "contract performance" when the underlying relationship is a continuous service agreement.

**Assumption documented:** We treat frequency as the primary indicator of "occasional." Volume (>10,000 records/month) is a secondary signal. Both thresholds are operational interpretations, not legal bright lines — they should be reviewed by legal counsel for each specific deployment.

### 2. Schrems II and the Limits of SCCs

The CJEU's *Schrems II* ruling (C-311/18, July 2020) established that SCCs are valid *in principle* but require a case-by-case Transfer Impact Assessment (TIA) to verify that the destination country's laws do not undermine the SCC protections in practice.

**Our implementation:** We require a TIA for all transfers to countries with broad government surveillance laws (US FISA 702/EO 12333, China NSL, Russia SORM). A missing TIA generates a `HIGH` finding; a TIA older than 24 months generates a `MEDIUM` finding (EDPB recommends periodic review).

**The EU-US DPF complication:** The Data Privacy Framework (July 2023) restored adequacy for DPF-certified US entities. We do *not* treat all US transfers as adequate — only those with explicit `dpf_certified: true`. Rationale: (1) DPF coverage is entity-specific, not country-wide; (2) Schrems III litigation is ongoing and the DPF's durability is uncertain; (3) conservative compliance posture is appropriate for a payment processor handling sensitive financial data.

### 3. When to Escalate vs. Auto-Determine

We use `REQUIRES_LEGAL_REVIEW` (distinct from `NON_COMPLIANT`) for genuinely ambiguous cases:
- Art. 49 derogation claimed for non-occasional transfers (human judgment needed on "necessity")
- GDPR/PCI DSS conflicts (resolution depends on specific retention policies and legal obligations)
- Sensitive data (Art. 9) with unclear legal basis

**Philosophy:** Automated tools that treat all compliance as binary create false confidence. The DPC doesn't want a tool that says "compliant" when the correct answer is "it depends on your specific retention policy and DPA clauses." We prefer surfacing ambiguity over auto-determining compliance in contested areas.

### 4. GDPR vs. PCI DSS Structural Conflict

Payment processors face a genuine tension that cannot be resolved by automation alone:

| Requirement | GDPR | PCI DSS |
|---|---|---|
| Log retention | Delete when no longer necessary (Art. 5(1)(e)) | 12 months minimum (Req. 10.7) |
| Transaction data | Purpose limitation (Art. 5(1)(b)) | Retain for fraud investigation (Req. 3.2) |
| Cardholder data | Erasure right (Art. 17) | Cannot delete if needed for dispute resolution |

We flag these conflicts as `requires_legal_review: true` rather than marking flows as non-compliant. The resolution requires: (1) a documented legal obligation basis under Art. 6(1)(c) for PCI retention; (2) contractual clauses in the DPA specifying the retention period; (3) legal review to confirm the PCI period satisfies GDPR's storage limitation principle.

### 5. Pre-2021 SCCs

The transition period for old SCCs ended **December 27, 2022**. Any transfer still using pre-2021 SCCs has been unlawful for over 3 years. We treat this as `CRITICAL` — not `HIGH` — because it is not an ambiguous case: the Commission's decision is unambiguous, and the deadline has long passed.

### 6. Assumptions and Scope Limitations

| Assumption | Rationale |
|---|---|
| `to_country` is authoritative for destination | We cannot infer server location from service name |
| EEA = EU + IS + LI + NO | Standard GDPR scope |
| TIA threshold: US, CN, RU, IN | EDPB Rec. 01/2020 Step 3 country assessment |
| Minimization threshold: >3 recipients = concern | Operational interpretation; not a legal bright line |
| DPF requires explicit certification flag | Conservative posture given ongoing litigation |
| Art. 49 "occasional" = non-continuous frequency | EDPB Opinion 1/2018 interpretation |

---

## Legal References


| Reference | Description |
|---|---|
| GDPR Art. 44 | General principle for transfers to third countries |
| GDPR Art. 45 | Transfers based on adequacy decisions |
| GDPR Art. 46 | Transfers subject to appropriate safeguards (SCC, BCR) |
| GDPR Art. 47 | Binding Corporate Rules |
| GDPR Art. 49 | Derogations for specific situations |
| CJEU C-311/18 | *Schrems II* — invalidated Privacy Shield, conditioned SCCs |
| EDPB Rec. 01/2020 | Supplementary measures for transfers post-Schrems II |
| Commission Decision 2021/914 | Standard Contractual Clauses (2021 version) |
| PCI DSS v4.0 Req. 10.7 | Audit log retention requirements |

---

## License

MIT — see [LICENSE](LICENSE) for details.
