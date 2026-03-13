"""
GDPR Cross-Border Transfer Validator — Core Engine

This module implements the compliance logic for validating data flows
under GDPR Chapter V (Articles 44-50). It handles:
  - Adequacy decision lookup (as of 2024)
  - Legal basis validation (SCCs, derogations, adequacy)
  - TIA requirement detection
  - Data minimization analysis
  - PCI DSS / GDPR conflict detection

Design Decisions:
  1. The "necessity" derogation (Art. 49(1)(b)) is treated as COMPLIANT_TIA_REQUIRED
     for individual transactions, but flagged with a HIGH finding when used for
     continuous/batch flows — reflecting EDPB guidance that derogations must be
     "occasional and non-repetitive."
  2. Missing legal basis → NON_COMPLIANT (Critical), not "incomplete data."
     Rationale: under GDPR, absence of documented legal basis IS a violation.
  3. US transfers with SCC but no TIA → COMPLIANT_TIA_REQUIRED (not NON_COMPLIANT),
     because SCCs remain a valid mechanism post-Schrems II when supplemented by TIA.
  4. Intra-EU/EEA flows are NOT cross-border transfers and are marked NOT_APPLICABLE.
  5. "Excessive" recipients for data minimization: >4 third parties receiving the
     same data category (Art. 5(1)(c) "limited to what is necessary").
"""

from datetime import datetime
from typing import Dict, List, Optional, Set

from .models import (
    Article30Entry,
    ComplianceConflict,
    ComplianceStatus,
    DataFlow,
    Finding,
    FindingType,
    MinimizationConcern,
    Severity,
    Service,
    ThirdPartyVendor,
    TransferValidationResult,
    ValidationReport,
)

# ─────────────────────────────────────────────────────────────────────────────
# GDPR Knowledge Base
# ─────────────────────────────────────────────────────────────────────────────

# EU/EEA countries — transfers within this set are NOT cross-border under GDPR
EEA_COUNTRIES: Set[str] = {
    "Austria", "Belgium", "Bulgaria", "Croatia", "Cyprus", "Czech Republic",
    "Denmark", "Estonia", "Finland", "France", "Germany", "Greece", "Hungary",
    "Iceland", "Ireland", "Italy", "Latvia", "Liechtenstein", "Lithuania",
    "Luxembourg", "Malta", "Netherlands", "Norway", "Poland", "Portugal",
    "Romania", "Slovakia", "Slovenia", "Spain", "Sweden",
}

# EU Commission adequacy decisions as of 2024 (Art. 45 GDPR)
# Source: https://commission.europa.eu/law/law-topic/data-protection/
ADEQUACY_COUNTRIES: Set[str] = {
    "Andorra", "Argentina", "Canada", "Faroe Islands", "Guernsey",
    "Isle of Man", "Israel", "Japan", "Jersey", "New Zealand",
    "South Korea", "Switzerland", "United Kingdom", "Uruguay",
    # Note: US does NOT have blanket adequacy. Only DPF-certified orgs qualify.
    # Brazil: adequacy decision granted Feb 2025 (included per latest guidance)
    "Brazil",
}

# Countries requiring TIA due to high surveillance risk (post-Schrems II)
# Heuristic: US surveillance laws (FISA 702, EO 12333), China (NSL), Russia (SORM)
HIGH_RISK_JURISDICTIONS: Set[str] = {
    "United States", "China", "Russia", "Belarus", "Iran",
    "North Korea", "Saudi Arabia", "United Arab Emirates",
}

# Data categories classified as "sensitive" requiring extra scrutiny
SENSITIVE_DATA_CATEGORIES: Set[str] = {
    "biometric_data", "health_data", "genetic_data", "racial_ethnic_data",
    "political_opinions", "religious_beliefs", "trade_union_membership",
    "sexual_orientation", "criminal_records", "identity_documents",
}

# Legal bases that are valid for cross-border transfers (Art. 44-49)
VALID_TRANSFER_LEGAL_BASES: Set[str] = {
    "adequacy_decision",   # Art. 45
    "SCC",                 # Art. 46(2)(c) - Standard Contractual Clauses
    "BCR",                 # Art. 46(2)(b) - Binding Corporate Rules
    "approved_code",       # Art. 46(2)(e) - Approved code of conduct
    "certification",       # Art. 46(2)(f) - Approved certification
    "necessity_contract",  # Art. 49(1)(b) - Necessary for contract performance (derogation)
    "explicit_consent",    # Art. 49(1)(a) - Explicit consent (derogation)
    "legal_claims",        # Art. 49(1)(e) - Legal claims
    "vital_interests",     # Art. 49(1)(f) - Vital interests
    "public_interest",     # Art. 49(1)(d) - Public interest
}

# PCI DSS requirements that conflict with GDPR minimization
PCI_DSS_REQUIREMENTS: Dict[str, str] = {
    "audit_logging": "PCI DSS Req. 10 — Log all access to system components and cardholder data",
    "fraud_monitoring": "PCI DSS Req. 10.6 — Review logs daily for anomalies",
    "data_retention": "PCI DSS Req. 3.4 — Retain transaction data for audit purposes",
}

# Threshold for "excessive" recipients (data minimization heuristic)
EXCESSIVE_RECIPIENTS_THRESHOLD = 4

# Indefinite retention keywords
INDEFINITE_RETENTION_KEYWORDS = {"indefinite", "unlimited", "forever", "no limit", "permanent"}


# ─────────────────────────────────────────────────────────────────────────────
# Data Loader
# ─────────────────────────────────────────────────────────────────────────────

class ArchitectureLoader:
    """Loads and parses the input JSON/YAML architecture file.

    Supports both JSON and YAML input formats. Provides detailed error
    messages for malformed input, missing required fields, and invalid
    data to help users quickly identify and fix issues.
    """

    # Required fields for each entity type
    SERVICE_REQUIRED_FIELDS = {"name", "region", "country"}
    VENDOR_REQUIRED_FIELDS = {"name", "country"}
    FLOW_REQUIRED_FIELDS = {"id", "from", "to", "to_country"}

    @staticmethod
    def load_json(filepath: str) -> dict:
        """Load and parse a JSON architecture file.

        Args:
            filepath: Absolute or relative path to the JSON file.

        Returns:
            Parsed dictionary containing the architecture definition.

        Raises:
            json.JSONDecodeError: If the file contains invalid JSON syntax.
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def load_yaml(filepath: str) -> dict:
        """Load and parse a YAML architecture file.

        Args:
            filepath: Absolute or relative path to the YAML file.

        Returns:
            Parsed dictionary containing the architecture definition.

        Raises:
            ImportError: If PyYAML is not installed.
            yaml.YAMLError: If the file contains invalid YAML syntax.
        """
        try:
            import yaml
            with open(filepath, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML input. "
                "Install with: pip install pyyaml"
            )

    @classmethod
    def load(cls, filepath: str) -> dict:
        """Load an architecture file, auto-detecting format from extension.

        Args:
            filepath: Path to the architecture file (.json, .yaml, or .yml).

        Returns:
            Parsed dictionary containing the architecture definition.

        Raises:
            json.JSONDecodeError: For malformed JSON files.
            yaml.YAMLError: For malformed YAML files.
            FileNotFoundError: If the file does not exist.
        """
        if filepath.endswith(".yaml") or filepath.endswith(".yml"):
            return cls.load_yaml(filepath)
        return cls.load_json(filepath)

    @classmethod
    def _validate_required_fields(
        cls, entity: dict, required: set, entity_type: str, index: int
    ) -> None:
        """Validate that a dict contains all required fields.

        Args:
            entity: The dictionary to validate.
            required: Set of required field names.
            entity_type: Human-readable entity type name (e.g., 'service').
            index: Zero-based index of the entity in its list (for error messages).

        Raises:
            ValueError: If any required fields are missing, with a descriptive
                message listing all missing fields and their expected types.
        """
        missing = required - set(entity.keys())
        if missing:
            name = entity.get("name") or entity.get("id") or f"#{index}"
            raise ValueError(
                f"Invalid {entity_type} '{name}' at index {index}: "
                f"missing required field(s): {sorted(missing)}. "
                f"All {entity_type}s must have: {sorted(required)}."
            )

    @classmethod
    def parse(cls, data: dict) -> tuple:
        """Parse raw architecture dict into typed model objects.

        Validates required fields and provides actionable error messages
        for any malformed or incomplete entries.

        Args:
            data: Raw dictionary loaded from the architecture file. Expected
                keys: 'organization', 'services', 'third_party_vendors',
                'data_flows'.

        Returns:
            A 4-tuple of (services, vendors, flows, org) where:
                - services: Dict[str, Service] keyed by service name
                - vendors: Dict[str, ThirdPartyVendor] keyed by vendor name
                - flows: List[DataFlow]
                - org: dict with organization metadata

        Raises:
            ValueError: If any entity is missing required fields.
            TypeError: If field values have unexpected types.
        """
        services: Dict[str, Service] = {}
        for i, s in enumerate(data.get("services", [])):
            cls._validate_required_fields(s, cls.SERVICE_REQUIRED_FIELDS, "service", i)
            svc = Service(
                name=s["name"],
                display_name=s.get("display_name", s["name"]),
                region=s["region"],
                country=s["country"],
                cloud_provider=s.get("cloud_provider", "Unknown"),
                data_categories=s.get("data_categories", []),
                data_subjects=s.get("data_subjects", ["customers"]),
                purpose=s.get("purpose", ""),
                retention_period=s.get("retention_period", "Not specified"),
                legal_basis_processing=s.get("legal_basis_processing", ""),
                is_controller=s.get("is_controller", False),
            )
            services[svc.name] = svc

        vendors: Dict[str, ThirdPartyVendor] = {}
        for i, v in enumerate(data.get("third_party_vendors", [])):
            cls._validate_required_fields(v, cls.VENDOR_REQUIRED_FIELDS, "vendor", i)
            vendor = ThirdPartyVendor(
                name=v["name"],
                display_name=v.get("display_name", v["name"]),
                country=v["country"],
                region=v.get("region", ""),
                purpose=v.get("purpose", ""),
                data_categories=v.get("data_categories", []),
                legal_basis=v.get("legal_basis"),
                dpf_certified=v.get("dpf_certified", False),
                processor_agreement=v.get("processor_agreement", False),
            )
            vendors[vendor.name] = vendor

        flows: List[DataFlow] = []
        for i, f in enumerate(data.get("data_flows", [])):
            cls._validate_required_fields(f, cls.FLOW_REQUIRED_FIELDS, "data_flow", i)
            flow = DataFlow(
                id=f["id"],
                from_service=f["from"],
                to_service=f["to"],
                to_region=f.get("to_region", ""),
                to_country=f["to_country"],
                data_categories=f.get("data_categories", []),
                purpose=f.get("purpose", ""),
                legal_basis=f.get("legal_basis"),
                tia_conducted=f.get("tia_conducted", False),
                volume=f.get("volume", "unknown"),
                frequency=f.get("frequency", "unknown"),
                notes=f.get("notes", ""),
            )
            flows.append(flow)

        org = data.get("organization", {})
        return services, vendors, flows, org


# ─────────────────────────────────────────────────────────────────────────────
# Core Validator
# ─────────────────────────────────────────────────────────────────────────────

class GDPRValidator:
    """
    Core GDPR compliance engine.

    Validates each data flow against GDPR Chapter V requirements,
    generates findings, and produces audit-ready reports.
    """

    def __init__(
        self,
        services: Dict[str, Service],
        vendors: Dict[str, ThirdPartyVendor],
        flows: List[DataFlow],
        org: dict,
    ):
        self.services = services
        self.vendors = vendors
        self.flows = flows
        self.org = org

    def get_origin_country(self, flow: DataFlow) -> Optional[str]:
        """Determine the origin country of a data flow."""
        svc = self.services.get(flow.from_service)
        return svc.country if svc else None

    def is_eea_country(self, country: str) -> bool:
        return country in EEA_COUNTRIES

    def is_cross_border(self, flow: DataFlow) -> bool:
        """
        A transfer is cross-border if it originates in EU/EEA and goes
        to a country outside the EU/EEA. Intra-EU flows are not cross-border.
        """
        origin = self.get_origin_country(flow)
        if not origin:
            return False
        origin_in_eea = self.is_eea_country(origin)
        dest_in_eea = self.is_eea_country(flow.to_country)
        return origin_in_eea and not dest_in_eea

    def has_adequacy_decision(self, country: str) -> bool:
        return country in ADEQUACY_COUNTRIES

    def requires_tia(self, flow: DataFlow) -> bool:
        """
        TIA required for transfers to high-risk jurisdictions (US, China, Russia)
        or when sensitive data categories are involved.
        """
        if flow.to_country in HIGH_RISK_JURISDICTIONS:
            return True
        sensitive = set(flow.data_categories) & SENSITIVE_DATA_CATEGORIES
        if sensitive:
            return True
        return False

    def is_derogation_valid(self, flow: DataFlow) -> bool:
        """
        Assess whether the Art. 49(1)(b) necessity derogation is valid.

        EDPB guidance: derogations must be "occasional and non-repetitive."
        Per-transaction flows: each individual transfer IS necessary for that
        specific contract, so we treat it as valid but flag it for review.
        Continuous/batch flows: derogation is NOT appropriate — SCCs required.
        """
        return flow.frequency in ("per_transaction", "per_onboarding", "per_event")

    def validate_flow(self, flow: DataFlow) -> TransferValidationResult:
        """Validate a single data flow for GDPR compliance."""
        findings: List[Finding] = []
        origin_country = self.get_origin_country(flow) or "Unknown"
        is_cross = self.is_cross_border(flow)
        tia_required = self.requires_tia(flow) if is_cross else False

        if not is_cross:
            return TransferValidationResult(
                flow=flow,
                is_cross_border=False,
                origin_country=origin_country,
                destination_country=flow.to_country,
                status=ComplianceStatus.NOT_APPLICABLE,
                tia_required=False,
                findings=[],
                notes="Intra-EU/EEA transfer — GDPR Chapter V does not apply.",
            )

        # ── Step 1: Check legal basis ─────────────────────────────────────
        if not flow.legal_basis:
            findings.append(Finding(
                finding_type=FindingType.MISSING_LEGAL_BASIS,
                severity=Severity.CRITICAL,
                flow_id=flow.id,
                source=flow.from_service,
                destination=flow.to_service,
                data_categories=flow.data_categories,
                description=(
                    f"Transfer from {flow.from_service} ({origin_country}) to "
                    f"{flow.to_service} ({flow.to_country}) has NO documented legal basis "
                    f"under GDPR Art. 44-49. This constitutes a prima facie violation."
                ),
                remediation=(
                    f"Immediately document a legal basis. Options: (1) Implement Standard "
                    f"Contractual Clauses (SCCs) with {flow.to_service} and conduct a TIA; "
                    f"(2) Assess whether Art. 49(1)(b) necessity derogation applies if this "
                    f"is a per-transaction flow; (3) Evaluate whether this transfer is "
                    f"necessary at all (data minimization review)."
                ),
                legal_reference="GDPR Art. 44, Art. 46, Art. 49; EDPB Guidelines 05/2021",
            ))
            return TransferValidationResult(
                flow=flow,
                is_cross_border=True,
                origin_country=origin_country,
                destination_country=flow.to_country,
                status=ComplianceStatus.NON_COMPLIANT,
                tia_required=tia_required,
                findings=findings,
            )

        # ── Step 2: Adequacy decision ─────────────────────────────────────
        if self.has_adequacy_decision(flow.to_country):
            status = ComplianceStatus.COMPLIANT
            # Special case: Brazil adequacy is recent (Feb 2025), flag for review
            if flow.to_country == "Brazil":
                findings.append(Finding(
                    finding_type=FindingType.MISSING_TIA,
                    severity=Severity.LOW,
                    flow_id=flow.id,
                    source=flow.from_service,
                    destination=flow.to_service,
                    data_categories=flow.data_categories,
                    description=(
                        f"Brazil's adequacy decision was granted in February 2025. "
                        f"Verify this decision remains in force and update DPA agreements."
                    ),
                    remediation="Confirm adequacy decision status with DPO. Update Article 30 record.",
                    legal_reference="GDPR Art. 45; EU Commission Decision on Brazil (Feb 2025)",
                ))
            return TransferValidationResult(
                flow=flow,
                is_cross_border=True,
                origin_country=origin_country,
                destination_country=flow.to_country,
                status=status,
                tia_required=False,
                findings=findings,
                notes=f"{flow.to_country} has an EU adequacy decision (Art. 45 GDPR).",
            )

        # ── Step 3: Validate the documented legal basis ───────────────────
        if flow.legal_basis not in VALID_TRANSFER_LEGAL_BASES:
            findings.append(Finding(
                finding_type=FindingType.INADEQUATE_LEGAL_BASIS,
                severity=Severity.CRITICAL,
                flow_id=flow.id,
                source=flow.from_service,
                destination=flow.to_service,
                data_categories=flow.data_categories,
                description=(
                    f"Legal basis '{flow.legal_basis}' is not a recognized GDPR Art. 44-49 "
                    f"transfer mechanism. Valid mechanisms: adequacy decision, SCC, BCR, "
                    f"approved certification, or Art. 49 derogations."
                ),
                remediation="Replace with a valid transfer mechanism (SCC recommended).",
                legal_reference="GDPR Art. 44-49; EDPB Guidelines 05/2021",
            ))
            return TransferValidationResult(
                flow=flow,
                is_cross_border=True,
                origin_country=origin_country,
                destination_country=flow.to_country,
                status=ComplianceStatus.NON_COMPLIANT,
                tia_required=tia_required,
                findings=findings,
            )

        # ── Step 4: Derogation assessment (Art. 49) ───────────────────────
        if flow.legal_basis == "necessity_contract":
            if not self.is_derogation_valid(flow):
                findings.append(Finding(
                    finding_type=FindingType.INADEQUATE_LEGAL_BASIS,
                    severity=Severity.HIGH,
                    flow_id=flow.id,
                    source=flow.from_service,
                    destination=flow.to_service,
                    data_categories=flow.data_categories,
                    description=(
                        f"Art. 49(1)(b) necessity derogation is used for a '{flow.frequency}' "
                        f"flow. EDPB Guidelines 2/2018 state derogations must be 'occasional "
                        f"and non-repetitive.' Continuous or batch flows do not qualify."
                    ),
                    remediation=(
                        f"Replace Art. 49(1)(b) derogation with Standard Contractual Clauses "
                        f"(SCCs) for this {flow.frequency} flow. Conduct a TIA for "
                        f"{flow.to_country}."
                    ),
                    legal_reference="GDPR Art. 49(1)(b); EDPB Guidelines 2/2018 on Art. 49",
                ))
                return TransferValidationResult(
                    flow=flow,
                    is_cross_border=True,
                    origin_country=origin_country,
                    destination_country=flow.to_country,
                    status=ComplianceStatus.NON_COMPLIANT,
                    tia_required=tia_required,
                    findings=findings,
                )
            else:
                # Derogation valid for per-transaction flows, but flag for review
                findings.append(Finding(
                    finding_type=FindingType.INADEQUATE_LEGAL_BASIS,
                    severity=Severity.MEDIUM,
                    flow_id=flow.id,
                    source=flow.from_service,
                    destination=flow.to_service,
                    data_categories=flow.data_categories,
                    description=(
                        f"Art. 49(1)(b) necessity derogation applied for per-transaction "
                        f"flow to {flow.to_country}. While each individual transaction may "
                        f"qualify, the aggregate volume of transfers warrants legal review. "
                        f"EDPB cautions against systematic reliance on Art. 49 derogations."
                    ),
                    remediation=(
                        f"Consult DPO and legal counsel to determine whether SCCs should "
                        f"replace the derogation for systematic transfers to {flow.to_country}. "
                        f"Document the necessity assessment in the Article 30 record."
                    ),
                    legal_reference="GDPR Art. 49(1)(b); EDPB Guidelines 2/2018 on Art. 49",
                ))

        # ── Step 5: TIA assessment ────────────────────────────────────────
        if tia_required and not flow.tia_conducted:
            sensitive_cats = set(flow.data_categories) & SENSITIVE_DATA_CATEGORIES
            severity = Severity.HIGH if sensitive_cats else Severity.MEDIUM
            findings.append(Finding(
                finding_type=FindingType.MISSING_TIA,
                severity=severity,
                flow_id=flow.id,
                source=flow.from_service,
                destination=flow.to_service,
                data_categories=flow.data_categories,
                description=(
                    f"Transfer to {flow.to_country} requires a Transfer Impact Assessment "
                    f"(TIA) per Schrems II (C-311/18). {flow.to_country} has laws that may "
                    f"undermine SCC protections (e.g., surveillance legislation). "
                    + (f"Sensitive data categories involved: {list(sensitive_cats)}." if sensitive_cats else "")
                ),
                remediation=(
                    f"Conduct a documented TIA assessing: (1) {flow.to_country}'s legal "
                    f"framework for government access to data; (2) whether supplementary "
                    f"measures (encryption, pseudonymization) adequately protect the data; "
                    f"(3) whether the transfer can be restructured to avoid {flow.to_country}."
                ),
                legal_reference="GDPR Art. 46; CJEU Schrems II (C-311/18); EDPB Recommendations 01/2020",
            ))

        # ── Step 6: Sensitive data extra check ───────────────────────────
        sensitive_cats = set(flow.data_categories) & SENSITIVE_DATA_CATEGORIES
        if sensitive_cats:
            findings.append(Finding(
                finding_type=FindingType.SENSITIVE_DATA_TRANSFER,
                severity=Severity.HIGH,
                flow_id=flow.id,
                source=flow.from_service,
                destination=flow.to_service,
                data_categories=list(sensitive_cats),
                description=(
                    f"Transfer includes special category data (Art. 9 GDPR): "
                    f"{list(sensitive_cats)}. These require explicit consent or a specific "
                    f"Art. 9(2) exception in addition to the Art. 6 legal basis."
                ),
                remediation=(
                    f"Verify Art. 9(2) exception applies (e.g., explicit consent, vital "
                    f"interests, legal claims). Implement data minimization — transfer only "
                    f"the minimum sensitive data necessary. Consider pseudonymization before "
                    f"transfer."
                ),
                legal_reference="GDPR Art. 9; Art. 9(2)(a)-(j); EDPB Guidelines 05/2021",
            ))

        # ── Determine final status ────────────────────────────────────────
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_tia_missing = any(f.finding_type == FindingType.MISSING_TIA for f in findings)

        if has_critical:
            status = ComplianceStatus.NON_COMPLIANT
        elif has_tia_missing:
            status = ComplianceStatus.COMPLIANT_TIA_REQUIRED
        elif findings:
            status = ComplianceStatus.REQUIRES_LEGAL_REVIEW
        else:
            status = ComplianceStatus.COMPLIANT

        return TransferValidationResult(
            flow=flow,
            is_cross_border=True,
            origin_country=origin_country,
            destination_country=flow.to_country,
            status=status,
            tia_required=tia_required,
            findings=findings,
        )

    def validate_all(self) -> List[TransferValidationResult]:
        return [self.validate_flow(flow) for flow in self.flows]

    # ─────────────────────────────────────────────────────────────────────
    # Data Minimization Analysis (Stretch Goal 5)
    # ─────────────────────────────────────────────────────────────────────

    def analyze_minimization(self) -> List[MinimizationConcern]:
        """
        Detect potential Art. 5(1)(c) violations:
        - Same data category sent to >4 third parties
        - Indefinite retention periods
        - Sensitive data flowing to vendors whose purpose doesn't justify it
        """
        concerns: List[MinimizationConcern] = []

        # Track recipients per data category
        category_recipients: Dict[str, List[str]] = {}
        for flow in self.flows:
            if not self.is_cross_border(flow):
                continue
            for cat in flow.data_categories:
                if cat not in category_recipients:
                    category_recipients[cat] = []
                if flow.to_service not in category_recipients[cat]:
                    category_recipients[cat].append(flow.to_service)

        for cat, recipients in category_recipients.items():
            if len(recipients) > EXCESSIVE_RECIPIENTS_THRESHOLD:
                concerns.append(MinimizationConcern(
                    data_category=cat,
                    recipient_count=len(recipients),
                    recipients=recipients,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Data category '{cat}' is shared with {len(recipients)} external "
                        f"recipients: {recipients}. GDPR Art. 5(1)(c) requires data to be "
                        f"'limited to what is necessary.' Sharing the same category with "
                        f">{EXCESSIVE_RECIPIENTS_THRESHOLD} parties warrants review."
                    ),
                    recommendation=(
                        f"Review whether all {len(recipients)} recipients genuinely require "
                        f"'{cat}' data. Consider: (1) pseudonymization before sharing; "
                        f"(2) aggregation instead of raw data; (3) eliminating non-essential "
                        f"recipients."
                    ),
                ))

        # Check for indefinite retention
        for svc in self.services.values():
            retention_lower = svc.retention_period.lower()
            if any(kw in retention_lower for kw in INDEFINITE_RETENTION_KEYWORDS):
                concerns.append(MinimizationConcern(
                    data_category="all categories",
                    recipient_count=0,
                    recipients=[svc.name],
                    severity=Severity.HIGH,
                    description=(
                        f"Service '{svc.display_name}' has retention period: "
                        f"'{svc.retention_period}'. GDPR Art. 5(1)(e) requires data to be "
                        f"kept 'no longer than necessary.' Indefinite retention is a violation "
                        f"unless a specific legal obligation requires it."
                    ),
                    recommendation=(
                        f"Define a specific retention period for '{svc.display_name}' tied "
                        f"to its processing purpose. If PCI DSS mandates long retention, "
                        f"document the legal obligation and implement automatic deletion "
                        f"after the maximum required period."
                    ),
                ))

        # Check sensitive data flowing to vendors with mismatched purpose
        for flow in self.flows:
            sensitive = set(flow.data_categories) & SENSITIVE_DATA_CATEGORIES
            if not sensitive:
                continue
            vendor = self.vendors.get(flow.to_service)
            if vendor and not vendor.processor_agreement:
                concerns.append(MinimizationConcern(
                    data_category=", ".join(sensitive),
                    recipient_count=1,
                    recipients=[flow.to_service],
                    severity=Severity.HIGH,
                    description=(
                        f"Sensitive data ({list(sensitive)}) flows to '{flow.to_service}' "
                        f"but no Data Processing Agreement (DPA) is documented. Art. 28 "
                        f"GDPR requires a DPA with all processors handling personal data."
                    ),
                    recommendation=(
                        f"Immediately execute a DPA with '{flow.to_service}'. If a DPA "
                        f"cannot be established, cease transferring sensitive data to this "
                        f"vendor."
                    ),
                ))

        return concerns

    # ─────────────────────────────────────────────────────────────────────
    # Compliance Conflict Detection (Stretch Goal 6)
    # ─────────────────────────────────────────────────────────────────────

    def detect_compliance_conflicts(self) -> List[ComplianceConflict]:
        """
        Identify scenarios where GDPR minimization conflicts with PCI DSS
        or fraud prevention requirements.
        """
        conflicts: List[ComplianceConflict] = []

        for flow in self.flows:
            if not self.is_cross_border(flow):
                continue

            # PCI DSS audit logging vs. GDPR minimization
            if "audit_log" in flow.from_service.lower() or "audit" in flow.purpose.lower():
                conflicts.append(ComplianceConflict(
                    flow_id=flow.id,
                    source=flow.from_service,
                    destination=flow.to_service,
                    gdpr_concern=(
                        "GDPR Art. 5(1)(c) data minimization and Art. 5(1)(e) storage "
                        "limitation require that personal data in logs be minimized and "
                        "deleted after the processing purpose is fulfilled."
                    ),
                    pci_requirement=(
                        "PCI DSS Requirement 10 mandates logging of all access to "
                        "cardholder data environment with sufficient detail for forensic "
                        "analysis. Logs must be retained for at least 12 months."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Recommended resolution: (1) Implement log pseudonymization — "
                        "replace cardholder names/emails with tokens in logs while "
                        "retaining transaction IDs for PCI audit purposes; (2) Define "
                        "a maximum retention period (12 months active + 12 months "
                        "archived) satisfying both PCI DSS and GDPR; (3) Restrict "
                        "log access to security team only; (4) Document the legal "
                        "obligation basis (Art. 6(1)(c)) in the Article 30 record. "
                        "This conflict requires DPO + CISO joint decision."
                    ),
                    requires_legal_review=True,
                ))

            # Fraud detection ML vs. GDPR minimization
            if "fraud" in flow.purpose.lower() and flow.to_country in HIGH_RISK_JURISDICTIONS:
                conflicts.append(ComplianceConflict(
                    flow_id=flow.id,
                    source=flow.from_service,
                    destination=flow.to_service,
                    gdpr_concern=(
                        "GDPR Art. 5(1)(c) requires fraud detection data to be 'limited "
                        "to what is necessary.' Sharing transaction data with ML vendors "
                        "in high-risk jurisdictions may expose data to government access."
                    ),
                    pci_requirement=(
                        "PCI DSS Requirement 10.6 requires daily review of logs for "
                        "anomalies. Fraud prevention systems often require extensive "
                        "transaction data for ML model accuracy."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Recommended resolution: (1) Evaluate whether fraud detection "
                        "can be performed on pseudonymized/tokenized data; (2) Consider "
                        "on-premises or EU-hosted ML models to avoid cross-border "
                        "transfer; (3) If US vendor is essential, ensure DPF certification "
                        "or robust SCCs with encryption-in-transit and at-rest; "
                        "(4) Conduct and document TIA. This is a legitimate interests "
                        "vs. data subject rights balancing exercise requiring DPO sign-off."
                    ),
                    requires_legal_review=True,
                ))

        return conflicts

    # ─────────────────────────────────────────────────────────────────────
    # Article 30 Inventory Generation
    # ─────────────────────────────────────────────────────────────────────

    def generate_article30(
        self, results: List[TransferValidationResult]
    ) -> List[Article30Entry]:
        """
        Generate GDPR Article 30 processing inventory entries.
        Groups flows by purpose for a cleaner inventory.
        """
        entries: List[Article30Entry] = []
        results_by_flow = {r.flow.id: r for r in results}

        # Group by controller service
        for svc in self.services.values():
            if not svc.is_controller:
                continue

            # Find all flows originating from this service
            svc_flows = [f for f in self.flows if f.from_service == svc.name]
            if not svc_flows and not svc.data_categories:
                continue

            # Collect recipients and transfer info
            recipients: List[str] = []
            cross_border_transfers: List[str] = []
            transfer_safeguards: List[str] = []
            flow_ids: List[str] = []
            overall_status = ComplianceStatus.COMPLIANT

            for flow in svc_flows:
                result = results_by_flow.get(flow.id)
                dest_display = flow.to_service
                vendor = self.vendors.get(flow.to_service)
                if vendor:
                    dest_display = vendor.display_name

                recipients.append(f"{dest_display} ({flow.to_country})")
                flow_ids.append(flow.id)

                if result and result.is_cross_border:
                    safeguard = flow.legal_basis or "NONE DOCUMENTED"
                    cross_border_transfers.append(
                        f"{flow.to_country} — {dest_display} [{safeguard}]"
                    )
                    if flow.legal_basis:
                        transfer_safeguards.append(safeguard)

                    # Escalate status
                    if result.status == ComplianceStatus.NON_COMPLIANT:
                        overall_status = ComplianceStatus.NON_COMPLIANT
                    elif (
                        result.status == ComplianceStatus.COMPLIANT_TIA_REQUIRED
                        and overall_status == ComplianceStatus.COMPLIANT
                    ):
                        overall_status = ComplianceStatus.COMPLIANT_TIA_REQUIRED

            # Collect all data subjects from flows
            all_subjects = list(svc.data_subjects)
            for flow in svc_flows:
                src_svc = self.services.get(flow.from_service)
                if src_svc:
                    all_subjects.extend(src_svc.data_subjects)
            all_subjects = list(dict.fromkeys(all_subjects))  # deduplicate preserving order

            entries.append(Article30Entry(
                activity_name=f"{svc.display_name} — {svc.purpose}",
                controller=self.org.get("name", "Yuno Payments"),
                purpose=svc.purpose,
                legal_basis=svc.legal_basis_processing,
                data_subjects=all_subjects,
                data_categories=svc.data_categories,
                recipients=recipients if recipients else ["Internal only"],
                cross_border_transfers=cross_border_transfers if cross_border_transfers else ["None"],
                transfer_safeguards=list(dict.fromkeys(transfer_safeguards)) if transfer_safeguards else ["N/A"],
                retention_period=svc.retention_period,
                compliance_status=overall_status,
                source_flows=flow_ids,
            ))

        return entries

    # ─────────────────────────────────────────────────────────────────────
    # Full Validation Run
    # ─────────────────────────────────────────────────────────────────────

    def run(self) -> ValidationReport:
        """Execute the full GDPR validation and return a complete report."""
        results = self.validate_all()
        all_findings = [f for r in results for f in r.findings]
        article30 = self.generate_article30(results)
        minimization = self.analyze_minimization()
        conflicts = self.detect_compliance_conflicts()

        cross_border = [r for r in results if r.is_cross_border]
        compliant = [r for r in cross_border if r.status == ComplianceStatus.COMPLIANT]
        non_compliant = [r for r in cross_border if r.status == ComplianceStatus.NON_COMPLIANT]
        tia_required = [r for r in cross_border if r.status == ComplianceStatus.COMPLIANT_TIA_REQUIRED]

        return ValidationReport(
            organization=self.org.get("name", "Yuno Payments"),
            generated_at=datetime.utcnow().isoformat() + "Z",
            total_flows=len(self.flows),
            cross_border_flows=len(cross_border),
            compliant_flows=len(compliant),
            non_compliant_flows=len(non_compliant),
            tia_required_flows=len(tia_required),
            transfer_results=results,
            findings=all_findings,
            article30_entries=article30,
            minimization_concerns=minimization,
            compliance_conflicts=conflicts,
        )
