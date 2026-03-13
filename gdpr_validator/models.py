"""
Data models for the GDPR Flow Validator.

This module defines all typed data structures used throughout the validator.
Uses Python dataclasses for clean, type-safe representations of:
  - Input schema (services, vendors, data flows)
  - Validation outputs (findings, results, reports)
  - Article 30 inventory entries
  - Compliance conflict records

All models are immutable by design — the validator creates new instances
rather than mutating existing ones, which simplifies testing and reasoning.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ComplianceStatus(str, Enum):
    """GDPR Chapter V compliance status for a data transfer.

    Values are ordered from most to least severe for escalation logic:
    NON_COMPLIANT > COMPLIANT_TIA_REQUIRED > REQUIRES_LEGAL_REVIEW > COMPLIANT > NOT_APPLICABLE

    Attributes:
        COMPLIANT: Transfer has a valid legal basis and no outstanding issues.
        COMPLIANT_TIA_REQUIRED: Transfer has a valid legal basis (e.g., SCCs) but
            requires a Transfer Impact Assessment per Schrems II (C-311/18).
        NON_COMPLIANT: Transfer lacks a valid legal basis or has a CRITICAL finding.
            Immediate remediation required.
        REQUIRES_LEGAL_REVIEW: Transfer has medium/low findings that require
            DPO or legal counsel review but are not definitively non-compliant.
        NOT_APPLICABLE: Intra-EU/EEA transfer — GDPR Chapter V does not apply.
    """

    COMPLIANT = "COMPLIANT"
    COMPLIANT_TIA_REQUIRED = "COMPLIANT_TIA_REQUIRED"
    NON_COMPLIANT = "NON_COMPLIANT"
    REQUIRES_LEGAL_REVIEW = "REQUIRES_LEGAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    """Finding severity levels, aligned with common risk management frameworks.

    Attributes:
        CRITICAL: Definitive GDPR violation requiring immediate action.
            Example: transfer with no legal basis whatsoever.
        HIGH: Significant compliance gap that must be addressed urgently.
            Example: missing TIA for US transfer with sensitive data.
        MEDIUM: Compliance concern that should be addressed in the near term.
            Example: Art. 49 derogation used for per-transaction flows.
        LOW: Minor issue or informational note for awareness.
            Example: Brazil adequacy decision is recent and should be monitored.
        INFO: Purely informational, no action required.
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingType(str, Enum):
    """Classification of compliance findings by type.

    Each type maps to a specific GDPR article or compliance requirement.

    Attributes:
        MISSING_LEGAL_BASIS: No legal basis documented for the transfer (Art. 44).
        MISSING_TIA: Transfer Impact Assessment required but not conducted (Schrems II).
        INADEQUATE_LEGAL_BASIS: Legal basis exists but is inappropriate for this transfer
            (e.g., Art. 49 derogation for systematic transfers).
        DATA_MINIMIZATION: Data minimization concern under Art. 5(1)(c).
        RETENTION_CONCERN: Retention period violates Art. 5(1)(e) storage limitation.
        SENSITIVE_DATA_TRANSFER: Transfer includes Art. 9 special category data.
        COMPLIANCE_CONFLICT: GDPR requirement conflicts with PCI DSS obligation.
        EXCESSIVE_RECIPIENTS: Same data category shared with too many third parties.
        HIGH_RISK_JURISDICTION: Transfer to jurisdiction with high surveillance risk.
    """

    MISSING_LEGAL_BASIS = "Missing Legal Basis"
    MISSING_TIA = "Missing TIA"
    INADEQUATE_LEGAL_BASIS = "Inadequate Legal Basis"
    DATA_MINIMIZATION = "Data Minimization"
    RETENTION_CONCERN = "Retention Concern"
    SENSITIVE_DATA_TRANSFER = "Sensitive Data Transfer"
    COMPLIANCE_CONFLICT = "Compliance Conflict (GDPR vs PCI DSS)"
    EXCESSIVE_RECIPIENTS = "Excessive Recipients"
    HIGH_RISK_JURISDICTION = "High-Risk Jurisdiction"


@dataclass
class Service:
    """Represents an internal service or system in the architecture.

    Services are the source nodes in data flow graphs. A service marked
    as ``is_controller=True`` will generate an Article 30 inventory entry.

    Attributes:
        name: Unique identifier for the service (used in flow references).
        display_name: Human-readable name for reports.
        region: Cloud region where the service is deployed (e.g., "eu-west-1").
        country: Country where the service is hosted (used for EEA determination).
        cloud_provider: Cloud provider name (e.g., "AWS", "GCP", "Azure").
        data_categories: List of personal data categories processed by this service.
        data_subjects: Categories of individuals whose data is processed.
        purpose: Processing purpose description for Article 30.
        retention_period: How long data is retained (e.g., "5 years", "indefinite").
        legal_basis_processing: GDPR Art. 6 legal basis for processing (not transfer).
        is_controller: Whether this service acts as a data controller under GDPR.
    """

    name: str
    display_name: str
    region: str
    country: str
    cloud_provider: str
    data_categories: List[str]
    data_subjects: List[str]
    purpose: str
    retention_period: str
    legal_basis_processing: str
    is_controller: bool = True


@dataclass
class DataFlow:
    """Represents a data transfer between two services or to a third-party vendor.

    This is the primary unit of analysis. Each flow is validated independently
    for GDPR Chapter V compliance.

    Attributes:
        id: Unique identifier for the flow (e.g., "flow-001").
        from_service: Name of the source service (must match a Service.name).
        to_service: Name of the destination service or vendor.
        to_region: Cloud region of the destination (e.g., "us-east-1").
        to_country: Country of the destination — used for cross-border determination.
        data_categories: Personal data categories included in this transfer.
        purpose: Business purpose of the transfer.
        legal_basis: GDPR Art. 44-49 transfer mechanism (e.g., "SCC", "BCR",
            "adequacy_decision", "necessity_contract"). None if undocumented.
        tia_conducted: Whether a Transfer Impact Assessment has been completed.
        volume: Approximate data volume (e.g., "low", "medium", "high").
        frequency: Transfer frequency (e.g., "continuous", "per_transaction",
            "batch_daily"). Used to assess Art. 49 derogation validity.
        notes: Optional free-text notes for the Article 30 record.
    """

    id: str
    from_service: str
    to_service: str
    to_region: str
    to_country: str
    data_categories: List[str]
    purpose: str
    legal_basis: Optional[str]
    tia_conducted: bool
    volume: str
    frequency: str
    notes: str = ""


@dataclass
class ThirdPartyVendor:
    """Represents a third-party vendor receiving personal data.

    Vendors are destination nodes in data flow graphs. The ``processor_agreement``
    flag is critical — Art. 28 GDPR requires a Data Processing Agreement (DPA)
    with all processors handling personal data on behalf of the controller.

    Attributes:
        name: Unique identifier for the vendor (used in flow references).
        display_name: Human-readable vendor name for reports.
        country: Country where the vendor is established or processes data.
        region: Cloud region (optional, for reference).
        purpose: Purpose for which the vendor processes data.
        data_categories: Personal data categories the vendor receives.
        legal_basis: Transfer mechanism used for this vendor (e.g., "SCC").
        dpf_certified: Whether the vendor is certified under the EU-US Data
            Privacy Framework (relevant only for US vendors).
        processor_agreement: Whether a signed DPA exists with this vendor.
    """

    name: str
    display_name: str
    country: str
    region: str
    purpose: str
    data_categories: List[str]
    legal_basis: Optional[str]
    dpf_certified: bool
    processor_agreement: bool


@dataclass
class TransferValidationResult:
    """The validation result for a single data flow.

    Contains the compliance status, all findings, and contextual metadata
    about the transfer. This is the primary output of ``GDPRValidator.validate_flow()``.

    Attributes:
        flow: The original DataFlow that was validated.
        is_cross_border: True if the transfer crosses the EU/EEA boundary.
        origin_country: Country of the source service (resolved from services dict).
        destination_country: Country of the destination (from flow.to_country).
        status: Overall compliance status for this transfer.
        tia_required: Whether a TIA is required for this transfer.
        findings: List of specific compliance findings for this flow.
        notes: Optional explanatory note (e.g., "Intra-EEA transfer — N/A").
    """

    flow: DataFlow
    is_cross_border: bool
    origin_country: str
    destination_country: str
    status: ComplianceStatus
    tia_required: bool
    findings: List["Finding"] = field(default_factory=list)
    notes: str = ""


@dataclass
class Finding:
    """A specific compliance finding for a data flow.

    Findings are the atomic units of the compliance report. Each finding
    maps to a specific GDPR article violation or concern, and includes
    actionable remediation guidance.

    Attributes:
        finding_type: Classification of the finding (see FindingType enum).
        severity: Risk severity level (see Severity enum).
        flow_id: ID of the flow this finding belongs to.
        source: Name of the source service.
        destination: Name of the destination service or vendor.
        data_categories: Data categories involved in this specific finding.
        description: Detailed description of the compliance issue, including
            the specific GDPR article and why it applies.
        remediation: Concrete, actionable steps to resolve the finding.
        legal_reference: GDPR articles, EDPB guidelines, or case law references.
    """

    finding_type: FindingType
    severity: Severity
    flow_id: str
    source: str
    destination: str
    data_categories: List[str]
    description: str
    remediation: str
    legal_reference: str = ""


@dataclass
class Article30Entry:
    """A single entry in the GDPR Article 30 Records of Processing Activities (RoPA).

    Article 30 requires controllers to maintain a written record of all processing
    activities. This dataclass represents one processing activity, typically
    corresponding to one controller service and all its outbound data flows.

    Attributes:
        activity_name: Name of the processing activity (e.g., "Payment Processing").
        controller: Name of the data controller organization.
        purpose: Purpose of the processing activity.
        legal_basis: Art. 6 legal basis for processing (not transfer).
        data_subjects: Categories of data subjects (e.g., "customers", "employees").
        data_categories: Categories of personal data processed.
        recipients: List of recipients including third-party vendors.
        cross_border_transfers: List of cross-border transfers with safeguards.
        transfer_safeguards: Transfer mechanisms used (e.g., "SCC", "BCR").
        retention_period: Data retention period for this activity.
        compliance_status: Overall compliance status of this processing activity.
        source_flows: IDs of the data flows that contributed to this entry.
    """

    activity_name: str
    controller: str
    purpose: str
    legal_basis: str
    data_subjects: List[str]
    data_categories: List[str]
    recipients: List[str]
    cross_border_transfers: List[str]
    transfer_safeguards: List[str]
    retention_period: str
    compliance_status: ComplianceStatus
    source_flows: List[str] = field(default_factory=list)


@dataclass
class MinimizationConcern:
    """A data minimization concern under GDPR Art. 5(1)(c).

    Identifies situations where personal data may be shared with more
    recipients than necessary, or retained longer than required.

    Attributes:
        data_category: The data category with excessive sharing or retention.
        recipient_count: Number of recipients receiving this data category.
        recipients: Names of the recipients.
        severity: Risk severity of this minimization concern.
        description: Explanation of why this is a minimization concern.
        recommendation: Actionable steps to reduce data sharing or retention.
    """

    data_category: str
    recipient_count: int
    recipients: List[str]
    severity: Severity
    description: str
    recommendation: str


@dataclass
class ComplianceConflict:
    """A conflict between GDPR requirements and PCI DSS obligations.

    Payment processors face genuine tensions where GDPR minimization
    requirements conflict with PCI DSS audit and retention mandates.
    These conflicts cannot be auto-resolved — they require DPO and
    legal counsel review.

    Attributes:
        flow_id: ID of the data flow where the conflict occurs.
        source: Name of the source service.
        destination: Name of the destination service or vendor.
        gdpr_concern: The GDPR requirement that creates the conflict.
        pci_requirement: The PCI DSS requirement that creates the conflict.
        severity: Risk severity of the conflict.
        recommendation: Suggested resolution approach (not a legal determination).
        requires_legal_review: Always True — these conflicts require human judgment.
    """

    flow_id: str
    source: str
    destination: str
    gdpr_concern: str
    pci_requirement: str
    severity: Severity
    recommendation: str
    requires_legal_review: bool = True


@dataclass
class ValidationReport:
    """The complete output of a GDPR validation run.

    This is the top-level report object returned by ``GDPRValidator.run()``.
    It aggregates all validation results, findings, and analysis into a
    single structure that can be rendered as HTML, JSON, or console output.

    Attributes:
        organization: Name of the organization being audited.
        generated_at: ISO 8601 UTC timestamp of when the report was generated.
        total_flows: Total number of data flows analyzed.
        cross_border_flows: Number of flows that cross the EU/EEA boundary.
        compliant_flows: Number of cross-border flows with COMPLIANT status.
        non_compliant_flows: Number of flows with NON_COMPLIANT status.
        tia_required_flows: Number of flows with COMPLIANT_TIA_REQUIRED status.
        transfer_results: Per-flow validation results (includes intra-EEA flows).
        findings: All findings from all flows, sorted by severity.
        article30_entries: Generated Article 30 RoPA entries.
        minimization_concerns: Data minimization analysis results.
        compliance_conflicts: Detected GDPR/PCI DSS conflicts.
    """

    organization: str
    generated_at: str
    total_flows: int
    cross_border_flows: int
    compliant_flows: int
    non_compliant_flows: int
    tia_required_flows: int
    transfer_results: List[TransferValidationResult]
    findings: List[Finding]
    article30_entries: List[Article30Entry]
    minimization_concerns: List[MinimizationConcern]
    compliance_conflicts: List[ComplianceConflict]
