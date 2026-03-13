"""
Data models for the GDPR Flow Validator.
Uses dataclasses for clean, typed representations of the input schema.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    COMPLIANT_TIA_REQUIRED = "COMPLIANT_TIA_REQUIRED"
    NON_COMPLIANT = "NON_COMPLIANT"
    REQUIRES_LEGAL_REVIEW = "REQUIRES_LEGAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Intra-EEA or intra-EU flows


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingType(str, Enum):
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
    data_category: str
    recipient_count: int
    recipients: List[str]
    severity: Severity
    description: str
    recommendation: str


@dataclass
class ComplianceConflict:
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
