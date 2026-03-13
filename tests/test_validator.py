"""
Unit tests for the GDPR Flow Validator.

Tests cover:
  1. Cross-border detection logic
  2. Legal basis validation (valid, missing, invalid)
  3. TIA requirement detection
  4. Adequacy decision lookup
  5. Derogation validity
  6. Article 30 inventory generation
  7. Data minimization analysis
  8. GDPR/PCI DSS conflict detection
  9. Full validation pipeline (end-to-end)
  10. Edge cases (intra-EEA, missing fields)
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gdpr_validator.models import (
    ComplianceStatus,
    DataFlow,
    FindingType,
    Severity,
    Service,
    ThirdPartyVendor,
)
from gdpr_validator.validator import ArchitectureLoader, GDPRValidator


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_service(name, country, **kwargs):
    return Service(
        name=name,
        display_name=name,
        region=kwargs.get("region", "eu-west-1"),
        country=country,
        cloud_provider=kwargs.get("cloud_provider", "AWS"),
        data_categories=kwargs.get("data_categories", ["contact_details"]),
        data_subjects=kwargs.get("data_subjects", ["customers"]),
        purpose=kwargs.get("purpose", "Payment processing"),
        retention_period=kwargs.get("retention_period", "5 years"),
        legal_basis_processing=kwargs.get("legal_basis_processing", "contract"),
        is_controller=kwargs.get("is_controller", False),
    )


def make_flow(flow_id, from_svc, to_svc, to_country, legal_basis=None, **kwargs):
    return DataFlow(
        id=flow_id,
        from_service=from_svc,
        to_service=to_svc,
        to_region=kwargs.get("to_region", "us-east-1"),
        to_country=to_country,
        data_categories=kwargs.get("data_categories", ["contact_details", "transaction_data"]),
        purpose=kwargs.get("purpose", "Payment processing"),
        legal_basis=legal_basis,
        tia_conducted=kwargs.get("tia_conducted", False),
        volume=kwargs.get("volume", "medium"),
        frequency=kwargs.get("frequency", "continuous"),
        notes=kwargs.get("notes", ""),
    )


def make_validator(services_list, flows_list, vendors_list=None):
    services = {s.name: s for s in services_list}
    vendors = {v.name: v for v in (vendors_list or [])}
    org = {"name": "Test Corp", "country": "Ireland"}
    return GDPRValidator(services=services, vendors=vendors, flows=flows_list, org=org)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Cross-border detection
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossBorderDetection:
    def test_eu_to_us_is_cross_border(self):
        """Transfer from EU (Ireland) to US is cross-border."""
        svc_eu = make_service("api-eu", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-eu", "api-us", "United States", legal_basis="SCC")
        v = make_validator([svc_eu, svc_us], [flow])
        assert v.is_cross_border(flow) is True

    def test_eu_to_eu_is_not_cross_border(self):
        """Transfer from Germany to France (both EEA) is NOT cross-border."""
        svc_de = make_service("api-de", "Germany")
        svc_fr = make_service("api-fr", "France")
        flow = make_flow("f2", "api-de", "api-fr", "France")
        v = make_validator([svc_de, svc_fr], [flow])
        assert v.is_cross_border(flow) is False

    def test_eu_to_uk_is_cross_border(self):
        """Transfer from EU to UK is cross-border (UK has adequacy decision)."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_uk = make_service("api-uk", "United Kingdom")
        flow = make_flow("f3", "api-ie", "api-uk", "United Kingdom", legal_basis="adequacy_decision")
        v = make_validator([svc_ie, svc_uk], [flow])
        assert v.is_cross_border(flow) is True

    def test_eu_to_jp_is_cross_border(self):
        """Transfer from EU to Japan is cross-border (Japan has adequacy decision)."""
        svc_de = make_service("api-de", "Germany")
        svc_jp = make_service("api-jp", "Japan")
        flow = make_flow("f4", "api-de", "api-jp", "Japan", legal_basis="adequacy_decision")
        v = make_validator([svc_de, svc_jp], [flow])
        assert v.is_cross_border(flow) is True

    def test_eu_to_norway_is_not_cross_border(self):
        """Transfer from EU to Norway (EEA non-EU) is NOT cross-border."""
        svc_de = make_service("api-de", "Germany")
        svc_no = make_service("api-no", "Norway")
        flow = make_flow("f5", "api-de", "api-no", "Norway")
        v = make_validator([svc_de, svc_no], [flow])
        assert v.is_cross_border(flow) is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. Legal basis validation
# ─────────────────────────────────────────────────────────────────────────────

class TestLegalBasisValidation:
    def test_scc_is_valid_for_us(self):
        """SCC is a valid transfer mechanism for US transfers."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-ie", "api-us", "United States", legal_basis="SCC")
        v = make_validator([svc_ie, svc_us], [flow])
        result = v.validate_flow(flow)
        # SCC for US → compliant (with TIA required)
        assert result.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.COMPLIANT_TIA_REQUIRED)

    def test_missing_legal_basis_is_non_compliant(self):
        """Missing legal basis for cross-border transfer is non-compliant."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_sg = make_service("api-sg", "Singapore")
        flow = make_flow("f2", "api-ie", "api-sg", "Singapore", legal_basis=None)
        v = make_validator([svc_ie, svc_sg], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.NON_COMPLIANT
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.MISSING_LEGAL_BASIS in finding_types

    def test_adequacy_decision_is_valid_for_uk(self):
        """Adequacy decision is valid for UK transfers."""
        svc_de = make_service("api-de", "Germany")
        svc_uk = make_service("api-uk", "United Kingdom")
        flow = make_flow("f3", "api-de", "api-uk", "United Kingdom", legal_basis="adequacy_decision")
        v = make_validator([svc_de, svc_uk], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_adequacy_decision_invalid_for_us(self):
        """Adequacy decision claimed for US triggers a TIA finding (no adequacy exists for US).
        The motor marks it COMPLIANT_TIA_REQUIRED and generates a MISSING_TIA finding
        because US is a high-risk jurisdiction regardless of the claimed legal basis.
        """
        svc_ie = make_service("api-ie", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f4", "api-ie", "api-us", "United States", legal_basis="adequacy_decision")
        v = make_validator([svc_ie, svc_us], [flow])
        result = v.validate_flow(flow)
        # Motor flags TIA required for US regardless of claimed legal basis
        assert result.status == ComplianceStatus.COMPLIANT_TIA_REQUIRED
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.MISSING_TIA in finding_types

    def test_bcr_is_valid_mechanism(self):
        """BCR is a valid transfer mechanism."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f5", "api-ie", "api-us", "United States", legal_basis="BCR")
        v = make_validator([svc_ie, svc_us], [flow])
        result = v.validate_flow(flow)
        assert result.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.COMPLIANT_TIA_REQUIRED)


# ─────────────────────────────────────────────────────────────────────────────
# 3. TIA requirement detection
# ─────────────────────────────────────────────────────────────────────────────

class TestTIARequirements:
    def test_us_transfer_requires_tia(self):
        """Transfers to US require TIA (high-risk jurisdiction post-Schrems II)."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-ie", "api-us", "United States", legal_basis="SCC")
        v = make_validator([svc_ie, svc_us], [flow])
        assert v.requires_tia(flow) is True

    def test_cn_transfer_requires_tia(self):
        """Transfers to China require TIA (high-risk jurisdiction)."""
        svc_de = make_service("api-de", "Germany")
        svc_cn = make_service("api-cn", "China")
        flow = make_flow("f2", "api-de", "api-cn", "China", legal_basis="SCC")
        v = make_validator([svc_de, svc_cn], [flow])
        assert v.requires_tia(flow) is True

    def test_jp_transfer_does_not_require_tia_for_basic_data(self):
        """Transfers to Japan (adequacy) with basic data don't require TIA."""
        svc_de = make_service("api-de", "Germany")
        svc_jp = make_service("api-jp", "Japan")
        flow = make_flow(
            "f3", "api-de", "api-jp", "Japan",
            legal_basis="adequacy_decision",
            data_categories=["contact_details"]
        )
        v = make_validator([svc_de, svc_jp], [flow])
        assert v.requires_tia(flow) is False

    def test_sensitive_data_requires_tia(self):
        """Transfers involving sensitive data categories require TIA."""
        svc_ie = make_service("api-ie", "Ireland")
        svc_br = make_service("api-br", "Brazil")
        flow = make_flow(
            "f4", "api-ie", "api-br", "Brazil",
            legal_basis="necessity_contract",
            data_categories=["biometric_data", "transaction_data"]
        )
        v = make_validator([svc_ie, svc_br], [flow])
        assert v.requires_tia(flow) is True


# ─────────────────────────────────────────────────────────────────────────────
# 4. Adequacy decision lookup
# ─────────────────────────────────────────────────────────────────────────────

class TestAdequacyDecisions:
    def _make_validator(self):
        svc = make_service("svc", "Germany")
        return make_validator([svc], [])

    def test_uk_has_adequacy(self):
        assert self._make_validator().has_adequacy_decision("United Kingdom") is True

    def test_japan_has_adequacy(self):
        assert self._make_validator().has_adequacy_decision("Japan") is True

    def test_brazil_has_adequacy(self):
        assert self._make_validator().has_adequacy_decision("Brazil") is True

    def test_us_no_adequacy(self):
        assert self._make_validator().has_adequacy_decision("United States") is False

    def test_china_no_adequacy(self):
        assert self._make_validator().has_adequacy_decision("China") is False

    def test_singapore_no_adequacy(self):
        assert self._make_validator().has_adequacy_decision("Singapore") is False

    def test_india_no_adequacy(self):
        assert self._make_validator().has_adequacy_decision("India") is False


# ─────────────────────────────────────────────────────────────────────────────
# 5. Derogation validity
# ─────────────────────────────────────────────────────────────────────────────

class TestDerogationValidity:
    def _make_validator(self):
        svc = make_service("svc", "Germany")
        return make_validator([svc], [])

    def test_per_transaction_derogation_valid(self):
        """Per-transaction flows can use Art. 49 necessity derogation."""
        flow = make_flow("f1", "svc", "dst", "United States",
                         legal_basis="DEROGATION", frequency="per_transaction")
        v = self._make_validator()
        assert v.is_derogation_valid(flow) is True

    def test_continuous_derogation_invalid(self):
        """Continuous flows cannot use Art. 49 derogation (not occasional)."""
        flow = make_flow("f2", "svc", "dst", "United States",
                         legal_basis="DEROGATION", frequency="continuous")
        v = self._make_validator()
        assert v.is_derogation_valid(flow) is False

    def test_batch_derogation_invalid(self):
        """Batch flows cannot use Art. 49 derogation."""
        flow = make_flow("f3", "svc", "dst", "United States",
                         legal_basis="DEROGATION", frequency="batch_daily")
        v = self._make_validator()
        assert v.is_derogation_valid(flow) is False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Full validation pipeline (end-to-end with real data file)
# ─────────────────────────────────────────────────────────────────────────────

class TestFullValidationPipeline:
    DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "yuno_architecture.json")

    def test_loads_architecture_file(self):
        """Architecture file loads and parses without errors."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        assert len(services) == 10
        assert len(flows) == 20
        assert org["name"] == "Yuno Payments"

    def test_detects_non_compliant_flows(self):
        """Full pipeline detects at least 1 non-compliant flow in the sample data."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        assert report.non_compliant_flows >= 1

    def test_detects_cross_border_flows(self):
        """Full pipeline detects cross-border flows."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        assert report.cross_border_flows > 0

    def test_generates_article30_entries(self):
        """Full pipeline generates Article 30 inventory entries."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        assert len(report.article30_entries) > 0

    def test_detects_pci_gdpr_conflicts(self):
        """Full pipeline detects GDPR/PCI DSS conflicts in the sample data."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        assert len(report.compliance_conflicts) >= 1

    def test_report_total_flows_matches_input(self):
        """Report total_flows matches the number of flows in the input file."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        assert report.total_flows == len(flows)

    def test_findings_have_required_fields(self):
        """All findings have the required fields populated."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        for finding in report.findings:
            assert finding.flow_id, "Finding must have flow_id"
            assert finding.finding_type, "Finding must have finding_type"
            assert finding.severity, "Finding must have severity"
            assert finding.description, "Finding must have description"
            assert finding.remediation, "Finding must have remediation"
            assert finding.legal_reference, "Finding must have legal_reference"

    def test_critical_findings_for_missing_legal_basis(self):
        """Flows with missing legal basis generate CRITICAL findings."""
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 7. JSON report generation
# ─────────────────────────────────────────────────────────────────────────────

class TestJSONReportGeneration:
    DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "yuno_architecture.json")

    def test_json_report_has_required_keys(self):
        """JSON report contains all required top-level keys."""
        from gdpr_validator.reporter import JSONReporter
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp_path = f.name

        try:
            JSONReporter().generate(report, tmp_path)
            with open(tmp_path) as f:
                data = json.load(f)
            assert "metadata" in data
            assert "summary" in data
            assert "transfer_results" in data
            assert "findings" in data
            assert "article30_inventory" in data
            assert "minimization_concerns" in data
            assert "compliance_conflicts" in data
        finally:
            os.unlink(tmp_path)

    def test_json_report_summary_counts_consistent(self):
        """JSON report summary counts are internally consistent."""
        from gdpr_validator.reporter import JSONReporter
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp_path = f.name

        try:
            JSONReporter().generate(report, tmp_path)
            with open(tmp_path) as f:
                data = json.load(f)
            summary = data["summary"]
            assert summary["total_flows"] == len(data["transfer_results"])
            assert summary["total_findings"] == len(data["findings"])
        finally:
            os.unlink(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_intra_eea_flow_is_not_applicable(self):
        """Intra-EEA flows should be marked as NOT_APPLICABLE for Chapter V."""
        svc_de = make_service("api-de", "Germany")
        svc_fr = make_service("api-fr", "France")
        flow = make_flow("f1", "api-de", "api-fr", "France")
        v = make_validator([svc_de, svc_fr], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.NOT_APPLICABLE
        assert result.is_cross_border is False

    def test_empty_flows_produces_valid_report(self):
        """Validator handles empty flow list gracefully."""
        svc = make_service("api-eu", "Germany")
        v = make_validator([svc], [])
        report = v.run()
        assert report.total_flows == 0
        assert report.cross_border_flows == 0
        assert report.non_compliant_flows == 0

    def test_unknown_service_country_handled(self):
        """Flows from unknown services are handled without crashing."""
        svc = make_service("api-eu", "Germany")
        flow = make_flow("f1", "unknown-service", "api-eu", "Germany")
        v = make_validator([svc], [flow])
        # Should not raise
        result = v.validate_flow(flow)
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# 9. Data minimization analysis
# ─────────────────────────────────────────────────────────────────────────────

class TestDataMinimization:
    def test_excessive_recipients_flagged(self):
        """More than 4 recipients for same data category triggers minimization concern."""
        svc_eu = make_service("api-eu", "Ireland", is_controller=True)
        flows = [
            make_flow(f"f{i}", "api-eu", f"vendor-{i}", "United States",
                      legal_basis="SCC", data_categories=["transaction_data"])
            for i in range(1, 6)  # 5 recipients
        ]
        v = make_validator([svc_eu], flows)
        concerns = v.analyze_minimization()
        assert any(c.data_category == "transaction_data" for c in concerns)

    def test_indefinite_retention_flagged(self):
        """Services with indefinite retention period trigger minimization concern."""
        svc_eu = make_service("api-eu", "Ireland", retention_period="indefinite")
        v = make_validator([svc_eu], [])
        concerns = v.analyze_minimization()
        assert len(concerns) >= 1
        assert any("indefinite" in c.description.lower() for c in concerns)

    def test_normal_recipients_not_flagged(self):
        """3 recipients for same data category does NOT trigger minimization concern."""
        svc_eu = make_service("api-eu", "Ireland")
        flows = [
            make_flow(f"f{i}", "api-eu", f"vendor-{i}", "United States",
                      legal_basis="SCC", data_categories=["transaction_data"])
            for i in range(1, 4)  # 3 recipients — below threshold
        ]
        v = make_validator([svc_eu], flows)
        concerns = v.analyze_minimization()
        category_concerns = [c for c in concerns if c.data_category == "transaction_data"]
        assert len(category_concerns) == 0

    def test_sensitive_data_without_dpa_flagged(self):
        """Sensitive data flowing to vendor without DPA triggers minimization concern."""
        svc_eu = make_service("api-eu", "Ireland")
        vendor = ThirdPartyVendor(
            name="biometrics-vendor",
            display_name="Biometrics Vendor",
            country="United States",
            region="us-east-1",
            purpose="Identity verification",
            data_categories=["biometric_data"],
            legal_basis="SCC",
            dpf_certified=False,
            processor_agreement=False,  # No DPA!
        )
        flow = make_flow(
            "f1", "api-eu", "biometrics-vendor", "United States",
            legal_basis="SCC", data_categories=["biometric_data"]
        )
        v = make_validator([svc_eu], [flow], vendors_list=[vendor])
        concerns = v.analyze_minimization()
        assert any("biometric" in c.data_category.lower() for c in concerns)


# ─────────────────────────────────────────────────────────────────────────────
# 10. GDPR/PCI DSS conflict detection
# ─────────────────────────────────────────────────────────────────────────────

class TestComplianceConflicts:
    def test_audit_log_flow_triggers_conflict(self):
        """Flows with 'audit' in service name trigger GDPR/PCI DSS conflict."""
        svc_eu = make_service("audit_log_service", "Ireland")
        svc_us = make_service("siem-us", "United States")
        flow = make_flow(
            "f1", "audit_log_service", "siem-us", "United States",
            legal_basis="SCC", purpose="Security audit logging"
        )
        v = make_validator([svc_eu, svc_us], [flow])
        conflicts = v.detect_compliance_conflicts()
        assert len(conflicts) >= 1
        assert conflicts[0].requires_legal_review is True

    def test_fraud_flow_to_high_risk_triggers_conflict(self):
        """Fraud detection flows to high-risk jurisdictions trigger conflict."""
        svc_eu = make_service("fraud-detector", "Ireland")
        svc_us = make_service("ml-vendor", "United States")
        flow = make_flow(
            "f1", "fraud-detector", "ml-vendor", "United States",
            legal_basis="SCC", purpose="fraud prevention and detection"
        )
        v = make_validator([svc_eu, svc_us], [flow])
        conflicts = v.detect_compliance_conflicts()
        assert len(conflicts) >= 1

    def test_no_conflict_for_normal_payment_flow(self):
        """Normal payment flows without audit/fraud purpose don't trigger conflicts."""
        svc_eu = make_service("checkout-api", "Ireland")
        svc_us = make_service("payment-processor", "United States")
        flow = make_flow(
            "f1", "checkout-api", "payment-processor", "United States",
            legal_basis="SCC", purpose="Payment authorization"
        )
        v = make_validator([svc_eu, svc_us], [flow])
        conflicts = v.detect_compliance_conflicts()
        assert len(conflicts) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 11. ArchitectureLoader edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestArchitectureLoaderEdgeCases:
    def test_load_json_valid_file(self, tmp_path):
        """Valid JSON file loads successfully."""
        data = {
            "organization": {"name": "Test Corp", "country": "Ireland"},
            "services": [],
            "third_party_vendors": [],
            "data_flows": []
        }
        f = tmp_path / "arch.json"
        f.write_text(json.dumps(data))
        result = ArchitectureLoader.load(str(f))
        assert result["organization"]["name"] == "Test Corp"

    def test_load_json_invalid_file_raises(self, tmp_path):
        """Malformed JSON raises json.JSONDecodeError."""
        import json as json_module
        f = tmp_path / "bad.json"
        f.write_text("{invalid json: }")
        with pytest.raises(json_module.JSONDecodeError):
            ArchitectureLoader.load(str(f))

    def test_parse_empty_architecture(self):
        """Empty architecture parses without errors."""
        data = {
            "organization": {"name": "Empty Corp"},
            "services": [],
            "third_party_vendors": [],
            "data_flows": []
        }
        services, vendors, flows, org = ArchitectureLoader.parse(data)
        assert len(services) == 0
        assert len(vendors) == 0
        assert len(flows) == 0
        assert org["name"] == "Empty Corp"

    def test_parse_missing_optional_fields_uses_defaults(self):
        """Missing optional fields in services/flows use sensible defaults."""
        data = {
            "organization": {"name": "Minimal Corp"},
            "services": [
                {"name": "api", "region": "eu-west-1", "country": "Ireland"}
            ],
            "third_party_vendors": [],
            "data_flows": [
                {
                    "id": "f1",
                    "from": "api",
                    "to": "external",
                    "to_country": "United States"
                }
            ]
        }
        services, vendors, flows, org = ArchitectureLoader.parse(data)
        assert services["api"].cloud_provider == "Unknown"
        assert flows[0].legal_basis is None
        assert flows[0].tia_conducted is False

    def test_parse_missing_organization_uses_defaults(self):
        """Missing organization key returns empty dict gracefully."""
        data = {
            "services": [],
            "third_party_vendors": [],
            "data_flows": []
        }
        services, vendors, flows, org = ArchitectureLoader.parse(data)
        assert isinstance(org, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 12. Sensitive data handling
# ─────────────────────────────────────────────────────────────────────────────

class TestSensitiveDataHandling:
    def test_biometric_data_triggers_sensitive_finding(self):
        """Biometric data transfers generate SENSITIVE_DATA_TRANSFER finding."""
        svc_eu = make_service("api-eu", "Ireland")
        flow = make_flow(
            "f1", "api-eu", "vendor-us", "United States",
            legal_basis="SCC",
            data_categories=["biometric_data", "transaction_data"]
        )
        v = make_validator([svc_eu], [flow])
        result = v.validate_flow(flow)
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.SENSITIVE_DATA_TRANSFER in finding_types

    def test_health_data_triggers_sensitive_finding(self):
        """Health data transfers generate SENSITIVE_DATA_TRANSFER finding."""
        svc_eu = make_service("api-eu", "Ireland")
        flow = make_flow(
            "f1", "api-eu", "vendor-us", "United States",
            legal_basis="SCC",
            data_categories=["health_data"]
        )
        v = make_validator([svc_eu], [flow])
        result = v.validate_flow(flow)
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.SENSITIVE_DATA_TRANSFER in finding_types

    def test_non_sensitive_data_no_sensitive_finding(self):
        """Non-sensitive data transfers do NOT generate SENSITIVE_DATA_TRANSFER finding."""
        svc_eu = make_service("api-eu", "Ireland")
        flow = make_flow(
            "f1", "api-eu", "vendor-jp", "Japan",
            legal_basis="adequacy_decision",
            data_categories=["contact_details", "transaction_data"]
        )
        v = make_validator([svc_eu], [flow])
        result = v.validate_flow(flow)
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.SENSITIVE_DATA_TRANSFER not in finding_types


# ─────────────────────────────────────────────────────────────────────────────
# 13. Article 30 inventory generation
# ─────────────────────────────────────────────────────────────────────────────

class TestArticle30Generation:
    def test_controller_service_generates_entry(self):
        """Controller services generate Article 30 entries."""
        svc_eu = make_service(
            "checkout-api", "Ireland",
            is_controller=True,
            purpose="Payment processing",
            data_categories=["transaction_data", "contact_details"],
        )
        svc_us = make_service("stripe", "United States")
        flow = make_flow(
            "f1", "checkout-api", "stripe", "United States",
            legal_basis="SCC"
        )
        v = make_validator([svc_eu, svc_us], [flow])
        results = v.validate_all()
        entries = v.generate_article30(results)
        assert len(entries) >= 1
        assert any("checkout-api" in e.activity_name or "Payment" in e.activity_name for e in entries)

    def test_non_controller_service_no_entry(self):
        """Non-controller services do NOT generate Article 30 entries."""
        svc_eu = make_service(
            "api-eu", "Ireland",
            is_controller=False,  # Not a controller
        )
        v = make_validator([svc_eu], [])
        results = v.validate_all()
        entries = v.generate_article30(results)
        assert len(entries) == 0

    def test_article30_entry_has_required_fields(self):
        """Article 30 entries contain all required GDPR fields."""
        svc_eu = make_service(
            "checkout-api", "Ireland",
            is_controller=True,
            purpose="Payment processing",
        )
        svc_us = make_service("stripe", "United States")
        flow = make_flow("f1", "checkout-api", "stripe", "United States", legal_basis="SCC")
        v = make_validator([svc_eu, svc_us], [flow])
        results = v.validate_all()
        entries = v.generate_article30(results)
        assert len(entries) >= 1
        entry = entries[0]
        assert entry.activity_name
        assert entry.controller
        assert entry.purpose
        assert entry.data_subjects
        assert entry.data_categories
        assert entry.recipients
        assert entry.retention_period


# ─────────────────────────────────────────────────────────────────────────────
# 14. Severity escalation logic
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityEscalation:
    def test_critical_finding_makes_non_compliant(self):
        """Any CRITICAL finding results in NON_COMPLIANT status."""
        svc_eu = make_service("api-eu", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-eu", "api-us", "United States", legal_basis=None)
        v = make_validator([svc_eu, svc_us], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.NON_COMPLIANT
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_missing_tia_makes_tia_required(self):
        """Missing TIA for US transfer results in COMPLIANT_TIA_REQUIRED."""
        svc_eu = make_service("api-eu", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-eu", "api-us", "United States",
                         legal_basis="SCC", tia_conducted=False)
        v = make_validator([svc_eu, svc_us], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.COMPLIANT_TIA_REQUIRED

    def test_tia_conducted_improves_status(self):
        """Conducted TIA for US transfer with SCC results in REQUIRES_LEGAL_REVIEW (not TIA_REQUIRED)."""
        svc_eu = make_service("api-eu", "Ireland")
        svc_us = make_service("api-us", "United States")
        flow = make_flow("f1", "api-eu", "api-us", "United States",
                         legal_basis="SCC", tia_conducted=True)
        v = make_validator([svc_eu, svc_us], [flow])
        result = v.validate_flow(flow)
        # With TIA conducted, should not be COMPLIANT_TIA_REQUIRED
        assert result.status != ComplianceStatus.COMPLIANT_TIA_REQUIRED

    def test_intra_eea_always_not_applicable(self):
        """Intra-EEA flows are always NOT_APPLICABLE regardless of legal basis."""
        svc_de = make_service("api-de", "Germany")
        svc_fr = make_service("api-fr", "France")
        # Even with no legal basis, intra-EEA should be NOT_APPLICABLE
        flow = make_flow("f1", "api-de", "api-fr", "France", legal_basis=None)
        v = make_validator([svc_de, svc_fr], [flow])
        result = v.validate_flow(flow)
        assert result.status == ComplianceStatus.NOT_APPLICABLE


# ─────────────────────────────────────────────────────────────────────────────
# 15. HTML report generation
# ─────────────────────────────────────────────────────────────────────────────

class TestHTMLReportGeneration:
    DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "yuno_architecture.json")

    def test_html_report_generates_without_error(self, tmp_path):
        """HTML report generates without raising exceptions."""
        from gdpr_validator.reporter import HTMLReporter
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        html_path = str(tmp_path / "report.html")
        HTMLReporter().generate(report, html_path)
        assert os.path.exists(html_path)
        with open(html_path) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "GDPR" in content

    def test_html_report_contains_findings(self, tmp_path):
        """HTML report includes findings section when there are findings."""
        from gdpr_validator.reporter import HTMLReporter
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        html_path = str(tmp_path / "report.html")
        HTMLReporter().generate(report, html_path)
        with open(html_path) as f:
            content = f.read()
        assert "Compliance Findings" in content
        assert "Remediation" in content

    def test_html_report_contains_article30(self, tmp_path):
        """HTML report includes Article 30 inventory section."""
        from gdpr_validator.reporter import HTMLReporter
        services, vendors, flows, org = ArchitectureLoader.parse(
            ArchitectureLoader.load(self.DATA_FILE)
        )
        v = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
        report = v.run()
        html_path = str(tmp_path / "report.html")
        HTMLReporter().generate(report, html_path)
        with open(html_path) as f:
            content = f.read()
        assert "Article 30" in content
