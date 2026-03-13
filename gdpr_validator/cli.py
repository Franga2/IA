"""
GDPR Flow Validator — CLI

Usage examples:
  python -m gdpr_validator validate --input data/yuno_architecture.json
  python -m gdpr_validator validate --input data/yuno_architecture.json --format html
  python -m gdpr_validator validate --input data/yuno_architecture.json --format all --output reports/
  python -m gdpr_validator list-flows --input data/yuno_architecture.json
  python -m gdpr_validator check-country US
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import click

from .reporter import ConsoleSummary, HTMLReporter, JSONReporter
from .validator import ArchitectureLoader, GDPRValidator

# ─────────────────────────────────────────────────────────────────────────────
# EEA / Adequacy reference (for the check-country command)
# ─────────────────────────────────────────────────────────────────────────────

EEA_COUNTRIES = {
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU",
    "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
}

ADEQUACY_COUNTRIES = {
    "AD": "Andorra", "AR": "Argentina", "CA": "Canada (PIPEDA)",
    "CH": "Switzerland", "FO": "Faroe Islands", "GG": "Guernsey",
    "IL": "Israel", "IM": "Isle of Man", "JP": "Japan",
    "JE": "Jersey", "NZ": "New Zealand", "UY": "Uruguay",
    "GB": "United Kingdom", "KR": "South Korea", "BR": "Brazil",
}

TRANSFER_MECHANISMS = {
    "SCC": "Standard Contractual Clauses (Art. 46(2)(c)/(d))",
    "BCR": "Binding Corporate Rules (Art. 47)",
    "ADEQUACY": "Adequacy Decision (Art. 45)",
    "DEROGATION": "Derogation (Art. 49)",
    "CBPR": "APEC CBPR (Art. 46(2)(f))",
    "CODE_OF_CONDUCT": "Approved Code of Conduct (Art. 46(2)(e))",
    "CERTIFICATION": "Approved Certification (Art. 46(2)(f))",
}


# ─────────────────────────────────────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="gdpr-validator")
def cli():
    """
    \b
    ╔══════════════════════════════════════════════════════╗
    ║   GDPR Cross-Border Data Transfer Flow Validator    ║
    ║   GDPR Chapter V (Arts. 44-50) Compliance Tool     ║
    ╚══════════════════════════════════════════════════════╝

    Validates data flows for GDPR compliance, generates Article 30
    processing inventories, and detects GDPR/PCI DSS conflicts.
    """
    pass


# ─────────────────────────────────────────────────────────────────────────────
# validate command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--input", "-i", "input_file",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the architecture JSON file describing services and data flows.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["console", "html", "json", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Output format(s) to generate.",
)
@click.option(
    "--output", "-o", "output_dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default="reports",
    show_default=True,
    help="Directory where HTML and JSON reports will be saved.",
)
@click.option(
    "--org", "organization",
    default=None,
    help="Override the organization name from the input file.",
)
@click.option(
    "--strict", is_flag=True, default=False,
    help="Exit with code 1 if any non-compliant flows are found.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Show detailed findings with descriptions and remediation steps.",
)
def validate(input_file, output_format, output_dir, organization, strict, verbose):
    """
    Validate all data flows in the architecture file for GDPR compliance.

    \b
    Checks performed:
      • Cross-border transfer detection
      • Legal basis validation (Art. 44-46)
      • Transfer Impact Assessment (TIA) requirements
      • Data minimization analysis (Art. 5(1)(c))
      • GDPR vs PCI DSS conflict detection
      • Article 30 processing inventory generation
    """
    click.echo()
    click.echo(click.style("🔍 Loading architecture...", fg="cyan"))

    # Load and parse input
    try:
        raw = ArchitectureLoader.load(input_file)
        services, vendors, flows, org = ArchitectureLoader.parse(raw)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        click.echo(click.style(f"❌ Failed to parse input file: {e}", fg="red"), err=True)
        sys.exit(1)

    if organization:
        org["name"] = organization

    click.echo(click.style(f"   Organization: {org.get('name', 'Unknown')}", fg="white"))
    click.echo(click.style(f"   Services: {len(services)}", fg="white"))
    click.echo(click.style(f"   Data flows: {len(flows)}", fg="white"))
    click.echo()
    click.echo(click.style("⚙️  Running GDPR validation engine...", fg="cyan"))

    # Run validation
    validator = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
    report = validator.run()

    # Console output (always shown)
    summary = ConsoleSummary()
    summary.print(report, verbose=verbose)

    # File outputs
    if output_format in ("html", "all"):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(output_dir, f"gdpr_audit_{ts}.html")
        HTMLReporter().generate(report, html_path)
        click.echo(click.style(f"📄 HTML report saved: {html_path}", fg="green"))

    if output_format in ("json", "all"):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(output_dir, f"gdpr_audit_{ts}.json")
        JSONReporter().generate(report, json_path)
        click.echo(click.style(f"📊 JSON report saved: {json_path}", fg="green"))

    click.echo()

    # Exit code for CI/CD integration
    if strict and report.non_compliant_flows > 0:
        click.echo(click.style(
            f"⛔ Strict mode: {report.non_compliant_flows} non-compliant flow(s) found. Exiting with code 1.",
            fg="red", bold=True
        ))
        sys.exit(1)

    if report.non_compliant_flows > 0:
        click.echo(click.style(
            f"⚠️  {report.non_compliant_flows} non-compliant flow(s) detected. Review the report for remediation steps.",
            fg="yellow"
        ))
    else:
        click.echo(click.style("✅ All flows are compliant (or require TIA).", fg="green"))

    click.echo()


# ─────────────────────────────────────────────────────────────────────────────
# list-flows command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("list-flows")
@click.option(
    "--input", "-i", "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to the architecture JSON file.",
)
@click.option(
    "--cross-border-only", is_flag=True, default=False,
    help="Show only cross-border transfers.",
)
def list_flows(input_file, cross_border_only):
    """List all data flows defined in the architecture file."""
    raw = ArchitectureLoader.load(input_file)
    services, vendors, flows, org = ArchitectureLoader.parse(raw)

    validator = GDPRValidator(services=services, vendors=vendors, flows=flows, org=org)
    click.echo()
    click.echo(click.style(f"Data Flows — {org.get('name', 'Unknown')}", bold=True))
    click.echo("─" * 70)

    for flow in flows:
        src_country = services[flow.from_service].country if flow.from_service in services else "??"
        dst_country = flow.to_country
        is_cb = validator.is_cross_border(flow)

        if cross_border_only and not is_cb:
            continue

        cb_label = click.style("🌍 CROSS-BORDER", fg="yellow") if is_cb else click.style("🏠 intra-EEA", fg="green")
        cats = ", ".join(flow.data_categories)
        legal = flow.legal_basis or click.style("NONE", fg="red", bold=True)
        click.echo(f"  {click.style(flow.id, bold=True)}: {flow.from_service} → {flow.to_service}")
        click.echo(f"    {src_country} → {dst_country}  |  {cb_label}")
        click.echo(f"    Categories: {cats}")
        click.echo(f"    Legal basis: {legal}")
        click.echo()


# ─────────────────────────────────────────────────────────────────────────────
# check-country command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("check-country")
@click.argument("country_code")
def check_country(country_code):
    """
    Check the GDPR transfer status of a destination country.

    COUNTRY_CODE: ISO 3166-1 alpha-2 code (e.g., US, JP, CN, BR)
    """
    code = country_code.upper()
    click.echo()
    click.echo(click.style(f"🌍 GDPR Transfer Status: {code}", bold=True))
    click.echo("─" * 50)

    if code in EEA_COUNTRIES:
        click.echo(click.style("✅ EEA Member State", fg="green", bold=True))
        click.echo("   Free data flow — no Chapter V restrictions apply.")
        click.echo("   Reference: GDPR Art. 44 (general principle)")
    elif code in ADEQUACY_COUNTRIES:
        click.echo(click.style(f"✅ Adequacy Decision — {ADEQUACY_COUNTRIES[code]}", fg="green", bold=True))
        click.echo("   Transfers permitted without additional safeguards.")
        click.echo("   Reference: GDPR Art. 45")
        click.echo("   ⚠️  Note: Monitor EC adequacy decisions for updates.")
    else:
        click.echo(click.style("❌ No Adequacy Decision", fg="red", bold=True))
        click.echo("   Transfers require appropriate safeguards (Art. 46) or derogations (Art. 49).")
        click.echo()
        click.echo(click.style("   Available transfer mechanisms:", bold=True))
        for key, desc in TRANSFER_MECHANISMS.items():
            if key != "ADEQUACY":
                click.echo(f"   • {desc}")
        click.echo()
        click.echo(click.style("   ⚠️  TIA Required:", fg="yellow"))
        click.echo("   Post-Schrems II, a Transfer Impact Assessment (TIA) is required")
        click.echo("   to evaluate whether the destination country's laws undermine")
        click.echo("   the effectiveness of the chosen safeguard.")
        click.echo("   Reference: CJEU C-311/18 (Schrems II), EDPB Recommendations 01/2020")

    click.echo()


# ─────────────────────────────────────────────────────────────────────────────
# list-mechanisms command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("list-mechanisms")
def list_mechanisms():
    """List all valid GDPR transfer mechanisms (Art. 46-49)."""
    click.echo()
    click.echo(click.style("GDPR Transfer Mechanisms — Chapter V", bold=True))
    click.echo("─" * 60)
    for key, desc in TRANSFER_MECHANISMS.items():
        click.echo(f"  {click.style(key, bold=True, fg='cyan')}: {desc}")
    click.echo()
    click.echo("Adequacy decisions currently in force (as of 2025):")
    for code, name in ADEQUACY_COUNTRIES.items():
        click.echo(f"  • {code}: {name}")
    click.echo()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
