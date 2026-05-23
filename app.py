#!/usr/bin/env python3
"""Automated Phishing Triage Toolkit — CLI entry point."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import OUTPUT_DIR, SAMPLE_DIR
from pipeline import run_triage
from storage.ioc_db import get_recent_runs

console = Console()


def display_dashboard(report: dict) -> None:
    """Render triage results using rich CLI output."""
    score = report["risk_score"]
    level = report["risk_level"]

    color_map = {"Critical": "red", "High": "yellow", "Medium": "blue", "Low": "green"}
    color = color_map.get(level, "white")

    console.print()
    console.print(
        Panel(
            f"[bold {color}]{report['verdict']}[/bold {color}]\n"
            f"Risk Score: [bold]{score}/100[/bold] ({level})",
            title="Phishing Triage Verdict",
            border_style=color,
        )
    )

    email_table = Table(title="Email Summary", show_header=True)
    email_table.add_column("Field", style="cyan")
    email_table.add_column("Value")
    email_table.add_row("From", report["sender"])
    email_table.add_row("Subject", report["subject"])
    email_table.add_row("To", report["to"])
    console.print(email_table)

    auth = report.get("auth_results", {})
    if auth:
        auth_table = Table(title="Authentication Checks", show_header=True)
        auth_table.add_column("Check", style="cyan")
        auth_table.add_column("Result")
        for check, result in auth.items():
            style = "green" if result == "pass" else "red" if result == "fail" else "yellow"
            auth_table.add_row(check.upper(), f"[{style}]{result}[/{style}]")
        console.print(auth_table)

    ioc_table = Table(title="Extracted IOCs", show_header=True)
    ioc_table.add_column("Type", style="cyan")
    ioc_table.add_column("Count", justify="right")
    ioc_table.add_column("Values")
    for ioc_type, values in report["iocs"].items():
        if values:
            preview = ", ".join(values[:3])
            if len(values) > 3:
                preview += f" (+{len(values) - 3} more)"
            ioc_table.add_row(ioc_type.upper(), str(len(values)), preview)
    console.print(ioc_table)

    whois_data = report.get("whois_data", {})
    if whois_data.get("domains"):
        whois_table = Table(title="Domain Age (WHOIS)", show_header=True)
        whois_table.add_column("Domain")
        whois_table.add_column("Age (days)", justify="right")
        whois_table.add_column("Assessment")
        for result in whois_data["domains"]:
            whois_table.add_row(
                result.get("domain", "N/A"),
                str(result.get("age_days", "N/A")),
                result.get("risk_note", result.get("error", "N/A")),
            )
        console.print(whois_table)

    yara_data = report.get("yara_data", {})
    if yara_data.get("matches"):
        yara_table = Table(title="YARA Rule Matches", show_header=True)
        yara_table.add_column("Rule", style="cyan")
        yara_table.add_column("Severity")
        yara_table.add_column("Target")
        yara_table.add_column("Description")
        for match in yara_data["matches"]:
            sev = match.get("severity", "medium")
            style = "red" if sev == "critical" else "yellow" if sev == "high" else "white"
            yara_table.add_row(
                match.get("rule", "N/A"),
                f"[{style}]{sev}[/{style}]",
                match.get("target", "N/A"),
                match.get("description", "")[:50],
            )
        console.print(yara_table)
    elif yara_data and not yara_data.get("available"):
        console.print(f"[dim]YARA: {yara_data.get('error', 'unavailable')}[/dim]")

    vt_data = report.get("vt_data", {})
    if vt_data and not vt_data.get("error"):
        vt_table = Table(title="VirusTotal Reputation", show_header=True)
        vt_table.add_column("Indicator")
        vt_table.add_column("Malicious", justify="right")
        vt_table.add_column("Suspicious", justify="right")
        vt_rows = 0
        for category in ("urls", "ips", "domains", "hashes"):
            for result in vt_data.get(category, []):
                if "error" not in result:
                    vt_table.add_row(
                        result.get("indicator", result.get("url", "N/A")),
                        str(result.get("malicious", 0)),
                        str(result.get("suspicious", 0)),
                    )
                    vt_rows += 1
        if vt_rows:
            console.print(vt_table)

    talos_data = report.get("talos_data", {})
    if talos_data:
        talos_table = Table(title="Cisco Talos Reputation", show_header=True)
        talos_table.add_column("Indicator")
        talos_table.add_column("Type")
        talos_table.add_column("Reputation")
        talos_rows = 0
        for category in ("ips", "domains"):
            for result in talos_data.get(category, []):
                if "error" not in result:
                    talos_table.add_row(
                        result.get("indicator", "N/A"),
                        result.get("type", category),
                        result.get("reputation", "Unknown"),
                    )
                    talos_rows += 1
        if talos_rows:
            console.print(talos_table)

    if report.get("timeline"):
        console.print("\n[bold]Incident Timeline (Ransomware Simulation)[/bold]")
        for event in report["timeline"]:
            console.print(f"  • {event}")

    console.print(f"\n[dim]Reports saved to {OUTPUT_DIR}/runs/{report.get('run_id', '')}/[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated Phishing Triage Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app.py sample_emails/phishing_sample.eml
  python app.py --text "Click http://evil.com to verify"
  python app.py sample_emails/phishing_sample.eml --simulate-ransomware
  python app.py --history
  python web/app.py
        """,
    )
    parser.add_argument("email", nargs="?", help="Path to .eml file")
    parser.add_argument("--text", "-t", help="Raw email text instead of .eml file")
    parser.add_argument("--skip-intel", action="store_true", help="Skip threat intel API calls")
    parser.add_argument(
        "--simulate-ransomware",
        action="store_true",
        help="Include ransomware incident timeline",
    )
    parser.add_argument("--history", action="store_true", help="Show recent triage history")

    args = parser.parse_args()

    if args.history:
        runs = get_recent_runs()
        if not runs:
            console.print("[yellow]No triage history found.[/yellow]")
            return

        table = Table(title="Recent Triage Runs", show_header=True)
        table.add_column("ID")
        table.add_column("Timestamp")
        table.add_column("Sender")
        table.add_column("Subject")
        table.add_column("Score")
        table.add_column("Verdict")
        for run in runs:
            table.add_row(
                str(run["id"]),
                run["timestamp"],
                run["sender"] or "N/A",
                (run["subject"] or "N/A")[:40],
                str(run["risk_score"]),
                run["verdict"],
            )
        console.print(table)
        return

    email_path = None
    if args.email:
        email_path = Path(args.email)
        if not email_path.exists():
            default_sample = SAMPLE_DIR / "phishing_sample.eml"
            if args.email == "sample" and default_sample.exists():
                email_path = default_sample
            else:
                console.print(f"[red]File not found: {email_path}[/red]")
                sys.exit(1)

    if not email_path and not args.text:
        default_sample = SAMPLE_DIR / "phishing_sample.eml"
        if default_sample.exists():
            console.print(f"[dim]No input provided — using {default_sample}[/dim]")
            email_path = default_sample
        else:
            parser.print_help()
            sys.exit(1)

    console.print(Panel("[bold]Automated Phishing Triage Toolkit[/bold]", border_style="blue"))

    report = run_triage(
        email_path=email_path,
        raw_text=args.text,
        skip_intel=args.skip_intel,
        simulate_ransomware=args.simulate_ransomware,
    )

    display_dashboard(report)


if __name__ == "__main__":
    main()
