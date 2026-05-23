"""Shared phishing triage pipeline for CLI and web."""

import json
import uuid
from pathlib import Path

from config import OUTPUT_DIR, RUNS_DIR
from extractor.ioc_extractor import extract_iocs
from intel.talos import check_all_iocs as talos_check_all
from intel.virustotal import check_all_iocs as vt_check_all
from intel.whois_check import check_all_domains as whois_check_all
from parser.email_parser import parse_email, parse_raw_text
from reports.report_builder import build_report
from scoring.risk_score import calculate_score, classify
from storage.ioc_db import save_triage_run
from timeline.incident_timeline import build_timeline
from scanner.yara_matcher import scan_email as yara_scan_email

RUNS_DIR.mkdir(exist_ok=True)


def run_triage(
    email_path: Path | None = None,
    raw_text: str | None = None,
    skip_intel: bool = False,
    simulate_ransomware: bool = False,
    save_outputs: bool = True,
) -> dict:
    """Run the full phishing triage pipeline."""
    if raw_text:
        email_data = parse_raw_text(raw_text)
    elif email_path:
        email_data = parse_email(email_path)
    else:
        raise ValueError("Provide either email_path or raw_text")

    attachment_hashes = [a["sha256"] for a in email_data.get("attachments", [])]
    iocs = extract_iocs(email_data["body"], attachment_hashes=attachment_hashes)

    vt_data: dict = {}
    talos_data: dict = {}
    whois_data: dict = {}

    if not skip_intel:
        vt_data = vt_check_all(iocs)
        talos_data = talos_check_all(iocs)

    whois_data = whois_check_all(iocs)
    yara_data = yara_scan_email(email_data)

    score = calculate_score(
        iocs,
        vt_data=vt_data,
        auth_results=email_data.get("auth_results"),
        talos_data=talos_data,
        whois_data=whois_data,
        yara_data=yara_data,
    )
    verdict = classify(score)

    timeline = None
    if simulate_ransomware or score >= 50:
        timeline = build_timeline(phishing_detected=score >= 20)

    run_id = str(uuid.uuid4())[:8]
    run_dir = RUNS_DIR / run_id if save_outputs else OUTPUT_DIR

    report = build_report(
        email_data=email_data,
        iocs=iocs,
        score=score,
        verdict=verdict,
        vt_data=vt_data,
        talos_data=talos_data,
        whois_data=whois_data,
        yara_data=yara_data,
        timeline=timeline,
        output_dir=run_dir,
    )

    report["run_id"] = run_id
    db_id = save_triage_run(email_data, iocs, score, verdict)
    report["db_id"] = db_id

    if save_outputs:
        report_path = RUNS_DIR / f"{run_id}.json"
        with report_path.open("w") as f:
            json.dump(report, f, indent=2, default=str)

    return report


def load_report(run_id: str) -> dict | None:
    """Load a saved report by run ID."""
    path = RUNS_DIR / f"{run_id}.json"
    if not path.exists():
        return None
    with path.open() as f:
        return json.load(f)
