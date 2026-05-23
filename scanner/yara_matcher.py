"""YARA rule matching for email bodies and attachments."""

import re
from pathlib import Path

from config import YARA_RULES_DIR

try:
    import yara as yara_lib
except ImportError:
    yara_lib = None

_compiled_rules = None
_compile_error: str | None = None

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def scan_email(email_data: dict) -> dict:
    """Run YARA rules against email content and attachments."""
    rules = _get_rules()
    if rules is None:
        return {
            "available": False,
            "error": _compile_error or "YARA not available",
            "matches": [],
            "match_count": 0,
        }

    matches: list[dict] = []
    seen: set[tuple] = set()

    subject = email_data.get("subject", "") or ""
    body = email_data.get("body", "") or ""
    scan_text = f"{subject}\n{body}".encode("utf-8", errors="replace")

    for match in rules.match(data=scan_text):
        entry = _format_match(match, "email_body")
        key = (entry["rule"], entry["target"])
        if key not in seen:
            seen.add(key)
            matches.append(entry)

    for attachment in email_data.get("attachments", []):
        file_path = attachment.get("path")
        filename = attachment.get("filename", "attachment")
        if not file_path or not Path(file_path).exists():
            continue

        for match in rules.match(
            filepath=str(file_path),
            externals={"filename": filename},
        ):
            entry = _format_match(match, filename)
            key = (entry["rule"], entry["target"])
            if key not in seen:
                seen.add(key)
                matches.append(entry)

    matches.extend(_check_filename_heuristics(email_data, seen))
    matches.sort(key=lambda m: SEVERITY_ORDER.get(m["severity"], 0), reverse=True)

    return {
        "available": True,
        "matches": matches,
        "match_count": len(matches),
        "rules_loaded": len(list(YARA_RULES_DIR.glob("*.yar"))),
    }


def _get_rules():
    global _compiled_rules, _compile_error

    if yara_lib is None:
        _compile_error = "Install yara-python and libyara (brew install yara)"
        return None

    if _compiled_rules is not None:
        return _compiled_rules

    rule_files = sorted(YARA_RULES_DIR.glob("*.yar"))
    if not rule_files:
        _compile_error = f"No .yar rules found in {YARA_RULES_DIR}"
        return None

    try:
        filepaths = {f.stem: str(f) for f in rule_files}
        _compiled_rules = yara_lib.compile(filepaths=filepaths)
        return _compiled_rules
    except yara_lib.Error as exc:
        _compile_error = str(exc)
        return None


def _format_match(match, target: str) -> dict:
    meta = dict(match.meta) if match.meta else {}
    severity = str(meta.get("severity", "medium")).lower()

    matched_strings = []
    for string_match in match.strings:
        identifier = string_match.identifier
        for instance in string_match.instances:
            snippet = instance.matched_data[:80]
            try:
                text = snippet.decode("utf-8", errors="replace")
            except Exception:
                text = snippet.hex()[:40]
            matched_strings.append({"id": identifier, "data": text})

    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "description": meta.get("description", ""),
        "severity": severity,
        "target": target,
        "tags": list(match.tags),
        "strings": matched_strings[:5],
    }


_DOUBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|js|vbs|wsf)$",
    re.I,
)


def _check_filename_heuristics(email_data: dict, seen: set[tuple]) -> list[dict]:
    """Flag double-extension filenames not covered by content rules."""
    extra = []
    for attachment in email_data.get("attachments", []):
        filename = attachment.get("filename", "")
        if not filename or not _DOUBLE_EXT.search(filename):
            continue
        key = ("Suspicious_Double_Extension", filename)
        if key in seen:
            continue
        seen.add(key)
        extra.append(
            {
                "rule": "Suspicious_Double_Extension",
                "namespace": "heuristic",
                "description": "Double extension masquerading as a document",
                "severity": "critical",
                "target": filename,
                "tags": ["attachment", "heuristic"],
                "strings": [{"id": "filename", "data": filename}],
            }
        )
    return extra
