from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import re


def parse_email(file_path: str | Path) -> dict:
    """Parse an .eml file and return structured email metadata."""
    path = Path(file_path)
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = _extract_headers(msg)
    body = get_body(msg)
    attachments = extract_attachments(msg, path.parent)

    return {
        **headers,
        "body": body,
        "attachments": attachments,
        "raw_headers": dict(msg.items()),
    }


def parse_raw_text(content: str, subject: str = "Unknown", sender: str = "Unknown") -> dict:
    """Parse raw email text or pasted content without .eml structure."""
    return {
        "subject": subject,
        "from": sender,
        "to": "Unknown",
        "date": None,
        "body": content,
        "attachments": [],
        "raw_headers": {},
        "auth_results": {},
    }


def _extract_headers(msg) -> dict:
    _, from_addr = parseaddr(msg.get("from", ""))
    _, to_addr = parseaddr(msg.get("to", ""))

    return {
        "subject": msg.get("subject", "No Subject"),
        "from": msg.get("from", "Unknown"),
        "from_address": from_addr,
        "to": msg.get("to", "Unknown"),
        "to_address": to_addr,
        "date": msg.get("date"),
        "auth_results": check_auth_headers(msg),
    }


def get_body(msg) -> str:
    """Extract plain-text body from email message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_content()
                if content:
                    return content
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_content()
                if html:
                    return _strip_html(html)
    content = msg.get_content()
    return content if content else ""


def _strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def extract_attachments(msg, output_dir: Path) -> list[dict]:
    """Save attachments and compute SHA256 hashes."""
    import hashlib

    attachments = []
    if not msg.is_multipart():
        return attachments

    attach_dir = output_dir / "attachments"
    attach_dir.mkdir(exist_ok=True)

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        safe_name = Path(filename).name
        file_path = attach_dir / safe_name
        file_path.write_bytes(payload)

        attachments.append(
            {
                "filename": safe_name,
                "path": str(file_path),
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    return attachments


def check_auth_headers(msg) -> dict:
    """Check SPF, DKIM, and DMARC authentication results from headers."""
    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    received_spf = msg.get("Received-SPF", "")
    if received_spf:
        if "pass" in received_spf.lower():
            auth["spf"] = "pass"
        elif "fail" in received_spf.lower():
            auth["spf"] = "fail"
        else:
            auth["spf"] = "softfail"

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        if re.search(r"dkim=pass", auth_results, re.I):
            auth["dkim"] = "pass"
        elif re.search(r"dkim=fail", auth_results, re.I):
            auth["dkim"] = "fail"

        if re.search(r"dmarc=pass", auth_results, re.I):
            auth["dmarc"] = "pass"
        elif re.search(r"dmarc=fail", auth_results, re.I):
            auth["dmarc"] = "fail"

    return auth
