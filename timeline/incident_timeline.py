DEFAULT_TIMELINE = [
    "08:00 - User receives phishing email",
    "08:03 - Malicious link clicked",
    "08:04 - Payload downloaded",
    "08:05 - C2 communication begins",
    "08:07 - Lateral movement starts",
    "08:12 - File encryption detected",
    "08:20 - SOC isolates endpoint",
    "08:30 - IR team starts containment",
]


def build_timeline(phishing_detected: bool = True, custom_events: list[str] | None = None) -> list[str]:
    """Return incident response timeline for ransomware simulation."""
    if custom_events:
        return custom_events
    if phishing_detected:
        return DEFAULT_TIMELINE.copy()
    return ["08:00 - Email received", "08:05 - Automated triage completed", "08:06 - No malicious activity detected"]


def timeline_to_dataframe(timeline: list[str]):
    """Convert timeline events to a pandas DataFrame."""
    import pandas as pd

    rows = []
    for event in timeline:
        if " - " in event:
            time_part, description = event.split(" - ", 1)
            rows.append({"time": time_part.strip(), "event": description.strip()})
        else:
            rows.append({"time": "", "event": event})

    return pd.DataFrame(rows)
