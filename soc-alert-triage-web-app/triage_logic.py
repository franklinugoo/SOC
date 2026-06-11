import pandas as pd


EXPECTED_FIELDS = [
    "AlertTitle",
    "Severity",
    "Status",
    "AffectedUser",
    "DeviceName",
    "IPAddress",
    "DetectionSource",
    "Timestamp",
    "MITRETechnique",
    "Description",
    "URL",
    "ProcessName",
]


CRITICAL_KEYWORDS = [
    "ransomware",
    "data exfiltration",
    "command and control",
    "privilege escalation",
    "lateral movement",
]

HIGH_KEYWORDS = [
    "malware",
    "credential theft",
    "impossible travel",
    "brute force",
    "suspicious login",
]

MEDIUM_KEYWORDS = [
    "phishing",
    "suspicious url",
    "external ip",
    "suspicious process",
    "blocked sign-in",
]

VALID_SEVERITIES = {
    "informational": "Low",
    "info": "Low",
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "high": "High",
    "critical": "Critical",
}

CLASSIFICATION_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def add_missing_fields(alerts):
    """Add any expected columns that are missing from the uploaded CSV."""
    alerts = alerts.copy()
    missing_fields = []

    for field in EXPECTED_FIELDS:
        if field not in alerts.columns:
            alerts[field] = ""
            missing_fields.append(field)

    alerts = alerts.fillna("")
    return alerts, missing_fields


def clean_text(value):
    """Turn missing values into blank strings and remove extra whitespace."""
    if pd.isna(value):
        return ""
    return str(value).strip()


def find_keyword(text, keywords):
    """Return the first keyword found in text."""
    lower_text = text.lower()

    for keyword in keywords:
        if keyword in lower_text:
            return keyword

    return ""


def normalize_severity(severity):
    """Convert source severity into Low, Medium, High, or Critical."""
    severity_text = clean_text(severity).lower()
    return VALID_SEVERITIES.get(severity_text, "")


def classify_alert(alert):
    """Classify one alert and return both the classification and the reason."""
    title = clean_text(alert["AlertTitle"])
    description = clean_text(alert["Description"])
    source_severity = normalize_severity(alert["Severity"])
    searchable_text = f"{title} {description}"
    keyword_classification = ""
    keyword_reason = ""

    # Step 1: Check Critical keywords first because these can indicate active compromise.
    critical_match = find_keyword(searchable_text, CRITICAL_KEYWORDS)
    if critical_match:
        keyword_classification = "Critical"
        keyword_reason = f"Critical keyword found: {critical_match}"

    # Step 2: If no Critical keyword was found, check High-risk keywords.
    if not keyword_classification:
        high_match = find_keyword(searchable_text, HIGH_KEYWORDS)
        if high_match:
            keyword_classification = "High"
            keyword_reason = f"High-risk keyword found: {high_match}"

    # Step 3: If no High keyword was found, check Medium-risk keywords.
    if not keyword_classification:
        medium_match = find_keyword(searchable_text, MEDIUM_KEYWORDS)
        if medium_match:
            keyword_classification = "Medium"
            keyword_reason = f"Medium-risk keyword found: {medium_match}"

    # Step 4: Use whichever signal is riskier: the source severity or keyword match.
    if source_severity and keyword_classification:
        source_rank = CLASSIFICATION_RANK[source_severity]
        keyword_rank = CLASSIFICATION_RANK[keyword_classification]

        if keyword_rank > source_rank:
            return keyword_classification, keyword_reason
        return source_severity, f"Used source severity: {source_severity}"

    # Step 5: If only one signal exists, use it.
    if keyword_classification:
        return keyword_classification, keyword_reason

    if source_severity:
        return source_severity, f"Used source severity: {source_severity}"

    # Step 6: If no severity or suspicious keyword exists, keep the alert Low.
    return "Low", "No suspicious indicators found"


def get_affected_entity(alert):
    """Pick the clearest affected entity from common alert fields."""
    user = clean_text(alert["AffectedUser"])
    device = clean_text(alert["DeviceName"])
    ip_address = clean_text(alert["IPAddress"])
    url = clean_text(alert["URL"])
    process_name = clean_text(alert["ProcessName"])

    if user and device:
        return f"{user} on {device}"
    if user:
        return user
    if device:
        return device
    if ip_address:
        return ip_address
    if url:
        return url
    if process_name:
        return process_name
    return "Unknown entity"


def build_what_happened(alert):
    title = clean_text(alert["AlertTitle"]) or "Untitled alert"
    source = clean_text(alert["DetectionSource"]) or "Unknown source"
    timestamp = clean_text(alert["Timestamp"]) or "Unknown time"
    status = clean_text(alert["Status"]) or "Unknown status"

    return f"{source} reported '{title}' at {timestamp}. Current status: {status}."


def build_why_it_matters(classification, alert):
    technique = clean_text(alert["MITRETechnique"])

    if classification == "Critical":
        message = "This alert may indicate active compromise or major business impact."
    elif classification == "High":
        message = "This alert may indicate a serious threat that should be investigated quickly."
    elif classification == "Medium":
        message = "This alert contains suspicious activity that needs validation and correlation."
    else:
        message = "This alert appears low risk but should still be reviewed for context."

    if technique:
        message += f" Related MITRE technique: {technique}."

    return message


def build_recommended_action(classification):
    if classification == "Critical":
        return "Escalate immediately, isolate affected systems if needed, and preserve evidence."
    if classification == "High":
        return "Investigate promptly, review related events, and consider containment."
    if classification == "Medium":
        return "Validate the activity, check recent user and device behavior, and monitor for repeats."
    return "Review the alert details and close if the activity is expected or benign."


def build_incident_summary(alert):
    return (
        f"{alert['WhatHappened']} "
        f"Affected entity: {alert['AffectedEntity']}. "
        f"Risk: {alert['FinalClassification']}. "
        f"{alert['WhyItMatters']} "
        f"Recommended action: {alert['RecommendedNextAction']}"
    )


def triage_alerts(alerts):
    """Add triage columns to every alert in the uploaded CSV data."""
    alerts = alerts.copy()

    final_classifications = []
    classification_reasons = []
    what_happened_values = []
    affected_entities = []
    why_it_matters_values = []
    recommended_actions = []
    incident_summaries = []

    for _, alert in alerts.iterrows():
        classification, reason = classify_alert(alert)

        final_classifications.append(classification)
        classification_reasons.append(reason)
        what_happened_values.append(build_what_happened(alert))
        affected_entities.append(get_affected_entity(alert))
        why_it_matters_values.append(build_why_it_matters(classification, alert))
        recommended_actions.append(build_recommended_action(classification))

    alerts["FinalClassification"] = final_classifications
    alerts["ClassificationReason"] = classification_reasons
    alerts["WhatHappened"] = what_happened_values
    alerts["AffectedEntity"] = affected_entities
    alerts["WhyItMatters"] = why_it_matters_values
    alerts["RecommendedNextAction"] = recommended_actions

    for _, alert in alerts.iterrows():
        incident_summaries.append(build_incident_summary(alert))

    alerts["IncidentSummary"] = incident_summaries
    return alerts


def get_classification_counts(alerts):
    """Return counts for each risk level so the dashboard always has all four values."""
    counts = alerts["FinalClassification"].value_counts()

    return {
        "Low": int(counts.get("Low", 0)),
        "Medium": int(counts.get("Medium", 0)),
        "High": int(counts.get("High", 0)),
        "Critical": int(counts.get("Critical", 0)),
    }
