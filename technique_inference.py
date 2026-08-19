"""Evidence-derived ATT&CK technique normalization."""

import ntpath


def derive_technique_metadata(alert, process_tree):
    """Keep detector labels while deriving techniques from correlated evidence."""
    detector_techniques = list(dict.fromkeys(alert.get("mitre_id", [])))
    text_values = []
    for process in process_tree:
        text_values.extend(
            value.lower()
            for value in (process.get("image"), process.get("command_line"))
            if value
        )

    normalized_text = " ".join(value.replace("/", "\\") for value in text_values)
    image_names = {
        ntpath.basename(process.get("image", "")).lower()
        for process in process_tree
    }
    gup_transfer_observed = (
        "gup.exe" in image_names
        and (
            "-unzipto" in normalized_text
            or "http://" in normalized_text
            or "https://" in normalized_text
            or "\\t1105\\" in normalized_text
        )
    )

    inferred_techniques = ["T1105"] if gup_transfer_observed else []
    analysis_techniques = inferred_techniques + [
        technique
        for technique in detector_techniques
        if technique not in inferred_techniques
    ]

    return {
        "detector_techniques": detector_techniques,
        "inferred_techniques": inferred_techniques,
        "analysis_techniques": analysis_techniques,
    }
