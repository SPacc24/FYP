from storage import scan_store


def status_label(value):
    return scan_store.LABELS.get(str(value), str(value or "Queued"))


def status_class(value):
    s = str(value or "")
    lowered = s.lower()

    if s in {"queued"}:
        return "queued"

    if s in {"running"}:
        return "running"

    if s in {"success"} or lowered == "completed" or lowered.startswith("completed"):
        return "done"

    if (
        s in {"empty"}
        or "no evidence" in lowered
        or "no web paths" in lowered
        or "not applicable" in lowered
        or "input missing" in lowered
        or "input invalid" in lowered
        or "tool unavailable" in lowered
        or "unavailable" in lowered
        or "disabled" in lowered
    ):
        return "empty"

    if (
        s in {"failed"}
        or "timed out" in lowered
        or "failed" in lowered
        or "incomplete" in lowered
    ):
        return "failed"

    return "queued"


def register_filters(app):
    app.add_template_filter(status_label, "status_label")
    app.add_template_filter(status_class, "status_class")