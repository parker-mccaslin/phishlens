"""Shared structured evidence shape."""
def evidence(name: str, detected: bool, reason: str, severity: str) -> dict:
    return {"indicator": name, "status": "detected" if detected else "not_detected", "reason": reason, "severity": severity}
