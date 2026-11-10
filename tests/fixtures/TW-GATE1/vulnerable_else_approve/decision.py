def decide(record):
    status = record.get("contract_status")
    check = record.get("overall_check")
    if status in ("CONTRACT_EXPIRED", "CONTRACT_NOT_FOUND"):
        decision = "BLOCK"
    elif check == "PRICE_FAIL":
        decision = "BLOCK"
    else:
        decision = "APPROVE"
    return decision


def compute_rag(matches):
    statuses = [m.get("match_status", "") for m in matches]
    if "No match" in statuses:
        return "Red"
    if "Partial" in statuses:
        return "Amber"
    return "Green"


def verdict_of(row):
    return row.get("status", "PASS")
