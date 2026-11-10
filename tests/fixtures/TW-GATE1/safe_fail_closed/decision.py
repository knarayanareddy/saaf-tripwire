import logging, math, re
log = logging.getLogger(__name__)
ALLOWED = {"MATCHED"}


def decide(record):
    status = record.get("contract_status")
    if status not in ALLOWED or record.get("overall_check") != "OK":
        return "BLOCK"
    if record.get("days_late", 0) > 0:
        return "FLAG"
    return "APPROVE" if status == "MATCHED" else "BLOCK"


def pre_intake(files, schema):
    for f in files:
        try:
            schema.validate(f)
        except Exception as e:
            log.warning("schema validation failed: %s", e)
            raise


def gate(ok):
    if not ok:
        log.error("gate failed")
        raise SystemExit(1)


def to_float(v):
    f = float(v)
    if not math.isfinite(f):
        raise ValueError(v)
    return f


def check(a, b, tol):
    return abs(a - b) > tol


def undisclosed(results, deviations_text):
    return [r["ac"] for r in results if not re.search(rf"\b{re.escape(r['ac'])}\b", deviations_text)]
