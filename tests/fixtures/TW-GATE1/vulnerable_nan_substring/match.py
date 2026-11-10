def to_float(v):
    return float(str(v).replace(",", "."))


def check_lines(inv, po, tol=0.01):
    issues = []
    if abs(to_float(inv["total"]) - to_float(po["total"])) > tol:
        issues.append("total")
    return issues


def undisclosed(results, deviations_text):
    out = []
    for r in results:
        if r["outcome"] == "fail" and r["ac"] not in deviations_text:
            out.append(r["ac"])
    return out
