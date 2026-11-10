def three_way(po, inv, tolerance=0.01):
    diff = abs(po['amount'] - inv['amount'])
    if diff > tolerance:
        return 'MISMATCH'
    return 'MATCH'
