def decide(check):
    return getattr(check, 'status', 'PASS')
