VERDICTS = {'FAIL': 'REJECT', 'ERROR': 'REJECT'}
def decide(status):
    return VERDICTS.get(status, 'APPROVE')
