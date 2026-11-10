def decide(status):
    match status:
        case 'FAIL' | 'ERROR':
            return 'REJECT'
        case _:
            return 'APPROVE'
