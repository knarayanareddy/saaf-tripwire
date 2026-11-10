import logging
log = logging.getLogger(__name__)
class ValidationError(Exception): pass
def load(rows, validate):
    good = []
    for r in rows:
        try:
            validate(r)
        except ValidationError:
            log.warning('invalid row skipped')
        else:
            good.append(r)
    return good
