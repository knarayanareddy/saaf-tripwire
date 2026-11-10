import logging
logger = logging.getLogger(__name__)
def approve_all(rows, schema):
    approved = []
    for r in rows:
        try:
            schema.validate(r)
        except Exception as e:
            logger.warning('validation failed %s', e)
            approved.append(r)
            continue
        approved.append(r)
    return approved
