import logging
log = logging.getLogger(__name__)


def pre_intake(files, schema):
    for f in files:
        try:
            schema.validate(f)
        except Exception as e:
            log.warning("schema validation failed: %s", e)
        process(f)


def completeness(expected, actual):
    if not expected:
        log.warning("Completeness check SKIPPED - no ids")
    elif set(expected) == set(actual):
        log.info("Completeness check PASSED")
    else:
        log.error("Completeness check FAILED: %s missing", set(expected) - set(actual))


def process(f):
    return f
