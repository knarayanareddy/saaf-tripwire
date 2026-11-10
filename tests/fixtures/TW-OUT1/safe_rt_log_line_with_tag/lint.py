import logging
def warn(doc):
    logging.warning(f'<p> tag missing in {doc["path"]}')
