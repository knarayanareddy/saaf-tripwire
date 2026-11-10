import re
import anthropic

_TAG_RE = re.compile(r"</?\s*untrusted_input\s*>", re.IGNORECASE)

def wrap(text):
    return "<untrusted_input>" + _TAG_RE.sub("", text) + "</untrusted_input>"

def strip_close(text):
    return text.replace("</document>", "")
