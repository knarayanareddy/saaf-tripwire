import logging
log = logging.getLogger(__name__)


def risk(score):
    if score >= 8:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def rag(s):
    if s["critical"] > 0 or s["high"] > 0:
        return "Red"
    elif s["gaps"] > 0:
        return "Amber"
    else:
        return "Green"


def load(cfg):
    if cfg.get("debug"):
        log.info("debug mode on")
