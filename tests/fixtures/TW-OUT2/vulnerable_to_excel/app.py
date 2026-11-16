import pandas as pd


def export(frame, path):
    frame.to_excel(path, index=False)
