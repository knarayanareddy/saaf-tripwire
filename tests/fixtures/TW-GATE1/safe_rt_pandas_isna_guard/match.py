import pandas as pd
def three_way(a, b, tol=0.01):
    if pd.isna(a) or pd.isna(b):
        return 'MISMATCH'
    if abs(a - b) > tol:
        return 'MISMATCH'
    return 'MATCH'
