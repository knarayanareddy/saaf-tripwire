import csv


def export(rows, path):
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        for row in rows:
            writer.writerow([
                ("'" + str(v)) if str(v).startswith(("=", "+", "-", "@")) else v for v in row
            ])
