import csv


def export(rows, path):
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["vendor", "amount"])
        for row in rows:
            writer.writerow([row["vendor"], row["amount"]])
