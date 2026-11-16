import csv


def write_header(path):
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["vendor", "amount", "status"])
