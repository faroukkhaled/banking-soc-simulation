"""Make real_data/creditcard_sample.csv: every fraud plus an evenly spaced slice of legitimate rows.

    python tools/make_sample.py creditcard.csv real_data/creditcard_sample.csv 6000
Full file (about 150 MB): https://storage.googleapis.com/download.tensorflow.org/data/creditcard.csv
(mirror of the ULB/Worldline dataset, also on OpenML as 'creditcard').
"""
import csv
import sys

src, dst, n_legit = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(src, newline="") as fh:
    rd = csv.reader(fh)
    header = next(rd)
    rows = list(rd)
legit = [r for r in rows if r[-1] == "0"]
step = max(1, len(legit) // n_legit)
keep_legit = set(id(r) for r in legit[::step])
out = [r for r in rows if r[-1] == "1" or id(r) in keep_legit]
with open(dst, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows([[("%.6g" % float(v)) if i not in (0, 30) else v for i, v in enumerate(r)] for r in out])
print(len(out), "rows")
