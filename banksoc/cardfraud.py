"""Card-fraud scoring on a real public dataset (standard library only).

Dataset: "Credit Card Fraud Detection", 284,807 real card transactions by European cardholders over two
days in September 2013, 492 of them fraud. Collected by Worldline and the ULB Machine Learning Group.
Database licence ODbL 1.0; cite: Dal Pozzolo et al., "Calibrating Probability with Undersampling for
Unbalanced Classification", IEEE SSCI 2015. Features V1-V28 are PCA components (the bank hid the
originals), plus Time, Amount and Class. This is not from any employer; no bank data of mine is used.

The model is a plain logistic regression. It is simple on purpose: every alert can list the features
that pushed its score up, which is what an analyst needs for triage. A first attempt with Gaussian naive
Bayes ranked huge legitimate amounts above real fraud (average precision 0.08), so it was replaced.
"""
import csv
import math

FEATURES = ["V%d" % i for i in range(1, 29)] + ["LogAmount"]


def load(path):
    """Read the CSV into a list of dicts sorted by Time. Adds LogAmount."""
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            row = {k: float(v) for k, v in r.items()}
            row["LogAmount"] = math.log1p(row["Amount"])
            rows.append(row)
    rows.sort(key=lambda r: r["Time"])
    return rows


def split_by_time(rows, train_fraction=0.7):
    """Train on the past, test on the future, as a deployed model would be."""
    cut = int(len(rows) * train_fraction)
    return rows[:cut], rows[cut:]


class LogisticModel:
    """L2-regularised logistic regression on standardised features, trained by batch gradient descent.

    Legitimate rows are undersampled (evenly spaced, so it is deterministic) because fraud is about
    0.17% of the data. Undersampling shifts probabilities, not the ranking, and ranking is what an
    alert queue needs.
    """

    def __init__(self, epochs=300, lr=0.5, l2=1e-3, max_legit=12000):
        self.epochs, self.lr, self.l2, self.max_legit = epochs, lr, l2, max_legit
        self.mean, self.std, self.w, self.b = {}, {}, {}, 0.0

    def _z(self, row):
        return [(row[f] - self.mean[f]) / self.std[f] for f in FEATURES]

    def fit(self, rows):
        fraud = [r for r in rows if r["Class"] == 1]
        legit = [r for r in rows if r["Class"] == 0]
        if len(fraud) < 2 or len(legit) < 2:
            raise ValueError("need at least two fraud and two legitimate rows to fit")
        step = max(1, len(legit) // self.max_legit)
        sample = fraud + legit[::step]
        n = len(sample)
        for f in FEATURES:
            vals = [r[f] for r in sample]
            m = sum(vals) / n
            sd = math.sqrt(sum((v - m) ** 2 for v in vals) / n) or 1.0
            self.mean[f], self.std[f] = m, sd
        X = [self._z(r) for r in sample]
        y = [int(r["Class"]) for r in sample]
        k = len(FEATURES)
        w = [0.0] * k
        b = 0.0
        for _ in range(self.epochs):
            gw = [0.0] * k
            gb = 0.0
            for xi, yi in zip(X, y):
                t = b + sum(wj * xj for wj, xj in zip(w, xi))
                p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, t))))
                e = p - yi
                gb += e
                for j in range(k):
                    gw[j] += e * xi[j]
            b -= self.lr * gb / n
            for j in range(k):
                w[j] -= self.lr * (gw[j] / n + self.l2 * w[j])
        self.w = dict(zip(FEATURES, w))
        self.b = b
        return self

    def contributions(self, row):
        """Per-feature share of the log-odds. Positive pushes towards fraud."""
        return {f: self.w[f] * z for f, z in zip(FEATURES, self._z(row))}

    def score(self, row):
        return self.b + sum(self.contributions(row).values())

    def explain(self, row, top=3):
        c = self.contributions(row)
        return sorted(c.items(), key=lambda kv: -kv[1])[:top]


def roc_auc(scores, labels):
    """Rank-based AUC (Mann-Whitney), ties get the average rank."""
    pairs = sorted(zip(scores, labels))
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if not n_pos or not n_neg:
        return float("nan")
    rank_sum = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1
        rank_sum += avg_rank * sum(1 for k in range(i, j + 1) if pairs[k][1] == 1)
        i = j + 1
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def average_precision(scores, labels):
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    n_pos = sum(labels)
    if not n_pos:
        return float("nan")
    tp = 0
    ap = 0.0
    for rank, i in enumerate(order, 1):
        if labels[i] == 1:
            tp += 1
            ap += tp / rank
    return ap / n_pos


def alert_budget(scores, labels, budget):
    """If analysts can review only `budget` alerts, how many frauds do they catch?"""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])[:budget]
    caught = sum(labels[i] for i in order)
    total = sum(labels)
    return {"alerts": len(order), "frauds_caught": caught, "frauds_total": total,
            "precision": caught / len(order) if order else 0.0, "recall": caught / total if total else 0.0}


def evaluate(rows, train_fraction=0.7, budget_fraction=0.002):
    train, test = split_by_time(rows, train_fraction)
    model = LogisticModel().fit(train)
    scores = [model.score(r) for r in test]
    labels = [int(r["Class"]) for r in test]
    budget = max(1, int(len(test) * budget_fraction))
    return {
        "train_rows": len(train), "test_rows": len(test), "test_frauds": sum(labels),
        "roc_auc": roc_auc(scores, labels), "average_precision": average_precision(scores, labels),
        "budget": alert_budget(scores, labels, budget),
        "base_rate": sum(labels) / len(labels),
    }, model, test, scores


def top_alerts(model, test, scores, n=10):
    order = sorted(range(len(test)), key=lambda i: -scores[i])[:n]
    return [{"time": test[i]["Time"], "amount": test[i]["Amount"], "score": round(scores[i], 1),
             "is_fraud": int(test[i]["Class"]), "why": [(f, round(v, 1)) for f, v in model.explain(test[i])]} for i in order]
