"""Trains the PhishGuard risk model on synthetic UPI transaction data."""
import numpy as np
import pickle, os
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

rng = np.random.default_rng(42)
N = 20000
FEATURES = [
    "log_amount", "odd_hour", "txn_count", "recipient_age", "new_device",
    "new_location", "velocity", "verified", "blacklisted", "name_mismatch",
    "domain_trust", "ip_host", "suspicious_tld", "link_keywords", "amount_anomaly",
]

def sample(n, fraud):
    X = np.zeros((n, len(FEATURES)))
    X[:, 0] = rng.normal(6.2 if fraud else 5.4, 1.1, n)          # log(amount)
    X[:, 1] = rng.binomial(1, 0.55 if fraud else 0.06, n)         # odd hour (0-6am)
    X[:, 2] = rng.beta(1, 8 if fraud else 2.2, n)                 # recipient txn count (norm)
    X[:, 3] = rng.beta(1, 9 if fraud else 3.0, n)                 # recipient age days (norm)
    X[:, 4] = rng.binomial(1, 0.7 if fraud else 0.08, n)          # new device
    X[:, 5] = rng.binomial(1, 0.6 if fraud else 0.07, n)          # new location
    X[:, 6] = np.clip(rng.normal(0.6 if fraud else 0.1, 0.2, n), 0, 1)  # velocity 24h
    X[:, 7] = rng.binomial(1, 0.05 if fraud else 0.85, n)         # verified recipient
    X[:, 8] = rng.binomial(1, 0.35 if fraud else 0.005, n)        # blacklisted
    X[:, 9] = rng.binomial(1, 0.5 if fraud else 0.02, n)          # name mismatch
    X[:, 10] = np.clip(rng.normal(0.15 if fraud else 0.9, 0.15, n), 0, 1)  # domain trust
    X[:, 11] = rng.binomial(1, 0.3 if fraud else 0.005, n)        # link uses IP host
    X[:, 12] = rng.binomial(1, 0.45 if fraud else 0.01, n)        # suspicious TLD
    X[:, 13] = rng.binomial(1, 0.5 if fraud else 0.03, n)         # phishing keywords
    X[:, 14] = rng.binomial(1, 0.55 if fraud else 0.04, n)        # amount vs user norm
    return X, np.ones(n, dtype=int) if fraud else np.zeros(n, dtype=int)

Xf, yf = sample(N // 2, True)
Xl, yl = sample(N // 2, False)
X, y = np.vstack([Xf, Xl]), np.concatenate([yf, yl])
idx = rng.permutation(len(y))
X, y = X[idx], y[idx]

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
model = GradientBoostingClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, random_state=42)
model.fit(Xtr, ytr)

acc = accuracy_score(yte, model.predict(Xte))
print(classification_report(yte, model.predict(Xte), target_names=["LEGIT", "PHISHING"]))
print(f"MODEL ACCURACY: {acc*100:.2f}%")

with open("phishguard_model.pkl", "wb") as f:
    pickle.dump({"model": model, "features": FEATURES}, f)
print("Saved phishguard_model.pkl")
