"""
train_model.py - Train the phishing detection ML model.

Supports two label modes:
  * Binary (legacy):   dataset.csv with a 'label' column of safe/phishing.
  * Multi-class (5-tier): dataset.csv with a 'class' column matching
    legitimate | suspicious | impersonated | phishing | fraud (aliases mapped).

Saves:
  model.pkl / vectorizer.pkl        - best model + TF-IDF vectorizer
  metrics.json                      - persisted metrics for the dashboard
  confusion_matrix.png              - matplotlib chart (when available)

Build a bigger labeled corpus from a folder of raw emails with:
  python build_dataset.py --emails-dir emails/ --labels labels.csv --output dataset.csv
"""

import argparse
import json
import os
import re
import time

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB

CANONICAL_CLASSES = ("legitimate", "suspicious", "impersonated", "phishing", "fraud")

# Aliases -> canonical class (so real-world labels map to the spec's 5 classes).
_CLASS_ALIASES = {
    "legitimate": "legitimate", "benign": "legitimate", "safe": "legitimate",
    "ham": "legitimate", "clean": "legitimate",
    "suspicious": "suspicious", "unknown": "suspicious", "uncertain": "suspicious",
    "impersonated": "impersonated", "impersonation": "impersonated",
    "spoofed": "impersonated", "lookalike": "impersonated",
    "phishing": "phishing", "phish": "phishing", "spam": "phishing",
    "fraud": "fraud", "scam": "fraud", "financial_fraud": "fraud",
}


def canonical_class(label: str) -> str:
    return _CLASS_ALIASES.get(str(label).strip().lower(), str(label).strip().lower())


# ─── Preprocessing ───────────────────────────────────────────────────────────

def preprocess_text(text: str) -> str:
    """Clean and normalize email text."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)                 # Remove HTML
    text = re.sub(r"http\S+|www\.\S+", " url ", text)    # Replace URLs
    text = re.sub(r"\S+@\S+", " email ", text)           # Replace emails
    text = re.sub(r"[^a-z0-9\s]", " ", text)             # Remove special chars
    text = re.sub(r"\s+", " ", text).strip()              # Collapse spaces
    return text


def prepare_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize an input frame into rows with 'clean_text' and a canonical
    target column ('label' for binary, 'class' for multi-class, whichever
    the source supplies). Never mutates the caller's frame.
    """
    df = df.copy()
    df["clean_text"] = df["email_text"].apply(preprocess_text)
    if "class" in df.columns:
        df["class_label"] = df["class"].apply(canonical_class)
        df = df[df["class_label"].isin(CANONICAL_CLASSES)]
        return df
    df = df[df["label"].notna()]
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(("safe", "phishing"))]
    return df


# ─── Pipeline ────────────────────────────────────────────────────────────────

def train_pipeline(df: pd.DataFrame, model_path="model.pkl",
                   vectorizer_path="vectorizer.pkl", metrics_path="metrics.json",
                   plot_path="confusion_matrix.png", out_dir=".", seed=42):
    """Run the full TF-IDF + model training, persisting artifacts + metrics."""
    df = prepare_dataset(df)
    out_dir = out_dir or "."
    os.makedirs(out_dir, exist_ok=True)

    multiclass = "class_label" in df.columns
    target = "class_label" if multiclass else "label"
    classes = sorted(df[target].unique().tolist())
    n = len(df)

    X = df["clean_text"]
    y = df[target]

    # Smallest class must stay represented in both splits.
    stratify = y
    min_class = y.value_counts().min()
    test_size = 0.3 if n and n < 30 else 0.2
    if min_class < 2:
        strata = None
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=seed)
    else:
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=seed, stratify=stratify)

    vectorizer = TfidfVectorizer(
        max_features=5000, ngram_range=(1, 2), min_df=1, max_df=0.95,
        stop_words="english")
    X_tr_tfidf = vectorizer.fit_transform(X_tr)
    X_te_tfidf = vectorizer.transform(X_te)

    candidates = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, C=10, random_state=seed),
    }

    best = None
    best_name = ""
    best_f1 = -1.0
    best_cv = 0.0
    report = {}
    cm = None

    for name, model in candidates.items():
        model.fit(X_tr_tfidf, y_tr)
        pred = model.predict(X_te_tfidf)
        macro_f1 = f1_score(y_te, pred, average="macro",
                            zero_division=0, labels=classes)
        try:
            cv = cross_val_score(
                model, X_tr_tfidf, y_tr, cv=min(5, max(2, len(set(y_tr)))),
                scoring="f1_macro")
            cv_mean, cv_std = float(cv.mean()), float(cv.std())
        except Exception:
            cv_mean, cv_std = 0.0, 0.0
        if macro_f1 > best_f1:
            best_f1, best = macro_f1, model
            best_name, best_cv = name, cv_mean
        cm = confusion_matrix(y_te, pred)
        report = classification_report(
            y_te, pred, output_dict=True, zero_division=0, labels=classes)
        report["__model"] = name

    acc = accuracy_score(y_te, best.predict(X_te_tfidf))

    metrics = {
        "mode": "multi_class" if multiclass else "binary",
        "n_samples": int(n),
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "classes": classes,
        "best_model": best_name,
        "best_macro_f1": float(best_f1),
        "cv_f1_mean": float(best_cv),
        "accuracy": float(acc),
        "per_class": {k: v for k, v in report.items()
                      if isinstance(v, dict) and k in classes or k in ("macro avg", "weighted avg")},
        "confusion": {
            "labels": classes,
            "matrix": [[int(x) for x in row] for row in cm],
        },
        "classifier_type": type(best).__name__,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    joblib.dump(best, os.path.join(out_dir, model_path))
    joblib.dump(vectorizer, os.path.join(out_dir, vectorizer_path))
    with open(os.path.join(out_dir, metrics_path), "w") as fh:
        json.dump(metrics, fh, indent=2)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(max(6, 0.8 * len(classes)) + 2,
                                        max(5, 0.7 * len(classes)) + 2))
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)
        ax.set(xticks=range(len(classes)), yticks=range(len(classes)),
               xticklabels=classes, yticklabels=classes,
               ylabel="True", xlabel="Predicted",
               title=f"Confusion matrix - {best_name}")
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
        for i in range(len(classes)):
            for j in range(len(classes)):
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, plot_path))
        plt.close(fig)
        metrics["chart"] = plot_path
    except Exception:
        metrics["chart"] = None

    return metrics, best_name


def main():
    ap = argparse.ArgumentParser(description="Train the phishing detection model")
    ap.add_argument("--csv", default="dataset.csv", help="Labeled dataset CSV")
    ap.add_argument("--out-dir", default=".", help="Where to save artifacts")
    ap.add_argument("--multiclass", action="store_true",
                    help="Force 5-class training (auto when a 'class' column exists)")
    args = ap.parse_args()

    print("=" * 60)
    print("MODEL TRAINING")
    print("=" * 60)

    df = pd.read_csv(args.csv)
    print(f"\nSamples: {len(df)}")
    if "class" in df.columns or args.multiclass:
        print("Mode: multi-class (5-tier verdicts)")
        print(df.groupby(df["class"].apply(canonical_class)).size().to_string())
    else:
        print("Mode: binary safe/phishing")
        print(df["label"].value_counts().to_string())

    start = time.time()
    metrics, best_name = train_pipeline(df, out_dir=args.out_dir)
    print(f"\nBest model: {metrics['best_model']} "
          f"(macro F1 {metrics['best_macro_f1']:.4f}, "
          f"accuracy {metrics['accuracy']:.4f})")
    print(f"CV F1: {metrics['cv_f1_mean']:.4f}")
    print(f"\nPer-class metrics:")
    for cls in metrics["classes"]:
        m = metrics["per_class"].get(cls, {})
        print(f"  {cls:12s} P:{m.get('precision', 0):.3f} "
              f"R:{m.get('recall', 0):.3f} F1:{m.get('f1-score', 0):.3f} "
              f"n:{m.get('support', 0)}")
    print(f"\nSaved model.pkl, vectorizer.pkl, metrics.json"
          + (", confusion_matrix.png" if metrics.get("chart") else ""))
    print(f"Elapsed: {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()