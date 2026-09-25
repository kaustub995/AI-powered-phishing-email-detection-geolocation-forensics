"""Tests for the training pipeline + dataset builder (all in-memory / temp)."""

import json

import pandas as pd

from train_model import canonical_class, preprocess_text, prepare_dataset, train_pipeline


def test_canonical_class_aliases():
    assert canonical_class("phish") == "phishing"
    assert canonical_class("benign") == "legitimate"
    assert canonical_class("SCAM") == "fraud"


def test_preprocess_text_normalization():
    out = preprocess_text('Click http://evil.io now <b>NOW</b> mail@x.com')
    assert "url" in out and "email" in out
    assert "<" not in out and "http" not in out


def test_prepare_dataset_binary_drops_unknown():
    df = pd.DataFrame({"email_text": ["a", "b", "c"],
                       "label": ["phishing", "safe", "weird"]})
    out = prepare_dataset(df)
    assert set(out["label"]) == {"phishing", "safe"}
    assert len(out) == 2


def test_prepare_dataset_multiclass_maps_aliases():
    df = pd.DataFrame({"email_text": ["a", "b", "c"],
                       "class": ["phish", "legitimate", "scam"]})
    out = prepare_dataset(df)
    assert sorted(out["class_label"].tolist()) == ["fraud", "legitimate", "phishing"]


def test_train_pipeline_binary_writes_artifacts(tmp_path):
    rows = ([{"email_text": f"phish {i} urgent account verify click", "label": "phishing"}
             for i in range(14)]
            + [{"email_text": f"hello team meeting notes {i}", "label": "safe"}
               for i in range(14)])
    df = pd.DataFrame(rows)
    metrics, name = train_pipeline(
        df, model_path="m.pkl", vectorizer_path="v.pkl",
        metrics_path="metrics.json", plot_path="cm.png", out_dir=str(tmp_path))
    assert metrics["mode"] == "binary"
    assert metrics["best_model"]
    assert (tmp_path / "m.pkl").exists()
    assert (tmp_path / "v.pkl").exists()
    with open(tmp_path / "metrics.json") as fh:
        assert json.load(fh)["accuracy"] >= 0.0


def test_train_pipeline_multiclass(tmp_path):
    rows = []
    for cls, words in (("legitimate", "project status update minutes"),
                       ("phishing", "verify account password urgent click"),
                       ("fraud", "investment guaranteed transfer wire now")):
        for i in range(6):
            rows.append({"email_text": f"{words} {i}", "class": cls})
    df = pd.DataFrame(rows)
    metrics, name = train_pipeline(
        df, model_path="m.pkl", vectorizer_path="v.pkl",
        metrics_path="metrics.json", plot_path="cm.png", out_dir=str(tmp_path))
    assert metrics["mode"] == "multi_class"
    assert set(metrics["classes"]) == {"phishing", "fraud", "legitimate"}
    assert "phishing" in metrics["per_class"]
    assert metrics["confusion"]["labels"] == ["fraud", "legitimate", "phishing"]
    assert (tmp_path / "m.pkl").exists()