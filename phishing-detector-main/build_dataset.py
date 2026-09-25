"""
build_dataset.py - Turn a folder of raw emails into a labeled training CSV.

Grows dataset.csv from your own real emails (the honest way to move past the
~100-row starter set):

    python build_dataset.py --emails-dir emails/ --labels labels.csv --output dataset.csv

labels.csv format (filename -> label/class), no header:

    phish_01.eml,phishing
    legit_01.eml,safe
    spoof_02.txt,impersonated

TXT/EML fall back to raw text when headers aren't parseable, so even a
plain-text paste works. Binary maps: safe -> safe, anything else -> phishing.
"""

import argparse
import csv
import os
import re
from email import policy
from email.parser import BytesParser


def readable_text(content: bytes) -> str:
    """Best-effort extraction of human-readable body text."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(content)
        if not msg.is_multipart():
            return msg.get_content()
        text_parts = []
        seen = set()
        for part in msg.walk():
            ct = part.get_content_type()
            cs = part.get_content_charset() or "utf-8"
            if ct in ("text/plain", "text/html") and id(part) not in seen:
                seen.add(id(part))
                try:
                    text_parts.append(part.get_content().decode(cs, errors="ignore"))
                except Exception:
                    text_parts.append("")
        return "\n".join(t for t in text_parts if t) or msg.get_payload() or ""
    except Exception:
        try:
            return content.decode("utf-8", errors="ignore")
        except Exception:
            return ""


def main():
    ap = argparse.ArgumentParser(description="Build a labeled dataset from emails")
    ap.add_argument("--emails-dir", required=True, help="Folder of .eml/.txt files")
    ap.add_argument("--labels", required=True, help="CSV: filename,label[,class]")
    ap.add_argument("--output", default="dataset.csv")
    args = ap.parse_args()

    labels = {}
    with open(args.labels, newline="") as fh:
        for row in csv.reader(fh):
            if not row or not row[0].strip():
                continue
            labels[row[0].strip()] = row

    rows = 0
    skipped = []
    out_rows = []
    for fname, (label, *rest) in labels.items():
        path = os.path.join(args.emails_dir, fname)
        if not os.path.exists(path):
            skipped.append(fname)
            continue
        with open(path, "rb") as fh:
            text = readable_text(fh.read())
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            skipped.append(fname)
            continue
        klass = rest[0].strip() if rest else (
            "safe" if str(label).strip().lower() == "safe" else "phishing")
        binary = "safe" if str(label).strip().lower() == "safe" else "phishing"
        row = {"email_text": text, "label": binary}
        if rest:
            row["class"] = klass
        out_rows.append(row)
        rows += 1

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        fields = ["email_text", "label"] + (
            ["class"] if any("class" in r for r in out_rows) else [])
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(out_rows)

    print(f"Wrote {rows} rows to {args.output}")
    if skipped:
        print(f"Skipped (missing/unreadable): {', '.join(skipped[:10])}")


if __name__ == "__main__":
    main()