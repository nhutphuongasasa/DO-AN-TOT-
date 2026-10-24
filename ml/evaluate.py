"""ml/evaluate.py — Tạo báo cáo đánh giá đầy đủ: F1, Confusion Matrix, so sánh 3 kịch bản.

Usage:
    python3 -m ml.evaluate --flow-results ml/models/flow/cv_summary.json \
                           --device-results ml/models/device/cv_summary.json \
                           --out ml/results/
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Palette và style
# ---------------------------------------------------------------------------

PALETTE = {
    "youtube":      "#FF0000",
    "zalo":         "#0068FF",
    "spotify":      "#1DB954",
    "meet":         "#00BCD4",
    "chatgpt":      "#74AA9C",
    "other-idle":   "#9E9E9E",
    "other-web":    "#FF9800",
    "other-update": "#795548",
}

def _setup_style() -> None:
    plt.rcParams.update({
        "font.family":    "DejaVu Sans",
        "font.size":      11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "figure.dpi":     150,
    })


# ---------------------------------------------------------------------------
# Confusion Matrix plot
# ---------------------------------------------------------------------------

def plot_confusion_matrix(
    cm: List[List[int]],
    class_names: List[str],
    title: str,
    out_path: Path,
    normalize: bool = True,
) -> None:
    """Plot and save a confusion matrix heatmap."""
    cm_arr = np.array(cm, dtype=float)
    if normalize:
        row_sums = cm_arr.sum(axis=1, keepdims=True)
        row_sums = np.where(row_sums == 0, 1, row_sums)
        cm_arr = cm_arr / row_sums

    fig, ax = plt.subplots(figsize=(max(8, len(class_names)), max(6, len(class_names) - 1)))
    sns.heatmap(
        cm_arr,
        annot=True,
        fmt=".2f" if normalize else "d",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        linewidths=0.5,
        ax=ax,
        vmin=0, vmax=1 if normalize else None,
        annot_kws={"size": 9},
    )
    ax.set_title(title)
    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")
    plt.xticks(rotation=35, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved confusion matrix → %s", out_path)


# ---------------------------------------------------------------------------
# Per-class F1 bar chart
# ---------------------------------------------------------------------------

def plot_f1_per_class(
    report: Dict[str, Any],
    title: str,
    out_path: Path,
    class_names: List[str],
) -> None:
    """Bar chart of F1-score per class from sklearn classification_report dict."""
    f1s  = [report.get(c, {}).get("f1-score", 0.0) for c in class_names]
    prec = [report.get(c, {}).get("precision", 0.0) for c in class_names]
    rec  = [report.get(c, {}).get("recall", 0.0) for c in class_names]

    x = np.arange(len(class_names))
    w = 0.25
    fig, ax = plt.subplots(figsize=(max(10, len(class_names) * 1.2), 5))
    bars_f1  = ax.bar(x - w, f1s,  w, label="F1-Score",  color="#2196F3", alpha=0.85)
    bars_pre = ax.bar(x,     prec, w, label="Precision", color="#4CAF50", alpha=0.85)
    bars_rec = ax.bar(x + w, rec,  w, label="Recall",    color="#FF9800", alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(class_names, rotation=25, ha="right", fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title(title)
    ax.legend(loc="lower right")
    ax.axhline(0.8, color="red", linewidth=0.8, linestyle="--", alpha=0.5, label="0.8 line")
    for bar in bars_f1:
        h = bar.get_height()
        if h > 0.05:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01,
                    f"{h:.2f}", ha="center", va="bottom", fontsize=7)
    plt.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved F1 bar chart → %s", out_path)


# ---------------------------------------------------------------------------
# Per-fold F1 line chart
# ---------------------------------------------------------------------------

def plot_fold_f1(
    fold_results: List[Dict[str, Any]],
    title: str,
    out_path: Path,
) -> None:
    """Line chart showing F1_macro for each fold (fold = batch held out)."""
    batches = [r["test_batch"] for r in fold_results]
    f1s     = [r["f1_macro"]   for r in fold_results]
    mean_f1 = np.mean(f1s)

    fig, ax = plt.subplots(figsize=(max(8, len(batches) * 1.5), 4))
    ax.plot(batches, f1s, marker="o", linewidth=2, markersize=8, color="#2196F3", label="F1_macro")
    ax.axhline(mean_f1, color="red", linestyle="--", linewidth=1.2,
               label=f"Mean = {mean_f1:.4f}")
    for i, (b, f) in enumerate(zip(batches, f1s)):
        ax.annotate(f"{f:.3f}", (i, f), textcoords="offset points",
                    xytext=(0, 10), ha="center", fontsize=9)
    ax.set_ylim(max(0, min(f1s) - 0.1), 1.05)
    ax.set_ylabel("F1_macro")
    ax.set_title(title)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.xticks(rotation=20, ha="right", fontsize=9)
    plt.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved fold F1 chart → %s", out_path)


# ---------------------------------------------------------------------------
# Scenario comparison bar chart
# ---------------------------------------------------------------------------

def plot_scenario_comparison(
    scenario_f1s: Dict[str, float],
    out_path: Path,
) -> None:
    """Bar chart comparing Rule-only, ML-only, Hybrid F1 scores."""
    labels = list(scenario_f1s.keys())
    values = [scenario_f1s[k] for k in labels]
    colors = ["#FF9800", "#2196F3", "#4CAF50"][:len(labels)]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, values, color=colors, alpha=0.85, width=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.4f}", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("F1_macro (device-level)")
    ax.set_title("So Sánh: Rule-Only vs ML-Only vs Hybrid")
    ax.axhline(0.9, color="gray", linestyle=":", alpha=0.5)
    plt.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved scenario comparison → %s", out_path)


# ---------------------------------------------------------------------------
# Aggregate report across folds
# ---------------------------------------------------------------------------

def aggregate_confusion_matrix(fold_results: List[Dict[str, Any]]) -> List[List[int]]:
    """Sum confusion matrices across all folds."""
    cm_agg = None
    for r in fold_results:
        cm = np.array(r["confusion_matrix"])
        if cm_agg is None:
            cm_agg = cm
        else:
            cm_agg = cm_agg + cm
    return cm_agg.tolist() if cm_agg is not None else []


def aggregate_per_class_f1(fold_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Average per-class metrics across folds."""
    all_reports = [r["report"] for r in fold_results]
    class_names = fold_results[0]["class_names"]
    avg_report: Dict[str, Any] = {}
    for cls in class_names:
        f1s   = [rpt.get(cls, {}).get("f1-score", 0.0) for rpt in all_reports]
        precs = [rpt.get(cls, {}).get("precision", 0.0) for rpt in all_reports]
        recs  = [rpt.get(cls, {}).get("recall", 0.0) for rpt in all_reports]
        avg_report[cls] = {
            "f1-score":  float(np.mean(f1s)),
            "precision": float(np.mean(precs)),
            "recall":    float(np.mean(recs)),
            "f1_std":    float(np.std(f1s)),
        }
    return avg_report


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_html_report(
    flow_summary: Optional[Dict],
    device_summary: Optional[Dict],
    out_dir: Path,
    image_paths: List[Path],
) -> Path:
    """Generate a simple HTML summary with embedded images."""
    html_lines = [
        "<!DOCTYPE html><html><head>",
        "<meta charset='utf-8'>",
        "<title>ML Evaluation Report — Edge AI Traffic Classification</title>",
        "<style>body{font-family:Arial,sans-serif;max-width:1100px;margin:auto;padding:20px}",
        "h1{color:#1a237e}h2{color:#283593;border-bottom:2px solid #e8eaf6;padding-bottom:4px}",
        "table{border-collapse:collapse;width:100%}",
        "th,td{border:1px solid #ccc;padding:8px;text-align:right}",
        "th{background:#e8eaf6;text-align:center}td:first-child{text-align:left}",
        "img{max-width:100%;margin:10px 0;border:1px solid #ddd;border-radius:4px}",
        ".metric{display:inline-block;background:#e3f2fd;border-radius:8px;",
        "padding:12px 24px;margin:8px;text-align:center}",
        ".metric .val{font-size:2em;font-weight:bold;color:#1565C0}",
        ".metric .lbl{font-size:0.85em;color:#555}</style>",
        "</head><body>",
        "<h1>📊 ML Evaluation Report — Edge AI Traffic Classification</h1>",
    ]

    # Per-flow summary
    if flow_summary:
        html_lines.append("<h2>Model 1 — LightGBM Per-Flow</h2>")
        html_lines.append(
            f"<div class='metric'><div class='val'>{flow_summary['f1_mean']:.3f}</div>"
            f"<div class='lbl'>F1 Mean</div></div>"
            f"<div class='metric'><div class='val'>±{flow_summary['f1_std']:.3f}</div>"
            f"<div class='lbl'>F1 Std</div></div>"
            f"<div class='metric'><div class='val'>{flow_summary['f1_min']:.3f}</div>"
            f"<div class='lbl'>F1 Min</div></div>"
            f"<div class='metric'><div class='val'>{flow_summary['f1_max']:.3f}</div>"
            f"<div class='lbl'>F1 Max</div></div>"
        )

    # Per-device summary
    if device_summary:
        html_lines.append("<h2>Model 2 — LightGBM Per-Device-Window</h2>")
        html_lines.append(
            f"<div class='metric'><div class='val'>{device_summary['f1_mean']:.3f}</div>"
            f"<div class='lbl'>F1 Mean</div></div>"
        )

    # Embed images
    html_lines.append("<h2>Biểu Đồ Đánh Giá</h2>")
    for img_path in image_paths:
        if img_path.exists():
            rel = img_path.name
            html_lines.append(
                f"<figure><img src='{rel}' alt='{rel}'>"
                f"<figcaption>{rel}</figcaption></figure>"
            )

    html_lines.append("</body></html>")

    out_path = out_dir / "report.html"
    out_path.write_text("\n".join(html_lines), encoding="utf-8")
    log.info("HTML report saved → %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    _setup_style()

    parser = argparse.ArgumentParser(description="Generate evaluation charts and report.")
    parser.add_argument("--flow-results",   default="ml/models/flow/cv_summary.json")
    parser.add_argument("--device-results", default=None)
    parser.add_argument("--out",            default="ml/results/")
    parser.add_argument("--verbose",        action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_images: List[Path] = []

    # ---- Flow model ----
    flow_summary = None
    if Path(args.flow_results).exists():
        flow_summary = json.loads(Path(args.flow_results).read_text())
        folds = flow_summary["folds"]
        class_names = folds[0]["class_names"]

        # Aggregate CM
        cm_agg = aggregate_confusion_matrix(folds)
        cm_path = out_dir / "flow_confusion_matrix.png"
        plot_confusion_matrix(cm_agg, class_names,
                              "Per-Flow Model — Aggregated Confusion Matrix (normalized)",
                              cm_path)
        generated_images.append(cm_path)

        # Per-class F1 (averaged across folds)
        avg_report = aggregate_per_class_f1(folds)
        f1_path = out_dir / "flow_f1_per_class.png"
        plot_f1_per_class(avg_report, "Per-Flow Model — F1 per Class (mean across folds)",
                          f1_path, class_names)
        generated_images.append(f1_path)

        # Per-fold F1
        fold_path = out_dir / "flow_fold_f1.png"
        plot_fold_f1(folds, "Per-Flow Model — F1_macro per Fold", fold_path)
        generated_images.append(fold_path)

        # Check ablation
        abl_path = Path(args.flow_results).parent / "ablation_no_port" / "cv_summary.json"
        if abl_path.exists():
            abl = json.loads(abl_path.read_text())
            comparison = {
                "Rule-Only\n(baseline)": 0.0,  # placeholder — fill from rule engine test
                "ML-Only\n(w/ port)": flow_summary["f1_mean"],
                "ML-Only\n(no port)": abl["f1_mean"],
            }
            cmp_path = out_dir / "ablation_comparison.png"
            plot_scenario_comparison(comparison, cmp_path)
            generated_images.append(cmp_path)

        log.info("Flow model: F1_mean=%.4f ± %.4f", flow_summary["f1_mean"], flow_summary["f1_std"])

    # ---- Device model ----
    device_summary = None
    if args.device_results and Path(args.device_results).exists():
        device_summary = json.loads(Path(args.device_results).read_text())
        folds_d = device_summary["folds"]
        class_names_d = folds_d[0]["class_names"]

        cm_d_path = out_dir / "device_confusion_matrix.png"
        plot_confusion_matrix(
            aggregate_confusion_matrix(folds_d), class_names_d,
            "Per-Device-Window Model — Confusion Matrix (normalized)",
            cm_d_path
        )
        generated_images.append(cm_d_path)

        fold_d_path = out_dir / "device_fold_f1.png"
        plot_fold_f1(folds_d, "Per-Device-Window Model — F1_macro per Fold", fold_d_path)
        generated_images.append(fold_d_path)

    # ---- Scenario comparison ----
    if flow_summary and device_summary:
        sc = {
            "ML Per-Flow":          flow_summary["f1_mean"],
            "ML Per-Device":        device_summary["f1_mean"],
        }
        sc_path = out_dir / "scenario_comparison.png"
        plot_scenario_comparison(sc, sc_path)
        generated_images.append(sc_path)

    # ---- HTML report ----
    html_path = generate_html_report(flow_summary, device_summary, out_dir, generated_images)
    print(f"\n✔ Report generated: {html_path}")
    print(f"  Open with: xdg-open {html_path}")


if __name__ == "__main__":
    main()
