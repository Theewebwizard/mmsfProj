"""Shared helpers: result writing (CSV / JSON / PNG) and timing."""

from __future__ import annotations

import csv
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


@dataclass
class BenchmarkResult:
    key: str
    title: str
    description: str
    files: list[str] = field(default_factory=list)
    charts: list[dict[str, Any]] = field(default_factory=list)
    table: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, float] = field(default_factory=dict)

    def manifest(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "files": self.files,
            "charts": self.charts,
            "table": self.table,
        }


class Out:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def csv(self, res: BenchmarkResult, name: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        path = self.root / name
        with path.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        res.files.append(name)

    def chart(
        self,
        res: BenchmarkResult,
        name: str,
        *,
        title: str,
        kind: str,
        x: str,
        series: list[str],
        data: list[dict[str, Any]],
        x_label: str = "",
        y_label: str = "",
        log_y: bool = False,
        log_x: bool = False,
    ) -> None:
        """Render a PNG with Matplotlib and register the same data for Recharts."""
        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)
        xs = [d[x] for d in data]
        if kind == "bar":
            n = len(series)
            width = 0.8 / max(n, 1)
            idx = list(range(len(xs)))
            for k, s in enumerate(series):
                ax.bar([i + (k - (n - 1) / 2) * width for i in idx], [d.get(s) or 0 for d in data], width, label=s)
            ax.set_xticks(idx)
            ax.set_xticklabels([str(v) for v in xs], rotation=35, ha="right", fontsize=8)
        else:
            for s in series:
                ax.plot(xs, [d.get(s) for d in data], marker="o", markersize=3, label=s)
        if log_y:
            ax.set_yscale("log")
        if log_x:
            ax.set_xscale("log", base=2)
        ax.set_title(title)
        ax.set_xlabel(x_label or x)
        ax.set_ylabel(y_label)
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(self.root / name)
        plt.close(fig)
        res.files.append(name)
        res.charts.append(
            {"title": title, "type": kind, "x": x, "series": series, "x_label": x_label, "y_label": y_label, "data": data}
        )


def time_us(fn: Callable[[], Any], reps: int) -> dict[str, float]:
    """Run fn `reps` times; return mean/median/p95 in microseconds."""
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1000)
    samples.sort()
    return {
        "mean_us": round(statistics.fmean(samples), 3),
        "median_us": round(statistics.median(samples), 3),
        "p95_us": round(samples[min(len(samples) - 1, int(0.95 * len(samples)))], 3),
        "reps": reps,
    }
