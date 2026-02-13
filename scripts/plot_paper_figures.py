from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Iterable


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _svg_begin(*, w: int, h: int) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(w)}" height="{int(h)}" viewBox="0 0 {int(w)} {int(h)}">',
        '<rect x="0" y="0" width="100%" height="100%" fill="#ffffff" />',
    ]


def _svg_end(lines: list[str]) -> str:
    return "\n".join(lines + ["</svg>"]) + "\n"


def _ticks_0_1() -> list[tuple[float, str]]:
    return [(0.0, "0.0"), (0.25, "0.25"), (0.5, "0.5"), (0.75, "0.75"), (1.0, "1.0")]


def _nice_max(x: float) -> float:
    if x <= 0:
        return 1.0
    p10 = 10 ** int(math.floor(math.log10(x)))
    m = x / p10
    if m <= 1:
        return 1 * p10
    if m <= 2:
        return 2 * p10
    if m <= 5:
        return 5 * p10
    return 10 * p10


def _svg_axes(
    lines: list[str],
    *,
    x0: int,
    y0: int,
    x1: int,
    y1: int,
    y_ticks: list[tuple[float, str]],
    title: str,
    y_label: str,
) -> None:
    # border + axes
    lines.append(f'<rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" fill="none" stroke="#111" stroke-width="1" />')
    lines.append(f'<text x="{(x0 + x1) // 2}" y="{max(14, y0 - 12)}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="14" fill="#111">{_esc(title)}</text>')
    # y label (rotated)
    lines.append(
        f'<text x="{max(14, x0 - 42)}" y="{(y0 + y1) // 2}" transform="rotate(-90 {max(14, x0 - 42)} {(y0 + y1) // 2})" '
        f'text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="12" fill="#111">{_esc(y_label)}</text>'
    )
    # y ticks + grid
    for t, lab in y_ticks:
        y = int(y1 - t * (y1 - y0))
        lines.append(f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" stroke="#e6e6e6" stroke-width="1" />')
        lines.append(f'<text x="{x0 - 6}" y="{y + 4}" text-anchor="end" font-family="ui-sans-serif,system-ui" font-size="11" fill="#333">{_esc(lab)}</text>')


def _svg_bar_dual(
    *,
    labels: list[str],
    a: list[float],
    b: list[float],
    a_name: str,
    b_name: str,
    title: str,
    out_path: Path,
    y_label: str = "Rate",
    y_max: float = 1.0,
) -> None:
    w, h = 920, 440
    margin_l, margin_r, margin_t, margin_b = 78, 24, 44, 92
    x0, y0 = margin_l, margin_t
    x1, y1 = w - margin_r, h - margin_b

    lines = _svg_begin(w=w, h=h)

    y_ticks = _ticks_0_1() if abs(y_max - 1.0) < 1e-9 else [(0.0, "0"), (0.5, f"{y_max/2:.2g}"), (1.0, f"{y_max:.2g}")]
    _svg_axes(lines, x0=x0, y0=y0, x1=x1, y1=y1, y_ticks=y_ticks, title=title, y_label=y_label)

    n = max(1, len(labels))
    span = (x1 - x0)
    step = span / n
    group_w = step * 0.72
    bar_w = group_w / 2.2
    gap = bar_w * 0.2

    def y_of(v: float) -> int:
        v2 = max(0.0, min(float(v), float(y_max)))
        t = v2 / float(y_max) if y_max > 0 else 0.0
        return int(y1 - t * (y1 - y0))

    for i, lab in enumerate(labels):
        cx = x0 + (i + 0.5) * step
        x_a = cx - (bar_w + gap / 2)
        x_b = cx + (gap / 2)
        y_a = y_of(a[i])
        y_b = y_of(b[i])
        lines.append(f'<rect x="{x_a:.2f}" y="{y_a}" width="{bar_w:.2f}" height="{y1 - y_a}" fill="#2b6cb0" />')
        lines.append(f'<rect x="{x_b:.2f}" y="{y_b}" width="{bar_w:.2f}" height="{y1 - y_b}" fill="#2f855a" />')
        # x label
        lines.append(
            f'<text x="{cx:.2f}" y="{y1 + 18}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="11" fill="#111">{_esc(lab)}</text>'
        )

    # legend
    lx = x0 + 4
    ly = y0 - 26
    lines.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" fill="#2b6cb0" />')
    lines.append(f'<text x="{lx + 18}" y="{ly + 11}" font-family="ui-sans-serif,system-ui" font-size="12" fill="#111">{_esc(a_name)}</text>')
    lines.append(f'<rect x="{lx + 190}" y="{ly}" width="12" height="12" fill="#2f855a" />')
    lines.append(f'<text x="{lx + 208}" y="{ly + 11}" font-family="ui-sans-serif,system-ui" font-size="12" fill="#111">{_esc(b_name)}</text>')

    out_path.write_text(_svg_end(lines), encoding="utf-8")


def _svg_bar_single(
    *,
    labels: list[str],
    v: list[float],
    title: str,
    out_path: Path,
    y_label: str,
    unit: str = "",
) -> None:
    w, h = 920, 440
    margin_l, margin_r, margin_t, margin_b = 78, 24, 44, 92
    x0, y0 = margin_l, margin_t
    x1, y1 = w - margin_r, h - margin_b

    vmax = _nice_max(max([float(x) for x in v] + [1.0]))
    y_ticks = [(0.0, "0"), (0.25, f"{vmax*0.25:.2g}"), (0.5, f"{vmax*0.5:.2g}"), (0.75, f"{vmax*0.75:.2g}"), (1.0, f"{vmax:.2g}")]
    lines = _svg_begin(w=w, h=h)
    _svg_axes(lines, x0=x0, y0=y0, x1=x1, y1=y1, y_ticks=y_ticks, title=title, y_label=y_label)

    n = max(1, len(labels))
    span = (x1 - x0)
    step = span / n
    bar_w = step * 0.58

    def y_of(val: float) -> int:
        val2 = max(0.0, min(float(val), float(vmax)))
        t = val2 / float(vmax) if vmax > 0 else 0.0
        return int(y1 - t * (y1 - y0))

    for i, lab in enumerate(labels):
        cx = x0 + (i + 0.5) * step
        x = cx - bar_w / 2
        y = y_of(v[i])
        lines.append(f'<rect x="{x:.2f}" y="{y}" width="{bar_w:.2f}" height="{y1 - y}" fill="#4a5568" />')
        lines.append(f'<text x="{cx:.2f}" y="{y1 + 18}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="11" fill="#111">{_esc(lab)}</text>')
        lines.append(
            f'<text x="{cx:.2f}" y="{y - 6}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="10" fill="#333">{float(v[i]):.3g}{_esc(unit)}</text>'
        )

    out_path.write_text(_svg_end(lines), encoding="utf-8")


def _svg_line_multi(
    *,
    series: list[tuple[str, list[float], list[float], str]],
    title: str,
    out_path: Path,
    x_label: str,
    y_label: str,
) -> None:
    w, h = 920, 520
    margin_l, margin_r, margin_t, margin_b = 78, 24, 44, 86
    x0, y0 = margin_l, margin_t
    x1, y1 = w - margin_r, h - margin_b

    xs_all: list[float] = []
    ys_all: list[float] = []
    for _name, xs, ys, _color in series:
        xs_all.extend([float(x) for x in xs])
        ys_all.extend([float(y) for y in ys])
    if not xs_all:
        xs_all = [0.0, 1.0]
    if not ys_all:
        ys_all = [0.0, 1.0]

    xmin, xmax = min(xs_all), max(xs_all)
    ymin, ymax = 0.0, _nice_max(max(ys_all))
    if abs(xmax - xmin) < 1e-9:
        xmax = xmin + 1.0

    # ticks
    y_ticks = [(0.0, "0"), (0.25, f"{ymax*0.25:.2g}"), (0.5, f"{ymax*0.5:.2g}"), (0.75, f"{ymax*0.75:.2g}"), (1.0, f"{ymax:.2g}")]

    lines = _svg_begin(w=w, h=h)
    _svg_axes(lines, x0=x0, y0=y0, x1=x1, y1=y1, y_ticks=y_ticks, title=title, y_label=y_label)

    # x axis label
    lines.append(f'<text x="{(x0 + x1) // 2}" y="{h - 16}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="12" fill="#111">{_esc(x_label)}</text>')

    def x_of(x: float) -> float:
        t = (float(x) - xmin) / (xmax - xmin)
        return x0 + t * (x1 - x0)

    def y_of(y: float) -> float:
        t = float(y) / float(ymax) if ymax > 0 else 0.0
        return y1 - t * (y1 - y0)

    # x ticks at observed x values (unique, sorted, but capped)
    xt = sorted(set([float(x) for x in xs_all]))
    if len(xt) > 8:
        # subsample evenly
        keep: list[float] = []
        for i in range(8):
            keep.append(xt[int(round(i * (len(xt) - 1) / 7))])
        xt = sorted(set(keep))
    for xv in xt:
        x = x_of(xv)
        lines.append(f'<line x1="{x:.2f}" y1="{y1}" x2="{x:.2f}" y2="{y1 + 4}" stroke="#111" stroke-width="1" />')
        lines.append(f'<text x="{x:.2f}" y="{y1 + 18}" text-anchor="middle" font-family="ui-sans-serif,system-ui" font-size="11" fill="#333">{xv:g}</text>')

    # draw series
    legend_y = y0 - 26
    legend_x = x0 + 4
    for si, (name, xs, ys, color) in enumerate(series):
        pts = [(x_of(float(x)), y_of(float(y))) for x, y in zip(xs, ys)]
        if len(pts) < 2:
            continue
        d = "M " + " L ".join([f"{px:.2f} {py:.2f}" for px, py in pts])
        lines.append(f'<path d="{d}" fill="none" stroke="{_esc(color)}" stroke-width="2" />')
        for px, py in pts:
            lines.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="3" fill="{_esc(color)}" />')

        # legend entry
        lx = legend_x + si * 210
        lines.append(f'<rect x="{lx}" y="{legend_y}" width="12" height="12" fill="{_esc(color)}" />')
        lines.append(f'<text x="{lx + 18}" y="{legend_y + 11}" font-family="ui-sans-serif,system-ui" font-size="12" fill="#111">{_esc(name)}</text>')

    out_path.write_text(_svg_end(lines), encoding="utf-8")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    fig_dir = out_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    made: list[str] = []

    paper_eval = _load_json(out_dir / "paper_eval" / "paper_eval_summary.json")
    if paper_eval and str(paper_eval.get("status")) == "OK":
        modes = list((paper_eval.get("modes") or {}).keys())
        atk = [float(((paper_eval.get("modes") or {}).get(m) or {}).get("attack_block_rate", 0.0)) for m in modes]
        bal = [float(((paper_eval.get("modes") or {}).get(m) or {}).get("benign_allow_rate", 0.0)) for m in modes]
        p = fig_dir / "paper_eval_rates.svg"
        _svg_bar_dual(
            labels=modes,
            a=atk,
            b=bal,
            a_name="Attack Block Rate",
            b_name="Benign Allow Rate",
            title="Security/Utility Across Baselines",
            out_path=p,
            y_label="Rate",
            y_max=1.0,
        )
        made.append(str(p))

        lat = [float(((paper_eval.get("modes") or {}).get(m) or {}).get("latency_p95_ms", 0.0)) for m in modes]
        thr = [float(((paper_eval.get("modes") or {}).get(m) or {}).get("throughput_ops_s", 0.0)) for m in modes]

        p_lat = fig_dir / "paper_eval_latency_p95_ms.svg"
        _svg_bar_single(labels=modes, v=lat, title="p95 Latency by Baseline", out_path=p_lat, y_label="p95 latency (ms)", unit="ms")
        made.append(str(p_lat))

        p_thr = fig_dir / "paper_eval_throughput_ops_s.svg"
        _svg_bar_single(labels=modes, v=thr, title="Throughput by Baseline", out_path=p_thr, y_label="Throughput (ops/s)")
        made.append(str(p_thr))

    curves = _load_json(out_dir / "policy_perf" / "policy_server_curves.json")
    if curves and str(curves.get("status")) == "OK":
        rows = [r for r in (curves.get("rows") or []) if isinstance(r, dict)]
        by: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for r in rows:
            by.setdefault((str(r.get("backend")), int(r.get("pad_to", 0))), []).append(r)

        palette = ["#2b6cb0", "#2f855a", "#b83280", "#dd6b20", "#4a5568", "#805ad5"]
        ser: list[tuple[str, list[float], list[float], str]] = []
        for i, ((backend, pad_to), rs) in enumerate(sorted(by.items(), key=lambda kv: (kv[0][0], kv[0][1]))):
            rs2 = sorted(rs, key=lambda x: int(x.get("effective_batch", 0)))
            xs = [float(int(x.get("effective_batch", 0))) for x in rs2]
            ys = [float(x.get("throughput_effective_keys_s", 0.0)) for x in rs2]
            ser.append((f"{backend}, pad_to={pad_to}", xs, ys, palette[i % len(palette)]))

        p = fig_dir / "policy_server_curves_effective_keys_s.svg"
        _svg_line_multi(
            series=ser,
            title="Policy Server Throughput Curves (Batch/Padding)",
            out_path=p,
            x_label="Effective batch size (keys/query)",
            y_label="Throughput (effective keys/s)",
        )
        made.append(str(p))

    native_eval = _load_json(out_dir / "native_baselines" / "native_guardrail_eval.json")
    if native_eval and str(native_eval.get("status")) == "OK":
        rows2 = [r for r in (native_eval.get("rows") or []) if isinstance(r, dict)]
        if rows2:
            names = [str(r.get("runtime")) for r in rows2]
            atk = [float(r.get("attack_block_rate", 0.0)) for r in rows2]
            bal = [float(r.get("benign_allow_rate", 0.0)) for r in rows2]
            p = fig_dir / "native_guardrail_eval.svg"
            _svg_bar_dual(
                labels=names,
                a=atk,
                b=bal,
                a_name="Attack Block Rate",
                b_name="Benign Allow Rate",
                title="Native Runtime Guardrails (Real CLIs)",
                out_path=p,
            )
            made.append(str(p))

    campaign = _load_json(out_dir / "campaign" / "real_agent_campaign.json")
    if campaign and str(campaign.get("status")) == "OK":
        summ = campaign.get("summary") or {}
        if isinstance(summ, dict) and summ:
            names = list(summ.keys())
            atk = [float((summ.get(k) or {}).get("attack_block_rate", 0.0)) for k in names]
            bal = [float((summ.get(k) or {}).get("benign_allow_rate", 0.0)) for k in names]
            p = fig_dir / "real_agent_campaign_rates.svg"
            _svg_bar_dual(
                labels=names,
                a=atk,
                b=bal,
                a_name="Attack Block Rate",
                b_name="Benign Allow Rate",
                title="Real-Agent Closed-Loop Campaign (Summary)",
                out_path=p,
            )
            made.append(str(p))

    out = {"status": "OK", "figures": made}
    out_path = fig_dir / "figures_index.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
