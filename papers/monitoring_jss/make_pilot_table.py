"""Rebuild the session timing table from checksum-verified cell summaries."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.run / "manifest.json").read_text())
    rows = []
    for cell in manifest["cells"]:
        path = args.run / cell["name"] / "summary.json"
        if hashlib.sha256(path.read_bytes()).hexdigest() != cell["summary_sha256"]:
            raise RuntimeError(f"summary checksum mismatch: {path}")
        rows.append(json.loads(path.read_text()))
    print("| Period | Playback speed | Events / raw triggers / notifications | Local loop, s | p99 local service, ms | Peak RSS, MB | Max virtual queue wait, s |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for period in sorted({row["period"] for row in rows}):
        for speed in sorted({row["speed_factor"] for row in rows}):
            selected = [r for r in rows if r["period"] == period and r["speed_factor"] == speed]
            def interval(values, scale=1, digits=3):
                values = [v * scale for v in values]
                return f"{min(values):.{digits}f}–{max(values):.{digits}f}"
            n, raw, alerts = (selected[0][k] for k in ("events", "raw_triggers", "notifications"))
            print(f"| {period.replace('.jsonl', '')} | {speed:,} | {n:,} / {raw} / {alerts} | "
                  + interval([r["wall_runtime_seconds"] for r in selected]) + " | "
                  + interval([r["distributions"]["local_service_seconds"]["p99"] for r in selected], 1000) + " | "
                  + interval([r["peak_rss_bytes"] for r in selected], 1e-6, 1) + " | "
                  + interval([r["distributions"]["virtual_queue_wait_seconds"]["max"] for r in selected]) + " |")


if __name__ == "__main__":
    main()
