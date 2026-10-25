"""Print the six-cell engineering table from saved summary measurements."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    result = json.loads((args.run / "pilot_summary.json").read_text())
    print("| Cell | Events | Raw / emitted | Local loop, s | Service p99, ms | Modeled queue max, ms | Pending max |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for cell in result["cells"]:
        count, dist = cell["counts"], cell["distributions"]
        print(f"| {cell['cell']} | {count['events']} | "
              f"{count['raw_triggers']} / {count['notifications']} | "
              f"{cell['wall_replay_seconds']:.3f} | "
              f"{1000 * dist['service_seconds']['p99']:.3f} | "
              f"{1000 * dist['queue_wait_seconds']['max']:.3f} | "
              f"{dist['pending_at_arrival']['max']} |")


if __name__ == "__main__":
    main()
