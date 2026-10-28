"""Observe one live collection process; never alter it or read dataset rows.

Snapshots describe this environment, not a controlled performance benchmark.
VmHWM is the process lifetime high-water mark observed at each sample. A final
unsampled allocation may be missed; the reported maximum is a lower bound.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--collection', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    proc = Path('/proc') / str(args.pid)
    expected = b'python\x00-u\x00papers/monitoring_jss/phase16/pipeline/streaming_pipeline.py\x00collect\x00'
    if not (proc / 'cmdline').read_bytes().startswith(expected):
        raise ValueError('process is not the expected collection command')
    with args.output.open('x') as out:
        while True:
            record = {'sampled_utc': datetime.now(timezone.utc).isoformat(),
                      'pid': args.pid, 'dataset_rows_read_by_observer': 0}
            try:
                if not (proc / 'cmdline').read_bytes().startswith(expected):
                    record['process_status'] = 'ENDED_OR_IDENTITY_CHANGED'
                else:
                    values = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                    record['process_status'] = 'RUNNING'
                    record['memory_kib'] = {key: int(values[key].split()[0]) for key in ('VmRSS', 'VmHWM')}
                    session = json.loads((args.collection / 'transport/session.json').read_text())
                    record['transport'] = {key: session[key] for key in ('status', 'request_count', 'retained_response_bytes', 'wall_seconds_elapsed')}
            except FileNotFoundError:
                record['process_status'] = 'ENDED'
            out.write(json.dumps(record, sort_keys=True) + '\n')
            out.flush()
            if record['process_status'] != 'RUNNING':
                break
            time.sleep(30)


if __name__ == '__main__':
    main()
