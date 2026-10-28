"""Read-only process/resource observations; not a controlled benchmark."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--collection', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    proc = Path('/proc') / str(args.pid)
    expected = b'python\x00-u\x00papers/monitoring_jss/phase16/storage_recovery/pipeline.py\x00collect\x00'
    if not (proc / 'cmdline').read_bytes().startswith(expected):
        raise ValueError('unexpected collection command')
    with args.output.open('x') as out:
        while True:
            record = {'sampled_utc': datetime.now(timezone.utc).isoformat(),
                      'pid': args.pid, 'dataset_rows_read_by_observer': 0,
                      'disk_free_bytes': shutil.disk_usage(args.collection.parent).free}
            try:
                record['process_status'] = 'RUNNING' if (proc / 'cmdline').read_bytes().startswith(expected) else 'ENDED_OR_IDENTITY_CHANGED'
                if record['process_status'] == 'RUNNING':
                    values = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                    record['memory_kib'] = {key: int(values[key].split()[0]) for key in ('VmRSS', 'VmHWM')}
                    session_path = args.collection / 'transport/session.json'
                    if session_path.exists():
                        record['transport_checkpoint'] = json.loads(session_path.read_text())
                    else:
                        record['transport_checkpoint'] = None
            except FileNotFoundError:
                record['process_status'] = 'ENDED'
            out.write(json.dumps(record, sort_keys=True) + '\n')
            out.flush()
            if record['process_status'] != 'RUNNING':
                break
            time.sleep(30)


if __name__ == '__main__':
    main()
