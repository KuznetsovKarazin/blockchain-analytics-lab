"""Original Elliptic v1 acquisition and ID-aligned prepared-feature audit.

No models are fitted. Source CSVs/labels stay private under data/raw/. All
features are already normalized by the data publisher; even selected direct
transaction columns do not reconstruct a live, raw-feature monitoring stream.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
import urllib.parse
import urllib.request
import zipfile

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
PAPER = Path(__file__).resolve().parent
SOURCE_API = "https://www.kaggle.com/api/v1/datasets/view/ellipticco/elliptic-data-set"
DOWNLOAD = "https://www.kaggle.com/api/v1/datasets/download/ellipticco/elliptic-data-set?datasetVersionNumber=1"
FILES = ("elliptic_txs_features.csv", "elliptic_txs_classes.csv", "elliptic_txs_edgelist.csv")
DIRECT18 = (2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22)
LOCAL93 = tuple(range(2, 95))
ALL165 = tuple(range(2, 167))
PIN = "dc1ba8876f3f163c27c48f3a39292fc47f71bf18"


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def dump(value, path):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def acquire(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "acquisition.json"
    if manifest_path.exists():
        saved = json.loads(manifest_path.read_text())
        for item in saved["files"]:
            if sha256(root / item["name"]) != item["sha256"]:
                raise RuntimeError("cached original file differs from acquisition manifest")
        return saved
    with urllib.request.urlopen(SOURCE_API, timeout=45) as response:
        metadata_bytes = response.read()
    metadata = json.loads(metadata_bytes)
    if metadata["ref"] != "ellipticco/elliptic-data-set" or metadata["currentVersionNumber"] != 1:
        raise RuntimeError("source version changed; re-review rather than silently upgrading")
    (root / "official_metadata.json").write_bytes(metadata_bytes)
    archive = root / "elliptic-data-set-v1.zip"
    start = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    if archive.exists():
        raise RuntimeError("archive exists without verified manifest; inspect before reuse")
    with urllib.request.urlopen(DOWNLOAD, timeout=90) as response, archive.with_suffix(".partial").open("wb") as handle:
        safe_headers = {k.lower(): v for k, v in response.headers.items()
                        if k.lower() in ("content-length", "content-type", "etag", "last-modified", "x-goog-hash")}
        redirect_host = urllib.parse.urlsplit(response.url).hostname
        while block := response.read(1024 * 1024):
            handle.write(block)
    archive.with_suffix(".partial").replace(archive)
    if "content-length" in safe_headers and archive.stat().st_size != int(safe_headers["content-length"]):
        raise RuntimeError("truncated official ZIP")
    extracted = []
    with zipfile.ZipFile(archive) as zipped:
        members = [item for item in zipped.infolist() if not item.is_dir()]
        if len(members) != 3 or {Path(item.filename).name for item in members} != set(FILES):
            raise RuntimeError("unexpected original dataset ZIP contents")
        for item in members:
            name = Path(item.filename).name
            with zipped.open(item) as source, (root / name).open("wb") as dest:
                shutil.copyfileobj(source, dest, 1024 * 1024)
            extracted.append({"name": name, "original_zip_path": item.filename,
                              "bytes": (root/name).stat().st_size, "sha256": sha256(root/name)})
    if sum(item["bytes"] for item in extracted) != metadata["totalBytes"]:
        raise RuntimeError("uncompressed file size does not match official metadata")
    record = {"schema_version": "elliptic_original_acquisition_v1", "source_api": SOURCE_API,
              "download_api": DOWNLOAD, "dataset_ref": metadata["ref"], "version": 1,
              "dataset_id": metadata["id"], "publisher_last_updated": metadata["lastUpdated"],
              "license": metadata["licenseName"], "license_url": "https://creativecommons.org/licenses/by-nc-nd/4.0/",
              "started_utc": start, "finished_utc": datetime.now(timezone.utc).isoformat(),
              "acquisition_seconds": time.perf_counter()-t0, "redirect_host": redirect_host,
              "signed_redirect_url_saved": False, "safe_http_headers": safe_headers,
              "official_metadata_sha256": sha256(root/"official_metadata.json"),
              "archive": {"name": archive.name, "bytes": archive.stat().st_size, "sha256": sha256(archive)},
              "files": extracted, "raw_distribution": "private academic research copy; no raw data or labels committed publicly",
              "command": [sys.executable, *sys.argv]}
    dump(record, manifest_path)
    return record


@dataclass
class TabularData:
    tx_ids: np.ndarray
    step: np.ndarray
    X: np.ndarray
    y: np.ndarray
    feature_columns: tuple[int, ...]


def read_classes(root):
    labels = pd.read_csv(Path(root)/FILES[1], dtype={"txId": np.int64, "class": str})
    if list(labels.columns) != ["txId", "class"] or labels.txId.duplicated().any():
        raise ValueError("classes must contain unique txId and class columns")
    if labels.isna().any().any() or not set(labels["class"]).issubset({"1", "2", "unknown"}):
        raise ValueError("unrecognized or missing source label; do not coerce to unknown")
    return labels


def load_tabular(root, feature_columns=DIRECT18, verify_hashes=True):
    """Strict txId alignment; requested CSV columns are positional and explicit."""
    root = Path(root)
    columns = tuple(feature_columns)
    if len(columns) != len(set(columns)) or not columns or any(not isinstance(c, int) or c < 2 or c > 166 for c in columns):
        raise ValueError("feature columns must be unique original CSV indices 2..166")
    if verify_hashes:
        record = json.loads((root/"acquisition.json").read_text())
        for item in record["files"]:
            if sha256(root/item["name"]) != item["sha256"]:
                raise RuntimeError("original input hash changed")
    with (root/FILES[0]).open() as handle:
        if len(next(csv.reader(handle))) != 167:
            raise ValueError("features CSV width is not 167")
    frame = pd.read_csv(root/FILES[0], header=None, usecols=[0, 1, *columns],
                        dtype={0: np.int64, 1: np.int16, **{c: np.float32 for c in columns}})
    tx = frame[0].to_numpy()
    if frame[0].duplicated().any() or not frame[1].between(1, 49).all():
        raise ValueError("duplicate transaction ID or invalid time step")
    X = frame.loc[:, list(columns)].to_numpy(dtype=np.float32)
    if not np.isfinite(X).all():
        raise ValueError("nonfinite prepared feature")
    labels = read_classes(root)
    if set(labels.txId) != set(tx):
        raise ValueError("features and classes have different txId populations")
    aligned = labels.set_index("txId")["class"].reindex(tx)
    y = aligned.map({"1": 1, "2": 0, "unknown": -1}).to_numpy(dtype=np.int8)
    return TabularData(tx, frame[1].to_numpy(dtype=np.int16), X, y, columns)


def audit(root, out):
    labels = read_classes(root)
    ids, steps = [], []
    total = nonfinite = 0
    for frame in pd.read_csv(root/FILES[0], header=None, chunksize=20000,
                             dtype={0: np.int64, 1: np.int16, **{c: np.float32 for c in ALL165}}):
        if frame.shape[1] != 167:
            raise ValueError("inconsistent original CSV width")
        total += len(frame)
        nonfinite += int((~np.isfinite(frame.iloc[:,2:].to_numpy())).sum())
        ids.append(frame[0].to_numpy())
        steps.append(frame[1].to_numpy())
    tx = np.concatenate(ids)
    step = np.concatenate(steps)
    if len(set(tx)) != total or set(labels.txId) != set(tx) or set(step) != set(range(1,50)) or nonfinite:
        raise ValueError("feature/ID/time-step integrity failed")
    aligned = labels.set_index("txId")["class"].reindex(tx)
    y = aligned.map({"1":1,"2":0,"unknown":-1}).to_numpy(dtype=np.int8)
    edges = pd.read_csv(root/FILES[2], dtype={"txId1":np.int64,"txId2":np.int64})
    if list(edges.columns) != ["txId1","txId2"] or edges.isna().any().any():
        raise ValueError("invalid original edge list")
    index = pd.Index(tx)
    source, target = index.get_indexer(edges.txId1), index.get_indexer(edges.txId2)
    dangling = int(((source<0)|(target<0)).sum())
    if dangling:
        raise ValueError("edges reference missing transaction IDs")
    cross_step = int((step[source] != step[target]).sum())
    per_step = []
    for time_step in range(1,50):
        selected = step==time_step
        per_step.append({"step":time_step,"rows":int(selected.sum()),"illicit":int((y[selected]==1).sum()),
                         "licit":int((y[selected]==0).sum()),"unknown":int((y[selected]==-1).sum())})
    with (out/"counts_by_step.csv").open("w",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=list(per_step[0]));writer.writeheader();writer.writerows(per_step)
    record = {"schema_version":"elliptic_original_data_audit_v1","nodes":total,"features_csv_columns":167,
              "tx_id_column":0,"time_step_column":1,"local_feature_columns":list(LOCAL93),
              "aggregate_feature_columns":list(range(95,167)),"direct18_feature_columns":list(DIRECT18),
              "prepared_feature_count_excluding_step":165,"local_count_excluding_step":93,"aggregate_count":72,
              "label_counts":{"illicit":int((y==1).sum()),"licit":int((y==0).sum()),"unknown":int((y==-1).sum())},
              "edges":len(edges),"duplicate_edge_rows":int(edges.duplicated().sum()),"self_loop_edges":int((source==target).sum()),
              "dangling_edges":dangling,"cross_step_edges":cross_step,"nonfinite_feature_cells":nonfinite,
              "classes_feature_order_equal":bool(np.array_equal(labels.txId.to_numpy(),tx)),
              "label_alignment":"exact txId join, never source-row-position assignment",
              "unique_tx_ids":True,"feature_label_id_sets_equal":True,"time_steps":sorted(int(s) for s in set(step)),
              "tx_order_sha256":hashlib.sha256(tx.astype('<i8').tobytes()).hexdigest(),
              "label_mapping":{"1":1,"2":0,"unknown":-1},"counts_by_step":per_step,
              "feature_availability":"All CSV features are publisher-prepared and globally normalized. No per-transaction raw availability or historical feedback timestamp is established.",
              "scope":"data audit only; no model fit, no policy comparison, no new independent test population"}
    dump(record,out/"data_audit.json")
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=ROOT/"data/raw/elliptic_v1")
    parser.add_argument("--download",action="store_true")
    parser.add_argument("--run-id")
    args=parser.parse_args()
    args.root=args.root.resolve()
    run_id=args.run_id or datetime.now(timezone.utc).strftime("elliptic_data_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name!=run_id:raise ValueError("run-id must be one component")
    out=PAPER/"runs"/run_id;out.mkdir(parents=True,exist_ok=False)
    shutil.copy2(__file__,out/"elliptic_data_source.py")
    manifest={"schema_version":"elliptic_data_run_v1","status":"running","started_utc":datetime.now(timezone.utc).isoformat(),
              "command":[sys.executable,*sys.argv],"source_sha256":sha256(__file__),"python":sys.version,
              "numpy":np.__version__,"pandas":pd.__version__,"root":str(args.root.relative_to(ROOT)),
              "pinned_companion_commit":PIN,"model_training_performed":False}
    dump(manifest,out/"manifest.json")
    try:
        acquisition=acquire(args.root) if args.download else json.loads((args.root/"acquisition.json").read_text())
        dump(acquisition,out/"acquisition_manifest.json")
        result=audit(args.root,out)
        manifest.update(status="complete",finished_utc=datetime.now(timezone.utc).isoformat(),
                        source_unchanged=sha256(__file__)==manifest['source_sha256'],
                        audit_sha256=sha256(out/"data_audit.json"))
        dump(manifest,out/"manifest.json")
        print(json.dumps({"status":"complete","run":str(out),"data_root":str(args.root),"nodes":result['nodes'],
                          "labels":result['label_counts'],"edges":result['edges'],"cross_step_edges":result['cross_step_edges']}),flush=True)
    except Exception as error:
        manifest.update(status="failed_incomplete",error=f"{type(error).__name__}: {error}")
        dump(manifest,out/"manifest.json")
        raise


if __name__=="__main__":
    main()
