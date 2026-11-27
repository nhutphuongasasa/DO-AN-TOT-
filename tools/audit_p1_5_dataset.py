#!/usr/bin/env python3
"""Read-only structural audit for P1.5 CSV + JSONL exports."""
import argparse
import csv
import json
import math
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--report", default="audit_report.json")
    a=ap.parse_args()
    errors=[]; warnings=[]
    with open(a.csv, newline="", encoding="utf-8") as f:
        rows=list(csv.DictReader(f))
    seqs=[]
    with open(a.jsonl, encoding="utf-8") as f:
        for n,line in enumerate(f,1):
            if line.strip():
                try: seqs.append(json.loads(line))
                except Exception as e: errors.append(f"JSONL line {n}: {e}")
    csv_keys=set()
    for r in rows:
        key=(r.get("session_id"),r.get("flow_id"),r.get("burst_index"))
        if key in csv_keys: errors.append(f"duplicate CSV burst key {key}")
        csv_keys.add(key)
        if not r.get("application") or not r.get("batch_id"): errors.append(f"missing label/batch for {key}")
    seq_keys=set()
    for seq in seqs:
        if not all(seq.get(k) for k in ("session_id","flow_id","application","batch_id")):
            errors.append(f"sequence missing lineage/label: {seq.get('flow_id')}")
        key=(seq.get("session_id"),seq.get("flow_id"))
        if key in seq_keys: errors.append(f"duplicate sequence {key}")
        seq_keys.add(key)
        bursts=seq.get("bursts",[])
        if seq.get("sequence_length") != len(bursts): errors.append(f"sequence length mismatch {key}")
        for b in bursts:
            lengths=b.get("packet_lengths",[]); times=b.get("packet_timestamps",[]); indexes=b.get("packet_indices",[])
            if not (len(lengths)==len(times)==len(indexes)==b.get("packet_count")):
                errors.append(f"packet array/count mismatch {key} burst={b.get('burst_index')}")
            if sum(lengths)!=b.get("total_bytes"): errors.append(f"bytes mismatch {key} burst={b.get('burst_index')}")
            if len(indexes)!=len(set(indexes)): errors.append(f"duplicate packet index {key} burst={b.get('burst_index')}")
            if any(not math.isfinite(float(t)) for t in times): errors.append(f"non-finite timestamp {key}")
            csv_key=(key[0],key[1],str(b.get("burst_index")))
            if csv_key not in csv_keys: errors.append(f"sequence burst missing CSV row {csv_key}")
    report={"csv_burst_rows":len(rows),"flow_sequences":len(seqs),"errors":errors,"warnings":warnings,"status":"PASS" if not errors else "FAIL"}
    Path(a.report).write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if not errors else 2)
if __name__=="__main__": main()
