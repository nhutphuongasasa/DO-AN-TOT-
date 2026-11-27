# Hybrid AppID Dashboard

This bundle adds a small HTML/CSS/JavaScript dashboard to the existing Hybrid AppID project.
It displays **finalized Flow decisions** from the real pipeline; it does not generate sample predictions.

## 1. Install / prepare

Use the project's existing virtual environment and dependencies. If this is a fresh setup:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[ml]'
```

## 2. Start the dashboard

Open terminal 1:

```bash
cd /path/to/p12-work
python3 scripts/run_dashboard.py
```

Open this URL in the browser:

`http://127.0.0.1:8765`

## 3. Start live AppID capture

Open terminal 2 in the same project folder. Example for the existing laptop NIC:

```bash
cd /path/to/p12-work
sudo -E .venv/bin/python -m appid.capture.live \
  --config config/network.json \
  --interface wlp62s0 \
  --ml-model outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm \
  --cnn-model outputs/p1_5_full_dataset_wirelen_v2/cnn1d/cnn1d_best.pt \
  --fusion-metrics outputs/p1_5_full_dataset_wirelen_v2/late_fusion/metrics.json \
  --burst-jsonl artifacts/live-bursts.jsonl \
  --burst-tsv artifacts/live-bursts.tsv
```

Replace `wlp62s0` with the correct interface name on the machine.

## How results reach the UI

- The packet pipeline continues to use DNS, SNI/QUIC, CatBoost and CNN1D late fusion.
- A Flow is published only after the processor finalizes it. The live capture writes each completed decision to `artifacts/live-appid-results.jsonl`.
- The dashboard polls its local read-only endpoint every two seconds and renders the final application, method and confidence.
- Active flows are not shown as final `UNKNOWN` rows while they are still being processed. Truly unresolved finalized flows may appear as `UNKNOWN`.
- Press `Ctrl+C` in the capture terminal to close the session and finalize remaining flows; those results are also published.

The dashboard server uses only Python's standard library. The HTML/CSS/JS frontend has no external CDN dependency.
