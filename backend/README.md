# AIDS Backend — Real-Time Intrusion Detection API

FastAPI service that scores network traffic with a trained NSL-KDD model in
real time and streams results to the dashboard over WebSocket.

## What's included

```
aids_backend/
├── app/
│   ├── main.py          FastAPI app: /predict, /ingest, /mode, /health, /metrics, /ws
│   ├── model_utils.py    Loads the trained model + does the exact same
│   │                      preprocessing as the training notebook
│   └── simulator.py       Draws real NSL-KDD rows (with light jitter) to
│                          act as "simulated traffic" when no live capture
│                          agent is connected
├── artifacts/            Trained model + scaler + encoders (already trained
│                          on NSL-KDD — see "Using your own model" below)
├── live_capture_agent.py Optional: run LOCALLY to feed real packets from
│                          your own machine into the deployed backend
├── requirements.txt
└── Dockerfile
```

This backend already comes with a **working trained model** (Random Forest,
~78% binary / ~74% multiclass accuracy on the NSL-KDD held-out test set) —
you can deploy it as-is. Swap in a better-trained model later (see below)
without changing any other file.

## Run it locally first

```bash
cd aids_backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

`--host 0.0.0.0` matters: without it, uvicorn only listens on `127.0.0.1`,
which means only your own machine can reach it — not your phone, not
another laptop on the same network, and not the dashboard if you ever open
it from a different device. `0.0.0.0` makes it listen on every network
interface your machine has.

Visit `http://localhost:8000/health` — you should see `{"status":"ok",...}`.

### Connecting the dashboard

Run the frontend (see the top-level `README.md`, one folder up) — it
auto-connects to `http://localhost:8000` the moment it loads, no manual
step needed for the common case of both running on your own machine.

For anything else (another device, a deployed backend), use the
**Backend URL** box on the dashboard itself:

| Where you're opening the dashboard from | What to put in Backend URL |
|---|---|
| Same machine the backend is running on | `http://localhost:8000` (already filled in automatically) |
| Another device on the same Wi-Fi/LAN (phone, another laptop) | `http://<your-machine's-LAN-IP>:8000` |
| Anywhere on the internet | the deployed URL, e.g. `https://aids-backend.onrender.com` |

To find your machine's LAN IP:
- **Windows:** open Command Prompt → `ipconfig` → look for "IPv4 Address" (something like `192.168.1.23`)
- **Mac/Linux:** `ifconfig` or `ip a` → look for `inet` under your Wi-Fi/Ethernet adapter

Then on another device on the same network, open the dashboard and enter
`http://192.168.1.23:8000` (using your actual IP) and click Connect.

**Windows Firewall will likely block this the first time** — when you run
the `uvicorn` command, Windows may pop up "Allow Python to communicate on
this network?" → click **Allow**. If you don't see that prompt and it's
not connecting, check Windows Defender Firewall → Allow an app → make sure
Python (or the port) is allowed for Private networks.

The dashboard's Backend URL field works with any `http://` or `https://`
address — a plain IP, a domain name, `localhost`, whatever — it builds the
correct WebSocket URL from it automatically.

## Deploy it (so the dashboard works from anywhere, not just your laptop)

The `Dockerfile` is deployment-ready for any container host. Three common
free-tier options for a student project:

**Render.com**
1. Push this `aids_backend/` folder to a GitHub repo.
2. New → Web Service → connect the repo → Render auto-detects the
   `Dockerfile`.
3. No extra environment variables needed (the Dockerfile already reads `$PORT`).
4. Deploy — you'll get a URL like `https://aids-backend.onrender.com`.

**Railway.app**
1. New Project → Deploy from GitHub repo.
2. Railway auto-detects the `Dockerfile` and sets `$PORT` for you.
3. Deploy — you'll get a URL like `https://aids-backend.up.railway.app`.

**Fly.io**
```bash
fly launch      # detects the Dockerfile, asks a few questions
fly deploy
```

Whichever you pick, once it's live, paste that URL (e.g.
`https://aids-backend.onrender.com`) into the dashboard's "Backend URL"
field — the dashboard is a static file, so it can be opened from anywhere
(your laptop, GitHub Pages, Netlify) and just needs that one URL to connect.

**Note on free tiers:** most free tiers spin the container down after a
period of inactivity and take ~30–60s to wake back up on the next request.
That's normal — not a bug in this code. If you're demoing live, open the
dashboard and hit Connect a minute or two beforehand.

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Live stats: mode, events processed, intrusions, uptime, avg confidence |
| `/metrics` | GET | Static held-out test accuracy + this session's attack-category tally |
| `/predict` | POST | Score one raw feature record, no side effects (use for testing) |
| `/mode` | POST | `{"mode": "simulated"}` or `{"mode": "live"}` — switches the data source |
| `/ingest` | POST | Live-capture agent posts real traffic here (only scored when mode="live") |
| `/ws` | WebSocket | Dashboard subscribes here for the live event stream |

## Using your own model (higher accuracy)

Run the Colab notebook from earlier, then copy these files from its
`ids_artifacts/` output into this project's `artifacts/` folder, **keeping
the exact same filenames**:

```
rf_binary_model.pkl
rf_multiclass_model.pkl
scaler.pkl
label_encoder_binary.pkl
label_encoder_multiclass.pkl
feature_columns.pkl
```

Also copy `numeric_cols.pkl` / `categorical_cols.pkl` — if the notebook
didn't save these, just keep the ones already in this folder (the numeric/
categorical column lists don't change).

To report your notebook's real accuracy on the dashboard's "Model
performance" panel instead of this script's numbers, update
`artifacts/metrics.json`:
```json
{"binary_accuracy": 0.94, "multiclass_accuracy": 0.89}
```
(use the actual numbers your notebook printed).

## Using real live traffic instead of simulated

1. Deploy the backend (above).
2. On your own laptop: `pip install scapy requests`
3. Run, with admin/root privileges (packet capture requires it):
   ```bash
   sudo python3 live_capture_agent.py --backend https://your-backend-url
   ```
4. In the dashboard, click **"Live capture"** mode (or `POST /mode
   {"mode":"live"}`) — the backend will now only score events coming from
   your agent instead of the built-in simulator.

Read the docstring at the top of `live_capture_agent.py` — the feature
extraction there is a deliberately simplified approximation (packet/byte
counts over a short window), not full CICFlowMeter/Zeek-grade flow
extraction. It's a legitimate, common simplification for a student project;
just don't present it as production-grade traffic analysis if asked.
