import os
import sys
import time
import threading
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Ensure we can import project modules (lucid_*.py at repo root)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import numpy as np
import pyshark
from tensorflow.keras.models import load_model

from util_functions import static_min_max, normalize_and_padding, count_packets_in_dataset
from lucid_dataset_parser import process_live_traffic, parse_labels, dataset_to_list_of_fragments


class StartConfig(BaseModel):
    source: str  # network interface name or path to pcap file
    model_path: str
    dataset_type: Optional[str] = None  # DOS2017 | DOS2018 | DOS2019 | SYN2020 (optional for accuracy calc)
    attack_net: Optional[str] = None    # optional for accuracy calc on custom traffic
    victim_net: Optional[str] = None    # optional for accuracy calc on custom traffic
    threshold: float = 0.5              # threshold on fraction of predicted ddos windows to trigger alert


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        failed: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                failed.append(connection)
        for ws in failed:
            self.disconnect(ws)


class DetectorService:
    def __init__(self, manager: ConnectionManager):
        self.manager = manager
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._status: str = "idle"
        self._last_error: Optional[str] = None
        self._history: List[Dict[str, Any]] = []  # recent metrics and alerts

        # dynamic runtime state
        self.cap: Optional[pyshark.LiveCapture] = None
        self.cap_file: Optional[pyshark.FileCapture] = None
        self.model = None
        self.model_info: Dict[str, Any] = {}
        self.labels = None
        self.time_window: int = 10
        self.max_flow_len: int = 10
        self.threshold: float = 0.5

        # mitigation simulation
        self.blocked_sources = set()

        # predictive analytics (simple EWMA of ddos_fraction)
        self._ewma_ddos = None
        self._ewma_alpha = 0.5

    def status(self) -> Dict[str, Any]:
        return {
            "status": self._status,
            "last_error": self._last_error,
            "model": self.model_info,
            "blocked_sources": list(self.blocked_sources),
        }

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        # close captures
        try:
            if self.cap:
                self.cap.close()
        except Exception:
            pass
        try:
            if self.cap_file:
                self.cap_file.close()
        except Exception:
            pass
        self.cap = None
        self.cap_file = None
        self._status = "idle"

    def _resolve_model_path(self, path: str) -> str:
        """Resolve a model path. Accepts absolute paths, relative paths, or just a filename
        and tries common locations like the repo ./output folder.
        """
        candidates = []
        # 1) as provided (expanded)
        p = os.path.expanduser(path)
        candidates.append(p)
        # 2) if just a filename, try ./output/<name>
        if os.path.basename(p) == p:
            candidates.append(os.path.join(REPO_ROOT, "output", p))
        # 3) try repo root + provided (for relative paths from different CWDs)
        if not os.path.isabs(p):
            candidates.append(os.path.join(REPO_ROOT, p))
        # 4) try CWD ./output/<name>
        if os.path.basename(p) == p:
            candidates.append(os.path.join(os.getcwd(), "output", p))

        for c in candidates:
            if os.path.isfile(c):
                return c
        raise FileNotFoundError(f"Model not found. Tried: {', '.join(candidates)}")

    def _resolve_source_path(self, source: str) -> str:
        """Resolve PCAP source path if it's a file. If it's an interface name, return as-is."""
        if source.endswith('.pcap'):
            s = os.path.expanduser(source)
            if os.path.isfile(s):
                return s
            # try repo root
            rr = os.path.join(REPO_ROOT, source)
            if os.path.isfile(rr):
                return rr
            # try sample-dataset in repo if only filename was given
            if os.path.basename(s) == s:
                sd = os.path.join(REPO_ROOT, 'sample-dataset', s)
                if os.path.isfile(sd):
                    return sd
            # try CWD
            cwdp = os.path.join(os.getcwd(), source)
            if os.path.isfile(cwdp):
                return cwdp
            # leave not found; pyshark will fail later with a clearer path
            return s
        return source

    def start(self, cfg: StartConfig):
        if self._status == "running":
            raise RuntimeError("Detector already running")

        # Load model and infer time window and flow len from filename convention: '<t>t-<n>n-*.h5'
        resolved_model_path = self._resolve_model_path(cfg.model_path)
        model_filename = os.path.basename(resolved_model_path)
        try:
            prefix = model_filename.split('n')[0] + 'n-'
            self.time_window = int(prefix.split('t-')[0])
            self.max_flow_len = int(prefix.split('t-')[1].split('n-')[0])
        except Exception:
            # fallback to defaults if parsing fails
            self.time_window = 10
            self.max_flow_len = 10

        self.model = load_model(resolved_model_path)
        self.model_info = {
            "path": resolved_model_path,
            "time_window": self.time_window,
            "max_flow_len": self.max_flow_len,
        }

        # labels (optional - for accuracy calc if dataset info provided)
        self.labels = parse_labels(cfg.dataset_type, cfg.attack_net, cfg.victim_net)

        # capture setup
        resolved_source = self._resolve_source_path(cfg.source)
        if resolved_source.endswith('.pcap'):
            self.cap_file = pyshark.FileCapture(resolved_source)
            self.cap = None
            data_source = os.path.basename(resolved_source)
        else:
            self.cap = pyshark.LiveCapture(interface=resolved_source)
            self.cap_file = None
            data_source = resolved_source

        self.threshold = cfg.threshold
        self._stop_event.clear()
        self._status = "running"
        self._last_error = None

        # start background loop
        self._thread = threading.Thread(target=self._loop, args=(data_source,), daemon=True)
        self._thread.start()

    def _loop(self, data_source: str):
        mins, maxs = static_min_max(self.time_window)
        while not self._stop_event.is_set():
            try:
                cap = self.cap if self.cap is not None else self.cap_file
                samples = process_live_traffic(cap, None, self.labels, self.max_flow_len, traffic_type="all", time_window=self.time_window)
                if len(samples) == 0:
                    # For file capture, when finished, stop
                    if isinstance(cap, pyshark.FileCapture):
                        self._status = "completed"
                        break
                    # For live capture, just continue to next window
                    continue

                # Apply mitigation simulation by filtering flows from blocked sources
                if self.blocked_sources:
                    filtered = []
                    for (five_tuple, flow_dict) in samples:
                        src_ip = five_tuple[0]
                        if src_ip not in self.blocked_sources:
                            filtered.append((five_tuple, flow_dict))
                    samples = filtered

                # Compute metrics for current window
                metrics = self._compute_metrics(samples)

                # Build input for model
                X, Y_true, keys = dataset_to_list_of_fragments(samples)
                X = np.array(normalize_and_padding(X, mins, maxs, self.max_flow_len))
                X = np.expand_dims(X, axis=3)

                t0 = time.time()
                y_pred = np.squeeze(self.model.predict(X, batch_size=2048) > 0.5, axis=1)
                latency = time.time() - t0
                [packets] = count_packets_in_dataset([X])

                ddos_fraction = float(np.sum(y_pred) / y_pred.shape[0]) if y_pred.shape[0] > 0 else 0.0
                alert = ddos_fraction >= self.threshold

                # Predictive analytics via EWMA trend estimation
                if self._ewma_ddos is None:
                    self._ewma_ddos = ddos_fraction
                else:
                    self._ewma_ddos = self._ewma_alpha * ddos_fraction + (1 - self._ewma_alpha) * self._ewma_ddos
                predicted_next = self._ewma_ddos  # naive next-step forecast
                predicted_alert = predicted_next >= self.threshold

                payload = {
                    "ts": time.time(),
                    "source": data_source,
                    "packets": int(packets),
                    "samples": int(y_pred.shape[0]),
                    "ddos_fraction": ddos_fraction,
                    "latency_sec": latency,
                    "metrics": metrics,
                    "alert": alert,
                    "threshold": self.threshold,
                    "forecast": {
                        "ddos_fraction_next": predicted_next,
                        "predicted_alert": predicted_alert,
                    }
                }
                self._history.append(payload)
                # Limit history size
                if len(self._history) > 500:
                    self._history = self._history[-500:]

                # Broadcast to clients
                import anyio
                anyio.from_thread.run(self.manager.broadcast, payload)

            except Exception as e:
                self._last_error = str(e)
                self._status = "error"
                break

    def _compute_metrics(self, samples: List):
        # samples: list of tuples (five_tuple, flow_dict)
        flow_count = len(samples)
        uniq_dst_ports = set()
        uniq_src_ips = set()
        total_pkts = 0
        for (five_tuple, flow_dict) in samples:
            src_ip, src_port, dst_ip, dst_port, proto = five_tuple
            if isinstance(dst_port, int):
                uniq_dst_ports.add(dst_port)
            uniq_src_ips.add(src_ip)
            # count packets in this window
            for k, arr in flow_dict.items():
                if k == 'label':
                    continue
                total_pkts += int(arr.shape[0])

        metrics = {
            "flow_density": flow_count,                # flows per window
            "unique_dest_ports": len(uniq_dst_ports),  # count of distinct destination ports
            "src_ip_diversity": len(uniq_src_ips),     # count of distinct source IPs
            "packet_volume": total_pkts,               # total packets in window
        }
        return metrics

    def block_sources(self, sources: List[str]):
        for s in sources:
            self.blocked_sources.add(s)

    def unblock_sources(self, sources: List[str]):
        for s in sources:
            if s in self.blocked_sources:
                self.blocked_sources.remove(s)

    def history(self) -> List[Dict[str, Any]]:
        return self._history


app = FastAPI(title="LUCID DDoS Detection Web Service", version="0.1.0")
manager = ConnectionManager()
service = DetectorService(manager)


# Serve static dashboard
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>LUCID DDoS Dashboard</h1><p>UI not found.</p>")


@app.get("/api/status")
def get_status():
    return service.status()


@app.get("/api/history")
def get_history():
    return service.history()


@app.post("/api/start")
def start(cfg: StartConfig):
    try:
        service.start(cfg)
        return {"ok": True, "status": service.status()}
    except FileNotFoundError as e:
        # Bad request from client (wrong path)
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        # Conflicting state
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        # Unexpected server error
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/stop")
def stop():
    service.stop()
    return {"ok": True, "status": service.status()}


class MitigationRequest(BaseModel):
    block_sources: Optional[List[str]] = None
    unblock_sources: Optional[List[str]] = None


@app.post("/api/mitigation")
def mitigation(req: MitigationRequest):
    if req.block_sources:
        service.block_sources(req.block_sources)
    if req.unblock_sources:
        service.unblock_sources(req.unblock_sources)
    return {"ok": True, "blocked_sources": list(service.blocked_sources)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection open; we don't expect messages from client, but we receive pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
