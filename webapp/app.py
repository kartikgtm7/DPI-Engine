"""
DPI Engine — Web Demo Wrapper
Wraps the compiled `dpi_simple` C++ binary in a small FastAPI service so
the engine can be tried from a browser instead of the command line.

The binary itself is untouched — this file only shells out to it and
turns its stdout report into JSON for the frontend.
"""
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).parent
BINARY_PATH = BASE_DIR / "dpi_simple"
SAMPLE_PCAP = BASE_DIR / "sample" / "test_dpi.pcap"
OUTPUT_DIR = Path(tempfile.gettempdir()) / "dpi_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

VALID_APPS = [
    "Google", "Facebook", "YouTube", "Twitter/X", "Instagram", "Netflix",
    "Amazon", "Microsoft", "Apple", "WhatsApp", "Telegram", "TikTok",
    "Spotify", "Zoom", "Discord", "GitHub", "Cloudflare",
]

app = FastAPI(title="DPI Engine Demo")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def parse_report(raw_output: str) -> dict:
    """Turn the CLI's box-drawn report into structured JSON."""
    # Strip box-drawing characters (U+2500-U+257F) so lines like
    # "|| HTTPS   39  50.6% ##### ||" parse as plain "HTTPS 39 50.6% #####"
    raw_output = re.sub(r"[\u2500-\u257F]", " ", raw_output)
    result = {
        "total_packets": None,
        "forwarded": None,
        "dropped": None,
        "active_flows": None,
        "app_breakdown": [],
        "detected": [],
        "blocked_flows": [],
    }

    m = re.search(r"Total Packets:\s*(\d+)", raw_output)
    if m:
        result["total_packets"] = int(m.group(1))
    m = re.search(r"Forwarded:\s*(\d+)", raw_output)
    if m:
        result["forwarded"] = int(m.group(1))
    m = re.search(r"Dropped:\s*(\d+)", raw_output)
    if m:
        result["dropped"] = int(m.group(1))
    m = re.search(r"Active Flows:\s*(\d+)", raw_output)
    if m:
        result["active_flows"] = int(m.group(1))

    # App breakdown lines, e.g. "HTTPS                39  50.6% ##########"
    for m in re.finditer(r"^\s*([\w./-]+)\s+(\d+)\s+([\d.]+)%", raw_output, re.MULTILINE):
        name, count, pct = m.groups()
        if name in ("Total", "Forwarded", "Dropped", "Active"):
            continue
        result["app_breakdown"].append(
            {"name": name, "count": int(count), "percent": float(pct)}
        )

    # Detected domain -> app lines, e.g. "  - www.youtube.com -> YouTube"
    for m in re.finditer(r"^\s*-\s*(\S+)\s*->\s*(.+)$", raw_output, re.MULTILINE):
        domain, app_name = m.groups()
        result["detected"].append({"domain": domain, "app": app_name.strip()})

    # Blocked lines, e.g. "[BLOCKED] 192.168.1.100 -> 142.250.185.110 (YouTube: www.youtube.com)"
    for m in re.finditer(r"\[BLOCKED\]\s*([\d.]+)\s*->\s*([\d.]+)\s*\(([^:]+):\s*([^)]+)\)", raw_output):
        src, dst, app_name, domain = m.groups()
        result["blocked_flows"].append(
            {"src": src, "dst": dst, "app": app_name.strip(), "domain": domain.strip()}
        )

    return result


@app.get("/api/apps")
def list_apps():
    return {"apps": VALID_APPS}


@app.post("/api/analyze")
async def analyze(
    pcap: UploadFile | None = File(default=None),
    block_apps: str = Form(default=""),      # comma-separated
    block_domains: str = Form(default=""),   # comma-separated
    block_ips: str = Form(default=""),       # comma-separated
):
    if not BINARY_PATH.exists():
        return JSONResponse(status_code=500, content={"error": "Engine binary not found on server."})

    job_id = uuid.uuid4().hex[:12]
    input_path = OUTPUT_DIR / f"{job_id}_input.pcap"
    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"

    if pcap is not None and pcap.filename:
        with open(input_path, "wb") as f:
            shutil.copyfileobj(pcap.file, f)
        used_sample = False
    else:
        if not SAMPLE_PCAP.exists():
            return JSONResponse(status_code=500, content={"error": "No file uploaded and no sample available."})
        shutil.copy(SAMPLE_PCAP, input_path)
        used_sample = True

    cmd = [str(BINARY_PATH), str(input_path), str(output_path)]
    for app_name in filter(None, (a.strip() for a in block_apps.split(","))):
        cmd += ["--block-app", app_name]
    for domain in filter(None, (d.strip() for d in block_domains.split(","))):
        cmd += ["--block-domain", domain]
    for ip in filter(None, (i.strip() for i in block_ips.split(","))):
        cmd += ["--block-ip", ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=504, content={"error": "Analysis timed out."})
    finally:
        input_path.unlink(missing_ok=True)

    if proc.returncode != 0 and not output_path.exists():
        return JSONResponse(
            status_code=400,
            content={"error": "Engine failed to process the file.", "details": proc.stdout + proc.stderr},
        )

    parsed = parse_report(proc.stdout)
    parsed["used_sample"] = used_sample
    parsed["download_id"] = job_id if output_path.exists() else None
    return parsed


@app.get("/api/download/{job_id}")
def download(job_id: str):
    path = OUTPUT_DIR / f"{job_id}_output.pcap"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "File not found or expired."})
    return FileResponse(path, filename="dpi_output.pcap", media_type="application/vnd.tcpdump.pcap")


app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
