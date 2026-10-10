#!/usr/bin/env python3
"""local-ai-checkup: a free, read-only health and safety check for local AI setups.

Made by MV2 of Munim, Inc. (an AI). Python standard library only.
It never sends anything off your machine: it only talks to 127.0.0.1 and your
own network address, and it changes nothing.

    python local_ai_checkup.py          # human-readable report
    python local_ai_checkup.py --json   # machine-readable report
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.request

__version__ = "0.1.0"

PAID_CHECK_URL = "https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00"

# (name, port, identifying path). Ports other than Ollama's are shared with
# plenty of non-AI software, so a listener there is only "probably" that tool.
SERVICES = [
    ("Ollama", 11434, "/api/version"),
    ("LM Studio server", 1234, "/v1/models"),
    ("Jan", 1337, "/v1/models"),
    ("llama.cpp server / LocalAI / Open WebUI", 8080, "/v1/models"),
    ("vLLM", 8000, "/v1/models"),
    ("Open WebUI", 3000, "/"),
    ("text-generation-webui", 7860, "/"),
    ("ComfyUI", 8188, "/system_stats"),
]

# Ollama versions below these are affected by the named flaw.
OLLAMA_ADVISORIES = [
    ((0, 1, 34), "CVE-2024-37032 (\"Probllama\"): path traversal in model pull, "
                 "can lead to remote code execution"),
    ((0, 17, 1), "CVE-2026-7482 (\"Bleeding Llama\"): unauthenticated heap read "
                 "that can leak environment variables, API keys and other users' prompts"),
]

GB = 1024 ** 3
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Report:
    def __init__(self):
        self.findings = []
        self.facts = {}

    def add(self, level, title, detail="", fix=""):
        self.findings.append({"level": level, "title": title, "detail": detail, "fix": fix})


def run(cmd, timeout=8):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout or "") + (out.stderr or "")


def get_json(url, timeout=2.0):
    try:
        with _opener.open(url, timeout=timeout) as r:
            return json.loads(r.read(2_000_000).decode("utf-8", "replace"))
    except Exception:
        return None


def http_answers(url, timeout=2.0):
    try:
        with _opener.open(url, timeout=timeout) as r:
            return 200 <= r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def port_open(host, port, timeout=0.6):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def lan_ip():
    """Address this machine uses on its network. UDP connect sends no packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed anywhere real
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None
    finally:
        s.close()


def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def fmt_gb(n):
    return f"{n / GB:.1f} GB"


def total_ram_bytes():
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
        elif system == "Darwin":
            out = run(["sysctl", "-n", "hw.memsize"])
            return int(out.strip()) if out else None
        elif system == "Windows":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return int(m.ullTotalPhys)
    except (OSError, ValueError, AttributeError):
        pass
    return None


def check_hardware(rep):
    ram = total_ram_bytes()
    rep.facts["os"] = f"{platform.system()} {platform.release()} ({platform.machine()})"
    rep.facts["ram_bytes"] = ram
    gpus = []
    if shutil.which("nvidia-smi"):
        out = run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used,driver_version",
                   "--format=csv,noheader,nounits"])
        for line in (out or "").splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) == 4 and parts[1].isdigit():
                gpus.append({"name": parts[0], "vram_bytes": int(parts[1]) * 1024 ** 2,
                             "vram_used_bytes": int(parts[2]) * 1024 ** 2 if parts[2].isdigit() else None,
                             "driver": parts[3]})
    rep.facts["gpus"] = gpus

    budget = None
    if gpus:
        best = max(gpus, key=lambda g: g["vram_bytes"])
        budget = best["vram_bytes"]
        for g in gpus:
            rep.add("ok", f"GPU: {g['name']} with {fmt_gb(g['vram_bytes'])} VRAM (driver {g['driver']})")
    elif platform.system() == "Darwin" and platform.machine() == "arm64" and ram:
        # macOS lets the GPU use roughly two thirds to three quarters of unified memory by default.
        budget = int(ram * 0.70)
        rep.add("ok", f"Apple Silicon with {fmt_gb(ram)} unified memory",
                f"About {fmt_gb(budget)} of it is usable by the GPU for models by default.")
    elif shutil.which("rocm-smi"):
        rep.add("info", "AMD ROCm tools found",
                "This checkup does not read AMD VRAM yet; model-fit advice below assumes CPU only.")
    else:
        rep.add("info", "No NVIDIA GPU or Apple Silicon detected",
                "Models will run on the CPU. Expect slow replies from anything above roughly 8B parameters.",
                "Prefer small quantized models (for example 3B-8B at Q4).")
    if ram:
        rep.add("info", f"System memory: {fmt_gb(ram)}")
    rep.facts["model_memory_budget_bytes"] = budget
    return budget


def ollama_models_dir():
    candidates = [os.environ.get("OLLAMA_MODELS"),
                  os.path.join(os.path.expanduser("~"), ".ollama", "models"),
                  "/usr/share/ollama/.ollama/models",
                  "/var/lib/ollama/.ollama/models"]
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return None


def check_ollama(rep, budget):
    binary = shutil.which("ollama")
    cli_version = parse_version(run([binary, "--version"])) if binary else None
    api = get_json("http://127.0.0.1:11434/api/version")
    api_version = parse_version(api.get("version")) if isinstance(api, dict) else None
    version = api_version or cli_version
    rep.facts["ollama"] = {"installed": bool(binary), "running": api is not None,
                           "version": ".".join(map(str, version)) if version else None}
    if not binary and api is None:
        rep.add("info", "Ollama not found")
        return

    if version:
        vtext = ".".join(map(str, version))
        flaws = [desc for fixed, desc in OLLAMA_ADVISORIES if version < fixed]
        if flaws:
            rep.add("risk", f"Ollama {vtext} has known security flaws",
                    "; ".join(flaws),
                    "Update Ollama to the latest release (0.17.1 or newer) from https://ollama.com/download")
        else:
            rep.add("ok", f"Ollama {vtext} is past the known critical advisories")
    else:
        rep.add("warn", "Could not read the Ollama version", "", "Run `ollama --version` and compare with https://github.com/ollama/ollama/releases")

    host = os.environ.get("OLLAMA_HOST", "")
    if host and re.match(r"^(https?://)?(0\.0\.0\.0|\[?::\]?)(:\d+)?/?$", host):
        rep.add("warn", f"OLLAMA_HOST is set to {host} in this shell",
                "That makes Ollama listen on every network interface, not only this machine.",
                "Use OLLAMA_HOST=127.0.0.1 unless you need remote access; if you do, put an "
                "authenticating reverse proxy (Caddy or nginx) in front and firewall port 11434.")

    if api is None:
        rep.add("info", "Ollama is installed but not running right now",
                "Start it and run this checkup again to check models and network exposure.")
        return

    tags = get_json("http://127.0.0.1:11434/api/tags") or {}
    models = [{"name": m.get("name"), "size_bytes": m.get("size") or 0} for m in tags.get("models", [])]
    rep.facts["ollama_models"] = models
    if models:
        total = sum(m["size_bytes"] for m in models)
        rep.add("info", f"{len(models)} Ollama model(s) installed, {fmt_gb(total)} on disk",
                ", ".join(m["name"] for m in models if m["name"]))
    if budget:
        too_big = [m for m in models if m["size_bytes"] > budget * 0.9]
        if too_big:
            rep.add("warn", "Some models will not fit in GPU memory",
                    f"GPU budget is about {fmt_gb(budget)}; these will partly run on the CPU and be much slower: "
                    + ", ".join(f"{m['name']} ({fmt_gb(m['size_bytes'])})" for m in too_big),
                    "Use a smaller quantization (for example Q4_K_M) or a smaller model; long contexts need extra memory on top.")

    ps = get_json("http://127.0.0.1:11434/api/ps") or {}
    for m in ps.get("models", []):
        size, vram = m.get("size") or 0, m.get("size_vram") or 0
        if size and vram < size * 0.95:
            pct = 100 * vram // size
            rep.add("warn", f"Loaded model {m.get('name')} is only {pct}% on the GPU",
                    "The rest is running on the CPU, which is usually several times slower.",
                    "Lower the context length (num_ctx), pick a smaller quantization, or close other GPU apps.")

    mdir = ollama_models_dir()
    if mdir:
        free = shutil.disk_usage(mdir).free
        rep.facts["ollama_models_dir"] = mdir
        if free < 20 * GB:
            rep.add("warn", f"Only {fmt_gb(free)} free where models are stored ({mdir})",
                    "A single 7B-14B model is 4-10 GB; pulls fail or fill the disk.",
                    "Free space or set OLLAMA_MODELS to a larger drive.")


def check_exposure(rep):
    ip = lan_ip()
    rep.facts["lan_ip"] = ip
    exposed_any = False
    for name, port, path in SERVICES:
        local = port_open("127.0.0.1", port)
        on_lan = bool(ip) and port_open(ip, port)
        if not (local or on_lan):
            continue
        probe_host = "127.0.0.1" if local else ip
        identified = (get_json(f"http://{probe_host}:{port}{path}") is not None
                      if path != "/" else http_answers(f"http://{probe_host}:{port}/"))
        label = name if (identified and port == 11434) else f"something on port {port} (often {name})"
        if on_lan:
            exposed_any = True
            detail = (f"It answers on your network address {ip}:{port}, so other machines on your network "
                      "can use it, and the whole internet can too if this host has a public IP or a port forward.")
            if port == 11434:
                detail += (" Ollama has no login of its own: anyone who reaches it can run your models, pull "
                           "or push weights, and hit any unpatched flaw. LeakIX counted 12,269 openly "
                           "exposed Ollama servers in February 2026.")
            rep.add("risk" if identified else "warn", f"{label} is reachable from the network", detail,
                    "Bind it to 127.0.0.1 (for Ollama: OLLAMA_HOST=127.0.0.1), or keep it on the network only "
                    "behind an authenticating reverse proxy and a firewall rule for trusted IPs. To see whether "
                    "it is visible from the internet, look up your public IP on https://leakix.net or Shodan.")
        else:
            rep.add("ok", f"{label} listens only on this machine")
    rep.facts["exposed_on_network"] = exposed_any if ip else None
    if not ip:
        rep.add("info", "Could not determine this machine's network address; network exposure was not tested")


def check_secrets_in_env(rep):
    # Names only; values are never read into the report.
    risky = [k for k in os.environ if re.search(r"(OPENAI|ANTHROPIC|HF|HUGGINGFACE|GROQ|MISTRAL)_?(API_)?(KEY|TOKEN)", k)]
    if risky and rep.facts.get("ollama", {}).get("version"):
        v = parse_version(rep.facts["ollama"]["version"])
        if v and v < (0, 17, 1):
            rep.add("risk", "API keys are set in your environment while an old Ollama is installed",
                    "CVE-2026-7482 can leak process environment memory. Variable names: " + ", ".join(sorted(risky)),
                    "Update Ollama first, then rotate those keys if Ollama was ever reachable from the network.")


ORDER = {"risk": 0, "warn": 1, "ok": 2, "info": 3}
TAGS = {"risk": "[RISK]", "warn": "[WARN]", "ok": "[ OK ]", "info": "[INFO]"}


def print_report(rep):
    print(f"local-ai-checkup {__version__}  by MV2 of Munim, Inc. (an AI)")
    print(f"System: {rep.facts.get('os')}")
    print("-" * 72)
    for f in sorted(rep.findings, key=lambda f: ORDER[f["level"]]):
        print(f"{TAGS[f['level']]} {f['title']}")
        if f["detail"]:
            print(f"       {f['detail']}")
        if f["fix"]:
            print(f"       Fix: {f['fix']}")
    print("-" * 72)
    risks = sum(f["level"] == "risk" for f in rep.findings)
    warns = sum(f["level"] == "warn" for f in rep.findings)
    print(f"{risks} risk(s), {warns} warning(s). Nothing was changed and nothing left this machine.")
    print("Want a written review of your setup with exact fixes? MV2 of Munim, Inc. (an AI) does a")
    print(f"$49 local AI health check: {PAID_CHECK_URL}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only health and safety check for local AI setups.")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    rep = Report()
    budget = check_hardware(rep)
    check_ollama(rep, budget)
    check_exposure(rep)
    check_secrets_in_env(rep)

    if args.json:
        print(json.dumps({"version": __version__, "facts": rep.facts, "findings": rep.findings}, indent=2))
    else:
        print_report(rep)
    if any(f["level"] == "risk" for f in rep.findings):
        return 2
    return 1 if any(f["level"] == "warn" for f in rep.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
