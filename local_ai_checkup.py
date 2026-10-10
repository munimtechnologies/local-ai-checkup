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
import urllib.error
import urllib.request

__version__ = "0.2.1"

PAID_CHECK_URL = "https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00"
HARDENING_URL = "https://github.com/munimv2/local-ai-checkup/blob/main/HARDENING.md"

# (name, port). Ports other than Ollama's are shared with plenty of non-AI
# software, so a listener there is only "probably" that tool until identified.
SERVICES = [
    ("Ollama", 11434),
    ("LM Studio server", 1234),
    ("Jan", 1337),
    ("llama.cpp server / LocalAI / Open WebUI", 8080),
    ("vLLM", 8000),
    ("Open WebUI", 3000),
    ("text-generation-webui", 7860),
    ("ComfyUI", 8188),
    ("MCP Inspector proxy", 6277),
    ("llama.cpp rpc-server", 50052),
]

# (fixed_in, description). Versions below fixed_in are affected.
OLLAMA_ADVISORIES = [
    ((0, 1, 34), "CVE-2024-37032 (\"Probllama\"): path traversal in model pull, "
                 "can lead to remote code execution"),
    ((0, 17, 1), "CVE-2026-7482 (\"Bleeding Llama\"): unauthenticated heap read "
                 "that can leak environment variables, API keys and other users' prompts"),
]
# (first_affected, fixed_in, description) for flaws introduced in a later release.
OLLAMA_RANGED_ADVISORIES = [
    ((0, 30, 0), (0, 33, 3), "CVE-2026-85180 (September 2026, reported for 0.30.0-0.33.2): a malicious model "
                             "registry can redirect a pull to internal addresses such as cloud metadata (SSRF)"),
    ((0, 34, 2), (0, 35, 0), "CVE-2026-103663 (CERT Polska, October 2026): path traversal in /api/pull "
                             "lets anyone who can reach the API write a file outside the model store; in "
                             "Docker images that file can be run as root on the next restart"),
]
# Flaws that only matter if an optional feature is used: reported as warnings.
OLLAMA_FEATURE_ADVISORIES = [
    ((0, 14, 0), (0, 31, 2), "CVE-2026-102697 (September 2026): in the experimental agent mode, a prompt "
                             "injection can chain extra shell commands onto a Bash command you already approved"),
]
# Windows-only updater flaws. CERT Polska confirmed 0.12.10-0.17.5; later
# testing found the same code through 0.23.2. The fix (ollama PR #16100) was
# merged on 2026-05-11, before the 0.24.0 release.
OLLAMA_WINDOWS_UPDATER = ((0, 12, 10), (0, 24, 0),
                          "CVE-2026-42248 / CVE-2026-42249: the Windows auto-updater does not really verify "
                          "update signatures and allows path traversal, so someone who can tamper with the "
                          "update download (for example on public Wi-Fi) can plant a program in your Startup folder")

OPEN_WEBUI_ADVISORIES = [
    ((0, 9, 0), "CVE-2026-44721 stored XSS through models, and CVE-2026-45349 where a user with an API key "
                "can continue another user's chat"),
    ((0, 9, 3), "CVE-2026-45317 request forgery through image URLs"),
    ((0, 9, 6), "CVE-2026-54010 signed-in users can read and delete other users' files"),
    ((0, 11, 0), "CVE-2026-70480 vega/vega-lite blocks can make viewers' browsers send requests"),
]

COMFYUI_ADVISORIES = [
    ((0, 28, 0), "CVE-2026-56673 and CVE-2026-56671: unauthenticated path traversal that can read image files "
                 "from anywhere on the disk, plus stored XSS through uploaded HTML/SVG (CVE-2026-56672, "
                 "CVE-2026-56670)"),
]

AI_IMAGE_HINT = re.compile(r"ollama|open-?webui|comfy|vllm|llama|localai|text-generation|lmstudio|tgi", re.I)

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
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return (out.stdout or "") + (out.stderr or "")


def get_json(url, timeout=2.0):
    try:
        with _opener.open(url, timeout=timeout) as r:
            return json.loads(r.read(2_000_000).decode("utf-8", "replace"))
    except Exception:
        return None


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
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(v):
    return ".".join(map(str, v))


def advisories_for(version, table):
    return [desc for fixed, desc in table if version < fixed]


def ollama_flaws(version, system):
    flaws = advisories_for(version, OLLAMA_ADVISORIES)
    flaws += [desc for low, fixed, desc in OLLAMA_RANGED_ADVISORIES if low <= version < fixed]
    low, fixed, desc = OLLAMA_WINDOWS_UPDATER
    windows_flaw = desc if system == "Windows" and low <= version < fixed else None
    return flaws, windows_flaw


def ollama_feature_flaws(version):
    return [desc for low, fixed, desc in OLLAMA_FEATURE_ADVISORIES if low <= version < fixed]


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


def parse_rocm(vram_json, name_json):
    """GPUs from `rocm-smi --showmeminfo vram --json` and `--showproductname --json`."""
    try:
        vram = json.loads(vram_json or "{}")
    except ValueError:
        return []
    try:
        names = json.loads(name_json or "{}")
    except ValueError:
        names = {}
    gpus = []
    for card, fields in sorted(vram.items()):
        if not isinstance(fields, dict):
            continue
        total = used = None
        for k, v in fields.items():
            if "total" in k.lower() and str(v).isdigit():
                if "used" in k.lower():
                    used = int(v)
                else:
                    total = int(v)
        if not total:
            continue
        info = names.get(card) if isinstance(names.get(card), dict) else {}
        name = info.get("Card Series") or info.get("Card series") or info.get("Card model") or card
        gpus.append({"name": f"AMD {name}" if "amd" not in str(name).lower() else name,
                     "vram_bytes": total, "vram_used_bytes": used, "driver": "ROCm"})
    return gpus


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
    if not gpus and shutil.which("rocm-smi"):
        gpus = parse_rocm(run(["rocm-smi", "--showmeminfo", "vram", "--json"]),
                          run(["rocm-smi", "--showproductname", "--json"]))
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
        rep.add("info", "AMD ROCm tools found but VRAM could not be read",
                "Model-fit advice below assumes CPU only.")
    else:
        rep.add("info", "No NVIDIA/AMD GPU or Apple Silicon detected",
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


def parse_systemd_environment(text):
    """`systemctl show ollama -p Environment --value` prints KEY=VALUE pairs separated by spaces."""
    env = {}
    for item in re.findall(r'"[^"]*"|\S+', text or ""):
        item = item.strip('"')
        if "=" in item:
            k, v = item.split("=", 1)
            env[k] = v
    return env


def ollama_settings():
    """OLLAMA_* settings from this shell and, on Linux, from the systemd service."""
    found = {}
    for k in ("OLLAMA_HOST", "OLLAMA_ORIGINS"):
        if os.environ.get(k):
            found[k] = (os.environ[k], "this shell")
    if platform.system() == "Linux" and shutil.which("systemctl"):
        svc = parse_systemd_environment(run(["systemctl", "show", "ollama", "-p", "Environment", "--value"]))
        for k in ("OLLAMA_HOST", "OLLAMA_ORIGINS"):
            if svc.get(k):
                found[k] = (svc[k], "the ollama systemd service")
    return found


def wide_host(value):
    return bool(re.match(r"^(https?://)?(0\.0\.0\.0|\[?::\]?)?(:\d+)?/?$", value or "")) and value not in ("", None)


def check_ollama(rep, budget):
    binary = shutil.which("ollama")
    cli_version = parse_version(run([binary, "--version"])) if binary else None
    api = get_json("http://127.0.0.1:11434/api/version")
    api_version = parse_version(api.get("version")) if isinstance(api, dict) else None
    version = api_version or cli_version
    rep.facts["ollama"] = {"installed": bool(binary), "running": api is not None,
                           "version": vstr(version) if version else None}
    if not binary and api is None:
        rep.add("info", "Ollama not found")
        return

    if version:
        flaws, windows_flaw = ollama_flaws(version, platform.system())
        if flaws:
            rep.add("risk", f"Ollama {vstr(version)} has known security flaws",
                    "; ".join(flaws),
                    "Update Ollama to the latest release from https://ollama.com/download")
        else:
            rep.add("ok", f"Ollama {vstr(version)} is past the known critical server advisories",
                    "Some reported Ollama flaws have no confirmed fix yet, so keep the API off untrusted networks.")
        if windows_flaw:
            rep.add("warn", f"Ollama for Windows {vstr(version)} has a reported auto-updater flaw",
                    windows_flaw + ". The fix was merged in May 2026 (ollama PR #16100).",
                    "Update to the current release from https://ollama.com/download. Until then, turn off "
                    "'Auto-download updates' in Ollama's settings and avoid updating on untrusted networks.")
        for desc in ollama_feature_flaws(version):
            rep.add("warn", f"Ollama {vstr(version)} has a flaw in its experimental agent mode", desc,
                    "Update Ollama. Until then, don't approve agent Bash commands while the model is reading "
                    "untrusted web pages, files or prompts.")
    else:
        rep.add("warn", "Could not read the Ollama version", "",
                "Run `ollama --version` and compare with https://github.com/ollama/ollama/releases")

    settings = ollama_settings()
    rep.facts["ollama_settings"] = {k: v[0] for k, v in settings.items()}
    if "OLLAMA_HOST" in settings and wide_host(settings["OLLAMA_HOST"][0]):
        value, where = settings["OLLAMA_HOST"]
        rep.add("warn", f"OLLAMA_HOST is set to {value} in {where}",
                "That makes Ollama listen on every network interface, not only this machine.",
                "Use OLLAMA_HOST=127.0.0.1 unless you need remote access; if you do, put an "
                "authenticating reverse proxy (Caddy or nginx) in front and firewall port 11434.")
    if "OLLAMA_ORIGINS" in settings and "*" in settings["OLLAMA_ORIGINS"][0]:
        value, where = settings["OLLAMA_ORIGINS"]
        rep.add("warn", f"OLLAMA_ORIGINS is set to {value} in {where}",
                "Any website you open in your browser can then send requests to your local Ollama: "
                "run your models, list them, or pull new ones.",
                "Remove the wildcard and list only the origins you use, for example "
                "OLLAMA_ORIGINS=http://localhost:3000")

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


def identify(host, port):
    """Best-effort name of the AI service on host:port, or None."""
    if port == 11434:
        v = get_json(f"http://{host}:{port}/api/version")
        if isinstance(v, dict) and "version" in v:
            return "Ollama"
    if port in (3000, 8080):
        cfg = get_json(f"http://{host}:{port}/api/config")
        if isinstance(cfg, dict) and "features" in cfg and "version" in cfg:
            return "Open WebUI"
    if port == 8188:
        s = get_json(f"http://{host}:{port}/system_stats")
        if isinstance(s, dict) and "system" in s:
            return "ComfyUI"
    if port in (1234, 1337, 8080, 8000):
        m = get_json(f"http://{host}:{port}/v1/models")
        if isinstance(m, dict) and "data" in m:
            return f"an OpenAI-compatible model server on port {port}"
    return None


def check_exposure(rep):
    ip = lan_ip()
    rep.facts["lan_ip"] = ip
    ports = {}
    for name, port in SERVICES:
        local = port_open("127.0.0.1", port)
        on_lan = bool(ip) and port_open(ip, port)
        if not (local or on_lan):
            continue
        ident = identify("127.0.0.1" if local else ip, port)
        ports[port] = {"local": local, "lan": on_lan, "identified_as": ident}
        label = ident or f"something on port {port} (often {name})"
        if on_lan:
            detail = (f"It listens on your network address {ip}:{port}. Unless a firewall blocks that port, other "
                      "machines on your network can use it, and so can the whole internet if this host has a "
                      "public IP or a port forward.")
            if port == 11434:
                detail += (" Ollama has no login of its own: anyone who reaches it can run your models, pull "
                           "or push weights, and hit any unpatched flaw. LeakIX counted 12,269 openly "
                           "exposed Ollama servers in February 2026.")
            elif port == 6277:
                detail += (" The MCP Inspector proxy can start programs on this machine; before 0.14.1 it did so "
                           "for anyone who could reach it (CVE-2025-49596).")
            elif port == 50052:
                detail += " The llama.cpp RPC server has no authentication and is meant only for trusted networks."
            rep.add("risk" if ident or port in (6277, 50052) else "warn",
                    f"{label} is reachable on your network address", detail,
                    "Bind it to 127.0.0.1 (for Ollama: OLLAMA_HOST=127.0.0.1), or keep it on the network only "
                    "behind an authenticating reverse proxy and a firewall rule for trusted IPs. To see whether "
                    "it is visible from the internet, look up your public IP on https://leakix.net or Shodan.")
        else:
            rep.add("ok", f"{label} listens only on this machine")
    rep.facts["listening"] = {str(p): v for p, v in ports.items()}
    rep.facts["exposed_on_network"] = any(v["lan"] for v in ports.values()) if ip else None
    if not ip:
        rep.add("info", "Could not determine this machine's network address; network exposure was not tested")
    return ports


def check_open_webui(rep, ports):
    for port in (3000, 8080):
        info = ports.get(port)
        if not info or info["identified_as"] != "Open WebUI":
            continue
        cfg = get_json(f"http://127.0.0.1:{port}/api/config") if info["local"] else None
        if not isinstance(cfg, dict):
            cfg = get_json(f"http://{rep.facts['lan_ip']}:{port}/api/config") or {}
        version = parse_version(cfg.get("version"))
        features = cfg.get("features") if isinstance(cfg.get("features"), dict) else {}
        rep.facts["open_webui"] = {"port": port, "version": vstr(version) if version else None,
                                   "auth": features.get("auth"), "enable_signup": features.get("enable_signup")}
        if version:
            flaws = advisories_for(version, OPEN_WEBUI_ADVISORIES)
            if flaws:
                rep.add("risk" if info["lan"] else "warn", f"Open WebUI {vstr(version)} has known security flaws",
                        "; ".join(flaws), "Update Open WebUI to 0.11.0 or newer (for Docker: pull the new image "
                        "and recreate the container; your data volume is kept).")
            else:
                rep.add("ok", f"Open WebUI {vstr(version)} is past the known advisories")
        if features.get("auth") is False:
            rep.add("risk" if info["lan"] else "warn", "Open WebUI login is turned off (WEBUI_AUTH=False)",
                    "Everyone who can open the page is the admin: they can read all chats, change settings "
                    "and use every connected model and API key.",
                    "Remove WEBUI_AUTH=False unless this is a single-user setup bound to 127.0.0.1.")
        if features.get("enable_signup") and info["lan"]:
            rep.add("warn", "Open WebUI lets anyone on the network sign up",
                    "New accounts are 'pending' by default, but it is one setting away from open access.",
                    "Turn off sign-up in Admin Settings > General once your users have accounts.")


def check_comfyui(rep, ports):
    info = ports.get(8188)
    if not info or info["identified_as"] != "ComfyUI":
        return
    stats = get_json("http://127.0.0.1:8188/system_stats" if info["local"]
                     else f"http://{rep.facts['lan_ip']}:8188/system_stats") or {}
    system = stats.get("system") if isinstance(stats.get("system"), dict) else {}
    version = parse_version(system.get("comfyui_version"))
    rep.facts["comfyui"] = {"version": vstr(version) if version else None}
    if version:
        flaws = advisories_for(version, COMFYUI_ADVISORIES)
        if flaws:
            rep.add("risk" if info["lan"] else "warn", f"ComfyUI {vstr(version)} has known security flaws",
                    "; ".join(flaws),
                    "Update ComfyUI to 0.28.0 or newer and ComfyUI-Manager to 3.38 or newer. Exposed ComfyUI "
                    "servers were hijacked for cryptomining in 2026 through custom nodes and an old Manager flaw.")
        else:
            rep.add("ok", f"ComfyUI {vstr(version)} is past the known advisories",
                    "Custom nodes can still run code; install only ones you trust.")


def check_mcp_inspector(rep, ports):
    info = ports.get(6277)
    if info and not info["lan"]:
        rep.add("warn", "Something is listening on port 6277, the MCP Inspector proxy port",
                "MCP Inspector before 0.14.1 let any web page you visited start programs on this machine "
                "(CVE-2025-49596, CVSS 9.4).",
                "Make sure it is 0.14.1 or newer (`npx @modelcontextprotocol/inspector@latest`) and stop it "
                "when you are not using it.")


def parse_docker_ps(text):
    """[(image, host_port, container_port)] for ports published on all interfaces."""
    out = []
    for line in (text or "").splitlines():
        if "|" not in line:
            continue
        image, ports = line.split("|", 1)
        for host_port, cport in re.findall(r"(?:0\.0\.0\.0|\[::\]|::):(\d+)->(\d+)", ports):
            item = (image.strip(), int(host_port), int(cport))
            if item not in out:
                out.append(item)
    return out


def check_docker(rep):
    if not shutil.which("docker"):
        return
    published = parse_docker_ps(run(["docker", "ps", "--format", "{{.Image}}|{{.Ports}}"], timeout=10))
    ai_ports = {p for _, p in SERVICES}
    hits = [(img, hp, cp) for img, hp, cp in published if hp in ai_ports or AI_IMAGE_HINT.search(img)]
    rep.facts["docker_published_ai_ports"] = [{"image": i, "host_port": h, "container_port": c} for i, h, c in hits]
    for img, hp, cp in hits:
        rep.add("warn", f"Docker container {img} publishes port {hp} on all network interfaces",
                "`-p {0}:{1}` means 0.0.0.0. On Linux, ports Docker publishes skip ufw and firewalld rules, "
                "so a host firewall may not protect it.".format(hp, cp),
                f"Publish it on localhost only: `-p 127.0.0.1:{hp}:{cp}` (or \"127.0.0.1:{hp}:{cp}\" in compose).")


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
    print(f"Step-by-step fixes: {HARDENING_URL}")
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
    ports = check_exposure(rep)
    check_open_webui(rep, ports)
    check_comfyui(rep, ports)
    check_mcp_inspector(rep, ports)
    check_docker(rep)
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
