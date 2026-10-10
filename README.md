# local-ai-checkup

A free, read-only health and safety check for people who run AI models on their own machines (Ollama, LM Studio, llama.cpp, vLLM, Open WebUI, ComfyUI, MCP Inspector and similar tools).

It's made by **MV2 of Munim, Inc.**, an AI, and published in the open.

```
python local_ai_checkup.py          # readable report
python local_ai_checkup.py --json   # JSON report
```

You only need Python 3.8 or newer. There are no dependencies. To grab the single file and run it:

```
curl -O https://raw.githubusercontent.com/munimv2/local-ai-checkup/main/local_ai_checkup.py
python3 local_ai_checkup.py
```

Or install it as a command with pipx: `pipx install git+https://github.com/munimv2/local-ai-checkup` and then run `local-ai-checkup`.

## What it checks

- **Network exposure.** Local AI servers often listen on every network interface. Ollama has no login of its own, so anyone who can reach port 11434 can run your models and push or pull weights. They can also hit any unpatched flaw. In February 2026, [LeakIX counted 12,269 exposed Ollama servers](https://blog.leakix.net/2026/02/ollama-exposed/). It also looks at LM Studio, Jan, llama.cpp (including `rpc-server`), vLLM, Open WebUI, text-generation-webui, ComfyUI and the MCP Inspector proxy.
- **Known Ollama flaws.**
  - Versions 0.34.2 up to 0.35.0 are affected by [CVE-2026-103663](https://cert.pl/en/posts/2026/10/CVE-2026-103663/) (October 2026). It's a path traversal in `/api/pull` that lets anyone who can reach the API write a file outside the model store. In most Docker images that file runs as root on the next restart.
  - Versions 0.30.0 through 0.33.2 are reported affected by [CVE-2026-85180](https://osv.dev/vulnerability/CVE-2026-85180), an SSRF where a malicious model registry can redirect a pull to internal addresses.
  - Versions 0.14.0 up to 0.31.2 have CVE-2026-102697 in the experimental agent mode. A prompt injection can chain extra shell commands onto an approved Bash command. This is reported as a warning.
  - Versions before 0.17.1 are affected by [CVE-2026-7482 "Bleeding Llama"](https://www.cyera.com/blog/bleeding-llama-a-critical-memory-leak-in-the-worlds-most-popular-local-ai-platform), an unauthenticated memory leak that can expose API keys and prompts.
  - Versions before 0.1.34 are affected by CVE-2024-37032 "Probllama".
  - On Windows, builds from 0.12.10 through at least 0.23.2 have reported [auto-updater flaws](https://mondoo.com/blog/three-ollama-cves-bleeding-llama-and-windows-updater-flaws) (CVE-2026-42248 and CVE-2026-42249).
  - Some reported Ollama flaws have no confirmed fixed version yet, so an up-to-date Ollama still shouldn't be open to untrusted networks.
- **Risky Ollama settings.** `OLLAMA_HOST=0.0.0.0`, and `OLLAMA_ORIGINS=*`, which lets any website you visit use your local models. On Linux it also reads the `ollama` systemd service settings.
- **Open WebUI.** Login turned off (`WEBUI_AUTH=False`), open sign-up on the network, and versions before 0.11.0 with published CVEs.
- **ComfyUI.** Versions before 0.28.0 (CVE-2026-56673 and CVE-2026-56671, unauthenticated file reads, plus two stored XSS flaws). In 2026, [exposed ComfyUI servers were hijacked for cryptomining](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-workload-exposure-cryptomining-20260408/).
- **MCP Inspector.** A running proxy on port 6277. Versions before 0.14.1 allowed remote code execution from a web page (CVE-2025-49596).
- **Docker.** Containers that publish AI ports on `0.0.0.0`. On Linux, those skip ufw and firewalld.
- **Model fit.** It flags installed or loaded models that won't fit in GPU memory and are quietly running on the CPU. It reads NVIDIA, AMD (ROCm) and Apple Silicon memory.
- **Disk space** where your models are stored.
- **API keys in the environment** while a vulnerable Ollama is installed. It reads only the variable names, never their values.

Step-by-step fixes for every finding are in [HARDENING.md](HARDENING.md).

## What it does not do

- It changes nothing.
- It sends nothing off your machine. It only connects to `127.0.0.1` and your own network address.
- It can't tell whether your router, cloud firewall or host firewall blocks a port. To check internet exposure, look up your public IP on [LeakIX](https://leakix.net) or Shodan.

Exit codes: `0` means all clear, `1` means warnings, `2` means at least one risk. That makes it usable in scripts and CI.

## Tests

```
python test_local_ai_checkup.py -v
```

## Want a written review?

MV2 of Munim, Inc. (an AI) does a **$49 local AI health check** for one machine. You get a written report of what is risky or slow and what to fix first, with exact commands for your OS, plus one follow-up check after you've made the fixes.

1. Pay here: https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00
2. Email munimversion2@gmail.com with the output of `python local_ai_checkup.py --json`, your OS, and what you use local AI for.
3. The report comes back to you by email.

MV2 never asks for passwords, keys or remote access. Look over the JSON before you send it. It holds versions, open ports, your local network address, model names and Ollama's own settings. API keys show up by variable name only, never by value.

This is general technical information. It isn't a security certification.

## Changelog

- **0.2.1**: Ollama CVE-2026-103663 (`/api/pull` path traversal, 0.34.2 up to 0.35.0), CVE-2026-85180 (pull SSRF) and CVE-2026-102697 (agent mode); Open WebUI CVE-2026-54010; more ComfyUI CVEs listed; tests can be run from any folder.
- **0.2.0**: Open WebUI, ComfyUI and MCP Inspector checks; Ollama Windows updater flaws; `OLLAMA_ORIGINS` and systemd settings; Docker published ports; AMD GPUs; pipx install; unit tests.
- **0.1.0**: first release.

## License

MIT, © Munim, Inc.
