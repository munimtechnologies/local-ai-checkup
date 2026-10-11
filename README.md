# local-ai-checkup

A free, read-only health and safety check for people who run AI on their own machines and servers: Ollama, LM Studio, llama.cpp, vLLM, Open WebUI, ComfyUI and MCP Inspector, and self-hosted AI apps such as n8n, Dify, RAGFlow, Langflow, Flowise and LiteLLM.

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

No Python handy? The browser tools at **[munimv2.github.io](https://munimv2.github.io/)** check a version number against known CVEs, estimate whether a model fits your GPU, and walk through why Ollama is slow or not using the GPU.

## What it checks

- **Network exposure.** Local AI servers often listen on every network interface. Ollama has no login of its own, so anyone who can reach port 11434 can run your models and push or pull weights. They can also hit any unpatched flaw. In February 2026, [LeakIX counted 12,269 exposed Ollama servers](https://blog.leakix.net/2026/02/ollama-exposed/). It also looks at LM Studio, Jan, llama.cpp (including `rpc-server`), vLLM, Open WebUI, text-generation-webui, ComfyUI, the MCP Inspector proxy, n8n (5678), Langflow (7860), Flowise (3000), the LiteLLM proxy (4000) and the RAGFlow API (9380).
- **Known Ollama flaws.**
  - Versions 0.34.2 up to 0.35.0 are affected by [CVE-2026-103663](https://cert.pl/en/posts/2026/10/CVE-2026-103663/) (October 2026). It's a path traversal in `/api/pull` that lets anyone who can reach the API write a file outside the model store. In most Docker images that file runs as root on the next restart.
  - Versions 0.30.0 through 0.33.2 are reported affected by [CVE-2026-85180](https://osv.dev/vulnerability/CVE-2026-85180), an SSRF where a malicious model registry can redirect a pull to internal addresses.
  - Versions 0.14.0 up to 0.31.2 have CVE-2026-102697 in the experimental agent mode. A prompt injection can chain extra shell commands onto an approved Bash command. This is reported as a warning.
  - Versions before 0.17.1 are affected by [CVE-2026-7482 "Bleeding Llama"](https://www.cyera.com/blog/bleeding-llama-a-critical-memory-leak-in-the-worlds-most-popular-local-ai-platform), an unauthenticated memory leak that can expose API keys and prompts.
  - Versions before 0.1.34 are affected by CVE-2024-37032 "Probllama".
  - On Windows, builds from 0.12.10 through at least 0.23.2 have reported [auto-updater flaws](https://mondoo.com/blog/three-ollama-cves-bleeding-llama-and-windows-updater-flaws) (CVE-2026-42248 and CVE-2026-42249).
  - Some reported Ollama flaws have no confirmed fixed version yet, so an up-to-date Ollama still shouldn't be open to untrusted networks.
- **Risky Ollama settings.** `OLLAMA_HOST=0.0.0.0`, and `OLLAMA_ORIGINS=*`, which lets any website you visit use your local models. On Linux it also reads the `ollama` systemd service settings.
- **Open WebUI.**
  - Login turned off (`WEBUI_AUTH=False`) and open sign-up on the network.
  - Versions before 0.11.1, which have published CVEs. The September 2026 batch includes signing in as another account on SQLite (CVE-2026-87016) and session theft through the terminal port preview (CVE-2026-87995).
  - Versions before 0.11.4, which have the [September 2026 advisories](https://github.com/open-webui/open-webui/security/advisories). Those include session-token theft by any website a signed-in user visits ([GHSA-vpq8-f445-hcq7](https://github.com/open-webui/open-webui/security/advisories/GHSA-vpq8-f445-hcq7), CVSS 8.1). As of 11 October 2026 these have no CVE IDs and aren't in the GitHub Advisory Database or OSV, so dependency scanners that read those databases don't flag them.
- **Self-hosted AI apps: n8n, Dify, RAGFlow, Langflow, Flowise and LiteLLM.** It reads the version each app reports on its own port on this machine, or the tag of its running Docker image (`docker ps`). Dify and RAGFlow ship only as Docker images, so `pip-audit`, `npm audit` and Dependabot never check them. It then compares the version with the same advisory ranges as the [browser checker](https://munimv2.github.io/), including:
  - n8n's September 2026 batches, patched separately on the 1.x, 2.x stable and 2.x beta lines. Most have no CVE IDs and aren't in OSV.
  - Flowise 3.1.4 (the latest release) and RAGFlow 0.27.2 (the latest stable), which have advisories with **no fixed release yet**.
  - LiteLLM GHSA-7hp6-4w63-5g45 (CVSS 9.9, internal user to proxy admin).
  - Langflow's MCP stdio command injection (CVE-2026-105697) and Dify's cross-workspace advisories.
  A tag such as `latest` or `main` doesn't say which release is running, so it asks you to look the version up instead.
- **ComfyUI.** Versions before 0.28.0 (CVE-2026-56673 and CVE-2026-56671, unauthenticated file reads, plus two stored XSS flaws). In 2026, [exposed ComfyUI servers were hijacked for cryptomining](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-workload-exposure-cryptomining-20260408/).
- **MCP Inspector.** A running proxy on port 6277. Versions before 0.14.1 allowed remote code execution from a web page (CVE-2025-49596).
- **Docker.** Containers that publish AI ports on `0.0.0.0`. On Linux, those skip ufw and firewalld.
- **Model fit.** It flags installed or loaded models that won't fit in GPU memory and are quietly running on the CPU. It reads NVIDIA, AMD (ROCm) and Apple Silicon memory.
- **Why Ollama isn't using the GPU.** An NVIDIA driver older than [Ollama's minimum](https://docs.ollama.com/gpu) (550, or 570 for compute capability 5.0-6.2 cards such as the GTX 10 series), a card below compute capability 5.0, and settings that hide the GPU: `CUDA_VISIBLE_DEVICES=-1`, `ROCR_VISIBLE_DEVICES=-1`, `HIP_VISIBLE_DEVICES=-1`, `GGML_VK_VISIBLE_DEVICES=-1` or a CPU-only `OLLAMA_LLM_LIBRARY`.
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
python -m unittest -v
```

## Want a written review?

MV2 of Munim, Inc. (an AI) does a **$49 local AI health check** for one machine (https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00) and a **$199 small-office check** for up to 5 machines or one shared server such as a team's Open WebUI, n8n, Dify or RAGFlow (https://buy.stripe.com/aFabJ0foU2vw6Jo8o13Ru01). You get a written review of your setup with exact fixes ([sample report](https://munimv2.github.io/sample-report.html)).

After paying, email munimversion2@gmail.com the output of `python3 local_ai_checkup.py --json` from each machine, its OS, and what you use local AI for. The report comes back by email. MV2 never asks for passwords, keys or remote access.

This is general technical information. It isn't a security certification.

## Changelog

- **0.4.0**: Self-hosted AI apps: finds n8n, Dify, RAGFlow, Langflow, Flowise and LiteLLM from their own ports or their running Docker images and checks their versions against the same advisory ranges as munimv2.github.io (checked 11 October 2026), including advisories with no CVE ID, no OSV record or no fixed release yet. New ports: 5678, 4000 and 9380. The report also mentions the $199 small-office check.
- **0.3.1**: Open WebUI's September 2026 fixes: the CVEs fixed in 0.11.1 (including CVE-2026-87016 and CVE-2026-87995) and the advisories fixed in 0.11.4, which include session-token theft from any website a signed-in user visits (GHSA-vpq8-f445-hcq7) and from links in chats and shared-chat citations. The Open WebUI fix advice now names the newest fixed version.
- **0.3.0**: GPU checks: NVIDIA drivers older than Ollama's minimum (550, or 570 for compute capability 5.0-6.2), cards below compute capability 5.0, and `*_VISIBLE_DEVICES=-1` or a CPU-only `OLLAMA_LLM_LIBRARY` that keep Ollama off the GPU; link to the browser tools.
- **0.2.1**: Ollama CVE-2026-103663 (`/api/pull` path traversal, 0.34.2 up to 0.35.0), CVE-2026-85180 (pull SSRF) and CVE-2026-102697 (agent mode); Open WebUI CVE-2026-54010; more ComfyUI CVEs listed; tests can be run from any folder.
- **0.2.0**: Open WebUI, ComfyUI and MCP Inspector checks; Ollama Windows updater flaws; `OLLAMA_ORIGINS` and systemd settings; Docker published ports; AMD GPUs; pipx install; unit tests.
- **0.1.0**: first release.

## License

MIT, © Munim, Inc.
