# Hardening a local AI setup

This guide gives fixes for each thing `local_ai_checkup.py` reports. It's written by MV2 of Munim, Inc., with AI agents. It's general technical information, not a security certification. Check each command against your own setup before you run it.

The short version:

1. Bind every AI server to `127.0.0.1` unless another machine really needs it.
2. If another machine needs it, use a VPN (Tailscale, WireGuard) or an authenticating reverse proxy. Don't use a bare open port.
3. Stay on current versions.
4. If something old was ever exposed, rotate the secrets it could see.

## Ollama

Ollama binds `127.0.0.1:11434` by default. It's only exposed if `OLLAMA_HOST` was changed (for example to `0.0.0.0`) or a container publishes the port.

**Put it back on localhost.**

- **Linux (systemd service).** Run `sudo systemctl edit ollama.service` and add:

  ```
  [Service]
  Environment="OLLAMA_HOST=127.0.0.1:11434"
  ```

  Then run `sudo systemctl daemon-reload && sudo systemctl restart ollama`. To check, run `ss -tlnp | grep 11434`. It should show `127.0.0.1:11434`, not `0.0.0.0:11434` or `*:11434`.
- **macOS (app).** Run `launchctl unsetenv OLLAMA_HOST`, or `launchctl setenv OLLAMA_HOST 127.0.0.1`, then quit and restart the Ollama app. To check, run `lsof -nP -iTCP:11434 -sTCP:LISTEN`.
- **Windows.** Quit Ollama from the tray. Open *Settings > System > About > Advanced system settings > Environment Variables*, or search for "Edit environment variables for your account". Remove `OLLAMA_HOST` or set it to `127.0.0.1`, then start Ollama again. To check, run `netstat -ano | findstr :11434`. It should show `127.0.0.1:11434 ... LISTENING`.
- **Docker.** Publish on localhost only: `docker run -d -p 127.0.0.1:11434:11434 -v ollama:/root/.ollama --name ollama ollama/ollama`. In compose, use `ports: ["127.0.0.1:11434:11434"]`. If Open WebUI runs in the same compose file, it can reach Ollama over the compose network at `http://ollama:11434`, and then you don't need to publish 11434 at all.

**Remove `OLLAMA_ORIGINS=*`.** A wildcard lets any web page you open call your local Ollama from your browser. List only what you use, for example `OLLAMA_ORIGINS=chrome-extension://<your-extension-id>`.

**If you need remote access**, a VPN is simplest. If it has to be over HTTP, put an authenticating proxy in front and keep Ollama itself on localhost. Here's a Caddy example. Make the hash with `caddy hash-password`:

```
ollama.example.com {
    basic_auth {
        alice <paste-hash-here>
    }
    reverse_proxy 127.0.0.1:11434 {
        header_up Host localhost:11434
    }
}
```

The `Host` rewrite matches Ollama's own nginx example (`proxy_set_header Host localhost:11434;`).

**Update.**

- **0.34.2 up to 0.35.0:** CVE-2026-103663 ([CERT Polska, 8 October 2026](https://cert.pl/en/posts/2026/10/CVE-2026-103663/)). A crafted `/api/pull` can write a file outside the model store. In most Docker images the server can write to `/usr/lib/ollama`, so the file can run as root on the next restart. Update to 0.35.0 or newer.
- **0.30.0 through 0.33.2:** CVE-2026-85180. A malicious registry can redirect a model pull to internal addresses, such as a cloud metadata endpoint. Pull only from registries you trust. On cloud VMs, block the server's access to the metadata address.
- **0.14.0 up to 0.31.2:** CVE-2026-102697, in the experimental agent mode. A prompt injection can chain extra shell commands onto a Bash command you approved. Don't approve agent commands while the model reads untrusted content.
- **Before 0.17.1:** CVE-2026-7482, "Bleeding Llama", an unauthenticated memory leak.
- **Windows, 0.12.10 through at least 0.23.2:** auto-updater flaws (CVE-2026-42248 and CVE-2026-42249). On an old Windows build, turn off *Auto-download updates* in Ollama's settings until you've updated, and don't update over public Wi-Fi.

Install the current release from https://ollama.com/download. With Docker, run `docker pull ollama/ollama` and recreate the container. Your models live in the volume, so they're kept.

**If 0.34.2-0.34.x was ever reachable from outside**, don't just update. Look for files you didn't put there:

- in the model store (`~/.ollama/models`, or `/root/.ollama/models` in Docker)
- in the library directory (`/usr/lib/ollama`)

The safest fix for a container is to recreate it from a fresh image.

**If an old version was ever reachable from outside**, rotate every API key or token that was in Ollama's environment or that went through it in prompts.

## Firewall

A firewall is a second layer. It doesn't replace binding to localhost.

- **Linux (ufw):** `sudo ufw deny 11434/tcp`. Ports that Docker publishes skip ufw and firewalld, so fix the `-p` flag instead.
- **Windows (PowerShell as admin):** `New-NetFirewallRule -DisplayName "Block Ollama inbound" -Direction Inbound -LocalPort 11434 -Protocol TCP -Action Block`
- **macOS:** turn on *System Settings > Network > Firewall*. Note that it filters apps, not ports.

## Open WebUI

- Keep the login on. `WEBUI_AUTH=False` makes every visitor an admin. Use it only for a single-user setup bound to `127.0.0.1`.
- Once your users have accounts, turn off sign-up in *Admin Settings > General*.
- Update to 0.11.4 or newer; the latest release is best. Older versions have published CVEs and advisories: stored XSS, cross-user chat access, request forgery, and users reading other users' files. Versions before 0.11.1 also allow signing in as another account through OAuth/SCIM lookups on SQLite (CVE-2026-87016) and session theft through the terminal port preview (CVE-2026-87995). Versions before 0.11.4 also let session tokens be stolen:
  - From 0.7.0, any website a signed-in user visits could take their token through the community-sharing message handler ([GHSA-vpq8-f445-hcq7](https://github.com/open-webui/open-webui/security/advisories/GHSA-vpq8-f445-hcq7), CVSS 8.1).
  - In any version, a `javascript:` link in a chat or in a shared chat's citation could do the same.

  The 0.11.4 advisories have no CVE IDs and, as of 11 October 2026, aren't in the GitHub Advisory Database or OSV, so a dependency scanner may report an older Open WebUI as clean. Check the version yourself under *Settings > About*.

  With Docker, run `docker pull ghcr.io/open-webui/open-webui:main` and then recreate the container. Your data lives in the volume, so it's kept.
- Can't update yet? Set `ENABLE_COMMUNITY_SHARING=False`. The advisory says deployments with community sharing off aren't affected by GHSA-vpq8-f445-hcq7. After updating, sign everyone out (0.12.0 adds *sign out all devices* in the user edit dialog) so any stolen token stops working.
- Publish it on localhost (`-p 127.0.0.1:3000:8080`), or put a VPN or proxy in front of it.

## ComfyUI

- ComfyUI listens on `127.0.0.1:8188` unless you start it with `--listen`. Don't use `--listen` on a machine with a public IP unless a proxy with authentication sits in front.
- Update ComfyUI to 0.28.0 or newer and ComfyUI-Manager to 3.38 or newer. 0.28.0 fixes CVE-2026-56673 and CVE-2026-56671 (unauthenticated file reads) and two stored XSS flaws. In 2026, exposed instances were hijacked for crypto-mining through custom nodes and an old Manager flaw.
- Custom nodes are code. Install only ones you trust.

## LM Studio, Jan, llama.cpp, vLLM

- **LM Studio:** leave *Serve on Local Network* off unless you need it.
- **llama.cpp `llama-server`:** it binds `127.0.0.1` by default. If you pass `--host 0.0.0.0`, also set `--api-key`. Never expose `rpc-server`, which has no authentication.
- **vLLM:** pass `--host 127.0.0.1`, and use `--api-key` whenever it's reachable from other machines.

## MCP Inspector

Port 6277 is the MCP Inspector proxy. Versions before 0.14.1 let any web page you visited run commands on your machine (CVE-2025-49596). Use `npx @modelcontextprotocol/inspector@latest` and stop it when you're done.

## Speed: models that don't fit

If a model is larger than about 90% of your VRAM, part of it runs on the CPU and gets several times slower. `ollama ps` shows the split. To fix it, pick a smaller quantization (Q4_K_M is a good default), pick a smaller model, or lower the context length (`num_ctx`), since long contexts need memory on top of the weights. To estimate fit before you download, use the [model fit calculator](https://munimv2.github.io/fit.html).

## Speed: Ollama not using the GPU at all

If `ollama ps` shows `100% CPU` for a small model, Ollama didn't find or couldn't use the GPU. The requirements below are from [Ollama's GPU docs](https://docs.ollama.com/gpu).

- **NVIDIA driver too old.** Ollama needs driver 550 or newer, and 570 or newer for cards with compute capability 5.0-6.2 (for example the GTX 10 series). Check with `nvidia-smi` and `nvidia-smi --query-gpu=compute_cap --format=csv`. Install the current driver from https://www.nvidia.com/drivers and restart Ollama.
- **Card too old.** Compute capability below 5.0 isn't supported, and Ollama will use the CPU.
- **A setting hides the GPU.** `CUDA_VISIBLE_DEVICES=-1`, `ROCR_VISIBLE_DEVICES=-1`, `HIP_VISIBLE_DEVICES=-1` or `GGML_VK_VISIBLE_DEVICES=-1` force CPU use, and so does a CPU-only `OLLAMA_LLM_LIBRARY` such as `cpu_avx2`. Remove it or set your GPU's UUID (`nvidia-smi -L`), then restart Ollama.
- **Docker.** Run the container with `--gpus all` and install the NVIDIA Container Toolkit. `docker run --gpus all ubuntu nvidia-smi` must work, or Ollama can't see the GPU.
- **Linux after suspend.** Ollama can fall back to the CPU after a resume. Reload the driver with `sudo rmmod nvidia_uvm && sudo modprobe nvidia_uvm`.
- **AMD.** Ollama needs the ROCm v7 driver. On Linux, some unsupported cards work with `HSA_OVERRIDE_GFX_VERSION` (for example `10.3.0` for an RX 5400).
- **Still stuck?** The server log says what it found at startup. It's at `%LOCALAPPDATA%\Ollama\server.log` on Windows and `~/.ollama/logs/server.log` on macOS. On Linux, run `journalctl -u ollama --no-pager`.

A step-by-step version is at [munimv2.github.io/ollama-gpu.html](https://munimv2.github.io/ollama-gpu.html).

---

For a written review of your own setup, MV2 of Munim, Inc. does a $49 local AI health check: https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00
