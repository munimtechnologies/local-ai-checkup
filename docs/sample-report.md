# Sample report: local AI health check

This is a real example. The machine is MV2's own Windows desktop, checked with [local-ai-checkup](https://github.com/munimtechnologies/local-ai-checkup) 0.2.1 on 10 October 2026. A paid report follows this layout, written for your machine, your OS and what you told MV2 you use local AI for.

## Your setup

| | |
|---|---|
| **System** | Windows 10, 15.9 GB RAM |
| **GPU** | NVIDIA GeForce GTX 1050, 4 GB VRAM |
| **Ollama** | 0.32.4, 8 models installed, listening on 127.0.0.1 only |
| **Stated use** | Coding help and summarising documents (example) |

## Summary: fix these first

1. **Update Ollama** (risk). 0.32.4 is in the reported range of CVE-2026-85180.
2. **Use models that fit in 4 GB** (speed). Anything larger runs partly on the CPU.
3. **Keep the API on localhost** (already good). Don't change `OLLAMA_HOST` without adding authentication.

## 1. Security

### Risk: Ollama 0.32.4 has a known flaw

[CVE-2026-85180](https://osv.dev/vulnerability/CVE-2026-85180) was reported for Ollama 0.30.0 to 0.33.2. A malicious model registry can redirect a model pull to internal network addresses (SSRF). Because your Ollama only listens on 127.0.0.1, an attacker would need you to pull a model from a registry they control, so the practical risk is low. Sources disagree on the exact fixed version, so update to the latest release instead of picking a minimum version. That also puts you past [CVE-2026-103663](https://cert.pl/en/posts/2026/10/CVE-2026-103663/) (0.34.2 up to 0.35.0), which you'd otherwise hit on the way up.

```
# Windows: download and run the current installer
https://ollama.com/download
# then confirm
ollama --version
```

Pull models only from `ollama.com/library` or publishers you trust.

### OK: nothing is exposed to your network

Ollama answers only on 127.0.0.1:11434, and no other local AI ports are open. If you later want to use it from another device, don't set `OLLAMA_HOST=0.0.0.0` on its own. Put an authenticating reverse proxy in front and allow the port only from your own devices in Windows Defender Firewall. Steps: [HARDENING.md](../HARDENING.md).

## 2. Speed

A GTX 1050 has 4 GB of VRAM. After the desktop and the driver take their share, about 3.5 GB is left for a model and its context. Whatever doesn't fit runs on the CPU, which is usually several times slower.

| Model size | Q4_K_M at 4k context | On this GPU |
|---|---|---|
| 1-2B | about 1.5-2.2 GB | Fits fully, fast |
| 3-4B | about 2.8-3.4 GB | Fits, but tight at 4k context |
| 7-8B | about 5-6 GB | About 60% on the GPU, noticeably slower |
| 14B and up | 9 GB and more | Mostly CPU, slow |

For coding help and summarising on this card, use a 3-4B model at Q4_K_M for everyday work (for example `qwen3:4b`, 2.5 GB), and a 7-8B model when quality matters more than speed. Check the split with:

```
ollama ps
# PROCESSOR should read "100% GPU"; a CPU/GPU split means it didn't fit
```

If a 3-4B model shows a split, lower the context length. In an interactive session, `/set parameter num_ctx 2048` does it. Close other GPU-heavy apps such as games and browsers with many video tabs.

## 3. Housekeeping

- Remove models you no longer use (`ollama rm <name>`) to free disk space. Eight models can easily take 30 GB or more.
- Re-run `python local_ai_checkup.py` after updating. You should see 0 risks.

## Follow-up

Each check includes one follow-up. After you've made the changes, email the new `--json` output and MV2 confirms what's fixed and what's left.

## Get one for your setup

- **$49, one machine:** [pay on Stripe](https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00).
- **$199, small office:** up to 5 machines, or one shared server such as Open WebUI, Ollama or n8n used by a team. One report covers them all, with the shared server's exposure and access settings first. [Pay on Stripe](https://buy.stripe.com/aFabJ0foU2vw6Jo8o13Ru01).

1. Pay for the tier you need.
2. Email munimversion2@gmail.com the output of `python3 local_ai_checkup.py --json` from each machine, its OS, and what you use local AI for.
3. Your report comes back by email, within 48 hours of receiving everything.

MV2 never asks for passwords, keys or remote access, and never connects to your machine. The script is read-only and sends nothing anywhere. You choose what to email.

---

Made by MV2 of Munim, Inc., with AI agents. This is general technical guidance, not a security certification or professional advice. Text licensed CC BY 4.0.
