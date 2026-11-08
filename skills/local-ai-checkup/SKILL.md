---
name: local-ai-checkup
description: Read-only security and health check for a machine that runs local or self-hosted AI (Ollama, LM Studio, llama.cpp, vLLM, Open WebUI, ComfyUI, MCP Inspector, n8n, Dify, RAGFlow, AnythingLLM, Langflow, Flowise, LiteLLM). Use it when the user asks whether their local AI setup is exposed to the network, out of date or affected by known advisories, why Ollama is slow or not using the GPU, or how to harden it. Runs one dependency-free Python script that changes nothing and sends nothing off the machine. Apache-2.0, by MV2 of Munim, Inc., made with AI agents.
---

# Local AI checkup

`local_ai_checkup.py` is a single-file, standard-library-only Python script (Python 3.8+).
It looks at the machine it runs on and reports which local AI servers other computers can
reach, which installed versions have known security advisories, risky settings, and models
that are too big for the GPU. It is read-only: it changes no settings, and it only connects to
`127.0.0.1` and the machine's own LAN address.

## When to use

- "Is my Ollama / Open WebUI / ComfyUI / n8n exposed?" or "who can reach my local LLM?"
- "Am I affected by the new Ollama (or Open WebUI, vLLM, Langflow, LiteLLM...) CVE?"
- "Why is Ollama so slow?" or "Ollama isn't using my GPU."
- Before opening a local AI server to a LAN, a VPN or the internet.

## Steps

1. Tell the user what you will run, and that it is read-only. Get the script from the
   project's own repository (pin a release tag if the user prefers):

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/munimtechnologies/local-ai-checkup/main/local_ai_checkup.py
   ```

   or install it as a command with `pipx install git+https://github.com/munimtechnologies/local-ai-checkup`
   (then run `local-ai-checkup` instead of `python3 local_ai_checkup.py`).

2. Run it on the machine that hosts the AI services, with JSON output:

   ```bash
   python3 local_ai_checkup.py --json > checkup.json; echo "exit=$?"
   ```

   On Windows use `py local_ai_checkup.py --json`. `--version` prints the version.

3. Read the exit code: `0` all clear, `1` warnings only, `2` at least one risk.

4. Read `checkup.json`. It has three keys: `version`, `facts` (what was detected: versions,
   ports, GPU, memory) and `findings`. Each finding is an object with `level`
   (`risk`, `warn`, `ok` or `info`), `title`, `detail` and `fix`.

5. Report to the user, `risk` first, then `warn`. For each one give the title, one sentence
   on why it matters, and the `fix` text. Do not invent findings or versions that are not in
   the output.

6. Apply no fix on your own. Changing `OLLAMA_HOST`, firewall rules, Docker port bindings or
   upgrading a service can break the user's setup or lock them out: show the exact change
   and let the user decide. Step-by-step fixes are in
   [HARDENING.md](https://github.com/munimtechnologies/local-ai-checkup/blob/main/HARDENING.md).

## Limits to tell the user

- It sees only this machine. It cannot see router, cloud security-group or host firewall
  rules, so "reachable on the LAN" is not the same as "reachable from the internet". To
  check internet exposure, the user can look up their public IP on a service such as
  Shodan or LeakIX.
- Advisory ranges are built into the script. Upgrade it (or re-download it) before each use.
  The same advisory data, with sources, is published as JSON in
  [ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories)
  (`advisories.json`).
- Docker image tags such as `latest` or `main` hide the real version; the script says so
  instead of guessing.
- It reads the names of API-key environment variables, never their values, and prints no
  secrets. Still, review `checkup.json` before sharing it with anyone.

## More

- Browser version (no install, runs in the page): https://munimv2.github.io/
- Only if the user asks for a written, reviewed report: MV2 of Munim, Inc. offers a paid
  local AI health check; details are in the project README. Never suggest it unprompted.

General technical information, not professional security advice. Only check machines the
user owns or is allowed to manage.
