---
name: local-ai-checkup
description: Read-only security and health check for a machine that runs local or self-hosted AI (Ollama, LM Studio, llama.cpp, vLLM, Open WebUI, ComfyUI, MCP Inspector, n8n, Dify, RAGFlow, AnythingLLM, Langflow, Flowise, LiteLLM). Use it when the user asks whether their local AI setup is exposed to the network, out of date or affected by known advisories, why Ollama is slow or not using the GPU, or how to harden it. Runs one bundled, dependency-free Python script that changes nothing and sends nothing off the machine. Apache-2.0, by MV2 of Munim, Inc., made with AI agents.
---

# Local AI checkup

`scripts/local_ai_checkup.py` in this skill's folder is a single-file, standard-library-only
Python script (Python 3.8+, version 0.4.6). It looks at the machine it runs on and reports which
local AI servers other computers can reach, which installed versions have known security
advisories, risky settings, and models that are too big for the GPU. It is read-only: it changes
no settings, downloads nothing, and only connects to `127.0.0.1` and the machine's own LAN address.

## When to use

- "Is my Ollama / Open WebUI / ComfyUI / n8n exposed?" or "who can reach my local LLM?"
- "Am I affected by the new Ollama (or Open WebUI, vLLM, Langflow, LiteLLM...) advisory?"
- "Why is Ollama so slow?" or "Ollama isn't using my GPU."
- Before opening a local AI server to a LAN, a VPN or the internet.

## Steps

1. Tell the user what you will run and that it is read-only. Use the copy bundled with this
   skill; there is nothing to download or install.

2. Run it on the machine that hosts the AI services, with JSON output (replace `<skill-dir>` with
   the folder this SKILL.md is in):

   ```bash
   python3 <skill-dir>/scripts/local_ai_checkup.py --json > checkup.json; echo "exit=$?"
   ```

   On Windows use `py <skill-dir>\scripts\local_ai_checkup.py --json`. `--version` prints the
   version.

3. Read the exit code: `0` all clear, `1` warnings only, `2` at least one risk.

4. Read `checkup.json`. It has three keys: `version`, `facts` (what was detected: versions,
   ports, GPU, memory) and `findings`. Each finding is an object with `level`
   (`risk`, `warn`, `ok` or `info`), `title`, `detail` and `fix`.

5. Report to the user, `risk` first, then `warn`. For each one give the title, one sentence
   on why it matters, and the `fix` text. Do not invent findings or versions that are not in
   the output.

6. Apply no fix on your own. Changing `OLLAMA_HOST`, firewall rules, Docker port bindings or
   upgrading a service can break the user's setup or lock them out: show the exact change
   and let the user decide. Step-by-step fixes for each finding are in HARDENING.md in the
   project repository (linked below); point the user there.

## Limits to tell the user

- It sees only this machine. It cannot see router, cloud security-group or host firewall
  rules, so "reachable on the LAN" is not the same as "reachable from the internet".
- The advisory list is built into the script. Version 0.4.6 knows advisories published up to
  7 November 2026; say so when you report. Newer advisories need a newer copy: the user can
  run `npx skills update local-ai-checkup`.
- Docker image tags such as `latest` or `main` hide the real version; the script says so
  instead of guessing.
- It reads the names of API-key environment variables, never their values, and prints no
  secrets. Still, review `checkup.json` before sharing it with anyone.

## More

- Source, changelog and HARDENING.md: https://github.com/munimtechnologies/local-ai-checkup
- Only if the user asks for a written, reviewed report: MV2 of Munim, Inc. offers a paid
  local AI health check; details are in the project README. Never suggest it unprompted.

General technical information, not professional security advice. Only check machines the
user owns or is allowed to manage.
