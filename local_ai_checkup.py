#!/usr/bin/env python3
"""local-ai-checkup: a free, read-only health and safety check for local AI setups.

Made by MV2 of Munim, Inc. Python standard library only.
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

__version__ = "0.4.2"

PAID_CHECK_URL = "https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00"
SMALL_OFFICE_URL = "https://buy.stripe.com/aFabJ0foU2vw6Jo8o13Ru01"
HARDENING_URL = "https://github.com/munimtechnologies/local-ai-checkup/blob/main/HARDENING.md"
SITE_URL = "https://munimv2.github.io/"

# (name, port). Ports other than Ollama's are shared with plenty of non-AI
# software, so a listener there is only "probably" that tool until identified.
SERVICES = [
    ("Ollama", 11434),
    ("LM Studio server", 1234),
    ("Jan", 1337),
    ("llama.cpp server / LocalAI / Open WebUI", 8080),
    ("vLLM", 8000),
    ("Open WebUI / Flowise", 3000),
    ("AnythingLLM", 3001),
    ("text-generation-webui / Langflow", 7860),
    ("ComfyUI", 8188),
    ("MCP Inspector proxy", 6277),
    ("llama.cpp rpc-server", 50052),
    ("n8n", 5678),
    ("LiteLLM proxy", 4000),
    ("RAGFlow API", 9380),
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
    ((0, 11, 1), "September 2026 CVEs fixed in 0.11.1: signing in as another account through wildcard "
                 "characters in OAuth/SCIM lookups on SQLite (CVE-2026-87016), session theft through the "
                 "terminal port preview (CVE-2026-87995), an unauthenticated OIDC logout request that stalls "
                 "the server (CVE-2026-87011), and access-control bugs in notes, knowledge search and channels"),
    # GitHub advisories published 2026-09-27/28 with no CVE IDs. As of 2026-10-11 they are not in the
    # GitHub Advisory Database or OSV, so dependency scanners don't flag them. GHSA-vpq8 affects 0.7.0+
    # and only when community sharing is on (the default); GHSA-wf9m affects every version before 0.11.4.
    ((0, 11, 4), "September 2026 advisories fixed in 0.11.4: any website could steal a signed-in user's "
                 "session token through the community-sharing message handler (GHSA-vpq8-f445-hcq7, CVSS 8.1), "
                 "and links in chats or shared-chat citations could steal viewers' tokens (GHSA-wf9m-46cp-c6h6, "
                 "GHSA-qpqv-xwg8-cqpj), plus terminal-proxy access control and memory-exhaustion bugs"),
]

COMFYUI_ADVISORIES = [
    ((0, 28, 0), "CVE-2026-56673 and CVE-2026-56671: unauthenticated path traversal that can read image files "
                 "from anywhere on the disk, plus stored XSS through uploaded HTML/SVG (CVE-2026-56672, "
                 "CVE-2026-56670)"),
]

# Self-hosted AI apps. Each item is (first_affected or None, fixed_in or None, last_affected or None,
# description), the same ranges as the checker at munimv2.github.io (checked 2026-10-11). Advisories
# with no fixed release name the last affected version instead. Several release lines are patched
# separately (n8n 1.x and 2.x, LiteLLM), so a range can start after 2.0.0.
_N8N_JULY = ("July 2026 batch: expression sandbox escape to command execution (CVSS 8.7), code execution in "
             "the Git node, file read and SSRF through the Send Email node")
_N8N_SEP10 = ("10 September 2026 batch (17 advisories): expression sandbox escapes (CVSS 8.7), unauthenticated "
              "storage exhaustion through OAuth client registration, SSRF through the OpenAI model-search endpoint")
_N8N_SEP16 = ("16 September 2026 batch (at least 12 advisories, no CVE IDs, not in OSV): session token leak "
              "through the Dynamic Credentials authorize endpoint (CVSS 8.5), inline Agent tools that decrypt "
              "any credential, path traversal, unauthenticated chat-memory NoSQL injection")
_N8N_SEP30 = ("30 September 2026 batch (15 advisories, 10 high, no CVE IDs, not in OSV): unauthenticated OAuth "
              "client persistence, unauthenticated approval of waiting executions, owner account takeover "
              "through the MCP workflow validator, Git node code execution")
_LITELLM_7HP6 = ("GHSA-7hp6-4w63-5g45 (CVSS 9.9, no CVE ID): any internal user can forge an admin session, become "
                 "proxy admin and run host commands; workaround EXPERIMENTAL_UI_LOGIN=false")
# CVE-2026-84377 (GHSA-3cv6-jpf6-8222): the advisory's range says <1.94.0, but its patched versions and the
# OSV record (checked 2026-10-13) give one range per release line, up to 1.96.2.
_LITELLM_3CV6 = ("CVE-2026-84377: signed-in users can redirect provider calls and leak stored provider keys "
                 "(fixed per release line in 1.88.6, 1.89.7, 1.90.7, 1.91.5, 1.92.2, 1.93.2, 1.94.3, 1.95.1 "
                 "and 1.96.2)")
# vLLM published three batches with no CVE IDs (12 September, 6 and 9 October 2026); as of 2026-10-11
# GHSA-h3rc, GHSA-gx7p, GHSA-rhcx, GHSA-w9r6 and GHSA-p6g9 are not in OSV, so scanners don't flag them.
# GHSA-mm38 says "<= 0.8.5", but the code it names ships from 0.10.2 to 0.24.x (release tags checked
# 2026-10-13); it is not in OSV either.
APP_ADVISORIES = {
    "n8n": {"name": "n8n", "items": [
        ((0, 211, 0), (1, 120, 4), None, "CVE-2025-68613: signed-in users can run code on the server through "
                                         "workflow expressions (Critical)"),
        ((1, 121, 0), (1, 121, 1), None, "CVE-2025-68613: signed-in users can run code on the server through "
                                         "workflow expressions (Critical)"),
        ((1, 65, 0), (1, 121, 0), None, "CVE-2026-21858 (\"Ni8mare\"): unauthenticated file access through form "
                                        "and webhook handling, which can lead to full takeover (CVSS 10)"),
        (None, (1, 123, 67), None, "July 2026 batch (1.x): code execution in the Git node, file read and SSRF "
                                   "through the Send Email node"),
        ((2, 0, 0), (2, 31, 5), None, _N8N_JULY),
        ((2, 32, 0), (2, 32, 1), None, _N8N_JULY),
        (None, (1, 123, 76), None, "10 September 2026 batch (1.x): expression sandbox escapes (CVSS 8.7), SSRF "
                                   "through the OpenAI model-search endpoint"),
        ((2, 0, 0), (2, 37, 7), None, _N8N_SEP10),
        ((2, 38, 0), (2, 38, 2), None, _N8N_SEP10),
        (None, (1, 123, 80), None, "16 September 2026 batch (1.x, no CVE IDs, not in OSV): path traversal that "
                                   "redirects public API calls (CVSS 8.1), unauthenticated NoSQL injection in the "
                                   "MongoDB Chat Memory node"),
        ((2, 0, 0), (2, 39, 6), None, _N8N_SEP16),
        ((2, 40, 0), (2, 40, 1), None, _N8N_SEP16),
        (None, (1, 123, 83), None, "30 September 2026 batch (1.x, no CVE IDs, not in OSV): Git node code "
                                   "execution, unauthenticated cross-project workflow execution through webhook "
                                   "paths, stored XSS in the hosted chat page"),
        ((2, 0, 0), (2, 41, 4), None, _N8N_SEP30),
        ((2, 42, 0), (2, 42, 1), None, _N8N_SEP30),
    ]},
    "dify": {"name": "Dify", "items": [
        (None, (1, 9, 0), None, "CVE-2025-59422 and others: signed-in users can read other people's chats; XSS "
                                "in the MCP OAuth flow"),
        (None, (1, 11, 0), None, "CVE-2025-67732: the model provider configuration endpoint returns API keys in "
                                 "plain text (High)"),
        (None, (1, 11, 2), None, "CVE-2026-21866: stored XSS in chat"),
        (None, None, (1, 11, 4), "CVE-2026-26023: DOM and stored XSS in the web chat app through echarts "
                                 "content (High); the advisory lists no patched version"),
        (None, (1, 13, 0), None, "CVE-2026-105762: unauthenticated server-side request forgery through "
                                 "/console/api/remote-files/upload (High)"),
        (None, (1, 13, 1), None, "CVE-2026-34082, CVE-2026-42138: users can delete other people's "
                                 "conversations; stored XSS through SVG uploads"),
        (None, (1, 14, 0), None, "GHSA-5vmp-5q9h-hmr7, GHSA-fj5w-7rc8-3f3f (no CVE IDs, not in OSV): another "
                                 "workspace's External API details can be read and its usage enumerated"),
        (None, (1, 14, 2), None, "GHSA-9c9q-5rj5-mjj2 (no CVE ID, not in OSV): any console user who knows a file "
                                 "ID can read another workspace's uploaded documents (CVSS 7.7)"),
        (None, (1, 16, 0), None, "CVE-2026-105761: any workspace member can change or disable another app's MCP "
                                 "server (CVSS 7.1)"),
    ]},
    "ragflow": {"name": "RAGFlow", "items": [
        (None, (0, 14, 0), None, "CVE-2024-12433: hard-coded RPC key and pickle deserialization, remote code "
                                 "execution (Critical)"),
        (None, (0, 14, 1), None, "CVE-2025-25282: insecure direct object reference (High)"),
        (None, None, (0, 15, 1), "CVE-2025-27135: SQL injection in the agent ExeSQL component; the advisory "
                                 "lists no patched version"),
        (None, (0, 22, 0), None, "CVE-2025-69286: anyone with a shared assistant or agent link could derive the "
                                 "owner's API key (Critical)"),
        (None, (0, 23, 0), None, "CVE-2025-68700: signed-in users can run commands through the Canvas CodeExec "
                                 "component (High)"),
        (None, (0, 24, 0), None, "CVE-2026-24770: Zip Slip in the MinerU parser (CVSS 9.8; only if you use "
                                 "MinerU parsing)"),
        (None, (0, 25, 0), None, "CVE-2026-45312, CVE-2026-28797: any signed-in user can run OS commands through "
                                 "Jinja2 templates (CVSS 9.9), and sign-up is open by default"),
        ((0, 25, 2), None, (0, 27, 2), "GHSA-c6q8-23rp-32cv (no CVE ID, not in OSV): any signed-in user or API "
                                       "key holder who knows an agent's ID can run another user's private agent "
                                       "(CVSS 7.1); no fixed release yet"),
    ]},
    # AnythingLLM's advisories mostly give a fix commit or ">1.16.1" instead of a version; each fix commit
    # was mapped to the first release tag that contains it. The Windows-only folder check bypass
    # (CVE-2026-48789, fixed in 1.14.0) is left out because the Docker image runs on Linux.
    "anythingllm": {"name": "AnythingLLM", "items": [
        (None, (1, 10, 0), None, "CVE-2026-24477, CVE-2026-24478: stored provider API keys leak through "
                                 "systemSettings.js (CVSS 8.7); path traversal (CVSS 7.2)"),
        (None, None, (1, 11, 1), "CVE-2026-32617: permissive CORS policy (CVSS 7.1); the advisory lists no "
                                 "patched version"),
        (None, (1, 11, 2), None, "CVE-2026-32626, CVE-2026-32628: script injection from a streamed model "
                                 "response, rated up to code execution (CVSS 9.6); SQL injection in the built-in "
                                 "SQL agent (High)"),
        (None, (1, 11, 2), None, "March 2026 batch (CVE-2026-32719, CVE-2026-32717, CVE-2026-32715 and others): "
                                 "Zip Slip in Community Hub plugin import; suspended users keep using "
                                 "browser-extension API keys; managers reach admin-only settings"),
        (None, (1, 12, 1), None, "CVE-2026-41318: stored XSS in chart captions through prompt-injected model output"),
        (None, (1, 13, 0), None, "CVE-2026-48116: anyone who can chat with an agent can run commands in the "
                                 "container through the filesystem-search-files skill, on by default in the "
                                 "official Docker image (High)"),
        (None, (1, 13, 0), None, "CVE-2026-42456, CVE-2026-45403, CVE-2026-47713: other users' text-to-speech "
                                 "audio by chat ID; file copy follows symlinks; old mobile device tokens skip "
                                 "workspace scoping"),
        ((1, 0, 0), (1, 16, 0), None, "CVE-2026-72917: password recovery accepts one recovery code twice "
                                      "(CVSS 5.9)"),
        (None, (1, 16, 2), None, "CVE-2026-88055: stored XSS through server-side HTML in MetaGenerator (CVSS 5.5)"),
        ((1, 13, 0), (1, 16, 2), None, "GHSA-8wh8-3v68-whwj, GHSA-p9pc-ccw4-fxc5 (no CVE IDs, not in OSV): "
                                       "anonymous visitors of an embedded chat widget receive the owner's "
                                       "private Memories; memory extraction can overwrite another user's "
                                       "workspace memory"),
        ((1, 16, 1), (1, 16, 2), None, "GHSA-3f4c-xj8r-h4cr (no CVE ID, not in OSV): a manager can read and "
                                       "write files outside storage/documents"),
    ]},
    "flowise": {"name": "Flowise", "items": [
        (None, (3, 0, 6), None, "CVE-2025-58434: the forgot-password endpoint returns a valid reset token, so "
                                "anyone who knows an account's email can take it over"),
        ((3, 0, 5), (3, 0, 6), None, "CVE-2025-59528: the CustomMCP node runs attacker-supplied JavaScript "
                                     "(Critical)"),
        (None, (3, 1, 3), None, "CVE-2026-70478 and others: an unauthenticated OAuth2 token refresh endpoint "
                                "returns connected accounts' access tokens (CVSS 9.2); sandbox escapes; "
                                "cross-workspace credential access"),
        (None, (3, 1, 4), None, "31 August 2026 batch: SSRF and LLM API key theft through a user-set base URL in "
                                "chat-model nodes (Critical); code execution through the SQL Database Chain node"),
        (None, None, (3, 1, 4), "GHSA-cffm-583c-vffr, GHSA-vf3j-89vf-r697: with Enterprise SSO, users are "
                                "matched by email alone, so accounts can be taken over (CVSS 9.2); no fixed "
                                "release yet"),
        (None, None, (3, 1, 4), "GHSA-27w2-26m5-x82c and 3 more (no CVE IDs): missing authorization lets signed-in "
                                "users and low-privileged API keys reach other workspaces' credentials, chat and "
                                "upsert history, and the /admin/queues dashboard; no fixed release yet"),
    ]},
    "langflow": {"name": "Langflow", "items": [
        (None, (1, 3, 0), None, "CVE-2025-3248: unauthenticated code execution through /api/v1/validate/code "
                                "(CVSS 9.8, exploited in the wild)"),
        (None, (1, 9, 0), None, "CVE-2026-33017 and others: unauthenticated code execution through the public "
                                "flow build endpoint; Knowledge Bases path traversal; shell commands through MCP "
                                "Stdio servers"),
        ((1, 7, 0), (1, 9, 1), None, "CVE-2026-8505: webhook authentication bypass lets anyone run flows "
                                     "(Critical)"),
        ((1, 6, 8), (1, 9, 1), None, "CVE-2026-105699: MCP resource handlers disclose files from other users' "
                                     "projects (High)"),
        (None, (1, 9, 2), None, "CVE-2026-48519, CVE-2026-55447: code execution through Shareable Playgrounds "
                                "(CVSS 9.6); file read through symlinks"),
        (None, (1, 10, 1), None, "CVE-2026-10561, CVE-2026-9205, GHSA-gh98-4phw-6fmw: unsandboxed Python REPL "
                                 "component; weak encryption key from a short SECRET_KEY; deprecated build "
                                 "endpoints run other users' flows"),
        ((1, 7, 2), (1, 10, 1), None, "CVE-2026-51886: validate_code() ran submitted function definitions with "
                                      "exec() (High)"),
        ((1, 1, 2), (1, 10, 3), None, "CVE-2026-105697: OS command injection through MCP stdio server settings "
                                      "(CVSS 9.9); with the default LANGFLOW_AUTO_LOGIN=true anyone who can "
                                      "reach Langflow can use it"),
        (None, (1, 10, 3), None, "GHSA-j8f7-x8jm-wmm4: SSRF protection in URL-taking components was off or "
                                 "warn-only by default"),
        ((1, 3, 0), (1, 10, 3), None, "CVE-2026-7700: prompt injection in the Smart Transform component leads to "
                                      "code execution (High); from 1.5.0 also CVE-2026-105741, X-Forwarded-For "
                                      "spoofing"),
        ((1, 0, 16), (1, 12, 0), None, "GHSA-33p4-w7j3-33mw: unsafe eval() on Tool-Mode input options (Low)"),
    ]},
    "litellm": {"name": "LiteLLM", "items": [
        (None, (1, 61, 15), None, "CVE-2025-0628: a user can become proxy admin (High)"),
        ((1, 82, 7), None, (1, 82, 8), "GHSA-5mg7-485q-xm76: the 1.82.7 and 1.82.8 releases on PyPI were "
                                       "malicious and harvested credentials; remove them and rotate every key "
                                       "that environment could see"),
        (None, (1, 83, 0), None, "CVE-2026-35030, CVE-2026-35029: OIDC authentication bypass (Critical); "
                                 "privilege escalation through the config endpoint"),
        (None, (1, 83, 7), None, "CVE-2026-37004: template injection in /prompts/test (Critical), plus on most "
                                 "versions SQL injection in the API key check and MCP stdio command execution"),
        (None, (1, 83, 10), None, "CVE-2026-47102, CVE-2026-59823: users can change their own role; SSRF "
                                  "through user_config"),
        (None, (1, 83, 14), None, "CVE-2026-47101: internal users can create keys for routes they aren't "
                                  "allowed to use (High)"),
        (None, (1, 84, 0), None, "CVE-2026-49468, CVE-2026-59822: a crafted Host header gets past the proxy's "
                                 "authentication (CVSS 9.8); MCP auth bypass"),
        ((1, 65, 5), (1, 85, 0), None, "GHSA-hhww-mrg2-969h: reflected XSS in /sso/debug/callback"),
        (None, (1, 88, 6), None, _LITELLM_3CV6),
        ((1, 89, 0), (1, 89, 7), None, _LITELLM_3CV6),
        ((1, 90, 0), (1, 90, 7), None, _LITELLM_3CV6),
        ((1, 91, 0), (1, 91, 5), None, _LITELLM_3CV6),
        ((1, 92, 0), (1, 92, 2), None, _LITELLM_3CV6),
        ((1, 93, 0), (1, 93, 2), None, _LITELLM_3CV6),
        ((1, 94, 0), (1, 94, 3), None, _LITELLM_3CV6),
        ((1, 95, 0), (1, 95, 1), None, _LITELLM_3CV6),
        ((1, 96, 0), (1, 96, 2), None, _LITELLM_3CV6),
        (None, (1, 95, 0), None, "GHSA-g5ff-637f-6q2m (no CVE ID, not in OSV): the internal_user_viewer role can "
                                 "read any file the proxy can, such as the master key (CVSS 8.1)"),
        ((1, 91, 0), (1, 100, 4), None, _LITELLM_7HP6),
        ((1, 101, 0), (1, 101, 3), None, _LITELLM_7HP6),
        ((1, 102, 0), (1, 102, 2), None, _LITELLM_7HP6),
        ((1, 103, 0), (1, 103, 1), None, _LITELLM_7HP6),
    ]},
    "vllm": {"name": "vLLM", "items": [
        ((0, 6, 5), (0, 8, 5), None, "CVE-2025-47277, CVE-2025-32444, CVE-2025-29783: only with distributed KV-cache "
                                     "transfer (PyNcclPipe on the V0 engine, or Mooncake), data from sockets on every "
                                     "interface is unpickled, allowing remote code execution (Critical)"),
        (None, (0, 11, 1), None, "CVE-2025-66448, CVE-2025-62164, CVE-2025-62372: a malicious model config runs its "
                                 "code even with trust_remote_code=False; prompt embeds can corrupt memory; malformed "
                                 "multimodal embeddings crash the server"),
        ((0, 10, 2), (0, 13, 0), None, "CVE-2026-56340: only with --enable-prompt-embeds, the CVE-2025-62164 fix was "
                                       "incomplete"),
        ((0, 10, 1), (0, 14, 0), None, "CVE-2026-22807: model code named in auto_map loads at startup without a "
                                       "trust_remote_code check (High)"),
        ((0, 8, 3), (0, 14, 1), None, "CVE-2026-22778: when serving a video model, a crafted video URL can lead to "
                                      "remote code execution (Critical)"),
        (None, (0, 14, 1), None, "CVE-2026-24779: SSRF past the media URL domain allowlist"),
        ((0, 10, 1), (0, 18, 0), None, "CVE-2026-27893: nemotron_vl and kimi_k25 model code hard-code "
                                       "trust_remote_code=True (High)"),
        ((0, 11, 1), (0, 18, 0), None, "GHSA-8c65-hq7q-r7jm (no CVE ID): remote denial of service through "
                                       "allowed_token_ids with speculative decoding (CVSS 7.5)"),
        ((0, 8, 0), (0, 19, 0), None, "CVE-2026-5497: no frame limit for video/jpeg data URLs, so one "
                                      "unauthenticated request can exhaust memory"),
        ((0, 3, 0), (0, 22, 0), None, "CVE-2026-48746: the API key check is skipped with a crafted Host header when "
                                      "vLLM is reached directly, not behind a proxy such as nginx (Critical)"),
        (None, (0, 24, 0), None, "CVE-2026-55574, CVE-2026-54234 and 9 October 2026 advisories without CVE IDs: "
                                 "regex denial of service in structured outputs, engine crashes, SSRF through "
                                 "X-Request-Id leaking KV-cache tensors on P2pNcclConnector setups"),
        ((0, 10, 2), (0, 25, 0), None, "GHSA-mm38-5g96-7j6x (no CVE ID, not in OSV): the Nemotron-VL processors "
                                       "switch off Pillow's decompression-bomb limit for the whole process, so an "
                                       "oversized image can exhaust memory (High); the advisory's own range, "
                                       "\"<= 0.8.5\", misses these versions"),
        (None, (0, 28, 0), None, "CVE-2026-93592 and others: a negative token ID sent to /v1/embeddings or /pooling "
                                 "crashes the engine (CVSS 7.5)"),
        (None, (0, 29, 0), None, "12 September and 9 October 2026 advisories (mostly no CVE IDs): out-of-range "
                                 "stop_token_ids crash the engine or write out of bounds on the GPU, prompt length "
                                 "checks skipped in disaggregated serving, scheduler stalls"),
        (None, (0, 30, 0), None, "September 2026 batch: structured-output errors crash the shared engine, video "
                                 "sampling exhausts CPU and memory, remote media downloaded in full before size "
                                 "limits apply (GHSA-p6g9-7v3x-m8mv, not in OSV)"),
        ((0, 7, 3), (0, 31, 0), None, "GHSA-h3rc-6mm3-gc2m (no CVE ID, not in OSV): only with trust_remote_code on "
                                      "and a multimodal model whose processor loads remote code, a request can pick "
                                      "the code revision to load, leading to remote code execution (CVSS 8.1)"),
        (None, (0, 31, 0), None, "6 and 9 October 2026 batches (no CVE IDs, not in OSV): per-request processor "
                                 "arguments exhaust memory with many multimodal models (CVSS 7.5), prompt_logprobs "
                                 "crashes the server for every tenant (CVSS 7.7), cache aliasing between requests"),
    ]},
}

# Docker image name (registry and tag removed) -> APP_ADVISORIES key.
IMAGE_PRODUCTS = {
    "n8nio/n8n": "n8n",
    "langgenius/dify-api": "dify",
    "langgenius/dify-web": "dify",
    "infiniflow/ragflow": "ragflow",
    "mintplexlabs/anythingllm": "anythingllm",
    "flowiseai/flowise": "flowise",
    "langflowai/langflow": "langflow",
    "langflowai/langflow-backend": "langflow",
    "berriai/litellm": "litellm",
    "berriai/litellm-database": "litellm",
    "berriai/litellm-non_root": "litellm",
    "vllm/vllm-openai": "vllm",
}


def _n8n_version(j):
    data = j.get("data")
    return data.get("versionCli") if isinstance(data, dict) else None


def _anythingllm_version(j):
    # /api/utils/metrics needs no login. appVersion is DEPLOYMENT_VERSION, which the official Docker
    # image sets; other installs may report null, and then the version can't be read.
    return j.get("appVersion") if "vectorDB" in j and "online" in j else None


# APP_ADVISORIES key -> (port, path, function that returns the version from the JSON reply or None).
# The checks are strict so another program on the same port is not mistaken for the app.
APP_ENDPOINTS = {
    "n8n": (5678, "/rest/settings", _n8n_version),
    "anythingllm": (3001, "/api/utils/metrics", _anythingllm_version),
    "langflow": (7860, "/api/v1/version",
                 lambda j: j.get("version") if "main_version" in j or "package" in j else None),
    "flowise": (3000, "/api/v1/version", lambda j: j.get("version") if set(j) == {"version"} else None),
    "litellm": (4000, "/health/readiness", lambda j: j.get("litellm_version")),
    "vllm": (8000, "/version", lambda j: j.get("version") if set(j) == {"version"} else None),
}

# Ollama's NVIDIA requirements, from https://docs.ollama.com/gpu (October 2026):
# compute capability 5.0+ with driver 550+, and driver 570+ for compute capability 5.0-6.2.
OLLAMA_GPU_DOCS = "https://docs.ollama.com/gpu"
OLLAMA_MIN_COMPUTE = (5, 0)
OLLAMA_MIN_DRIVER = 550
OLLAMA_MIN_DRIVER_OLD_CARDS = 570
# Setting any of these to -1 hides every GPU from Ollama.
FORCE_CPU_VARS = ("CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES", "GGML_VK_VISIBLE_DEVICES")
SETTINGS_KEYS = ("OLLAMA_HOST", "OLLAMA_ORIGINS", "OLLAMA_LLM_LIBRARY") + FORCE_CPU_VARS

AI_IMAGE_HINT = re.compile(r"ollama|open-?webui|comfy|vllm|llama|localai|text-generation|lmstudio|tgi|"
                           r"n8n|flowise|langflow|litellm|dify|ragflow|anythingllm", re.I)

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


def parse_compute_cap(text):
    """(major, minor) from one line of `nvidia-smi --query-gpu=compute_cap`, e.g. "6.1"."""
    m = re.match(r"^\s*(\d+)\.(\d+)\s*$", str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def vstr(v):
    return ".".join(map(str, v))


def advisories_for(version, table):
    return [desc for fixed, desc in table if version < fixed]


def newest_fix(table):
    """The lowest version that is past every advisory in a (fixed_in, description) table."""
    return max(fixed for fixed, _ in table)


def app_flaws(key, version):
    """(descriptions, version to update to or None, how many list no fixed release) for an app version."""
    flaws, upgrade, unfixed = [], None, 0
    for first, fixed, last, desc in APP_ADVISORIES[key]["items"]:
        if first and version < first:
            continue
        if fixed and version >= fixed:
            continue
        if last and version > last:
            continue
        flaws.append(desc)
        if fixed and (upgrade is None or fixed > upgrade):
            upgrade = fixed
        if not fixed:
            unfixed += 1
    return flaws, upgrade, unfixed


def parse_image(image):
    """'docker.n8n.io/n8nio/n8n:2.40.0' -> ('n8nio/n8n', '2.40.0'). The tag is '' when there is none."""
    s = str(image or "").strip().split("@", 1)[0]
    name, tag = s, ""
    if ":" in s.rsplit("/", 1)[-1]:
        name, tag = s.rsplit(":", 1)
    parts = name.lower().split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return "/".join(parts), tag


def parse_docker_images(text):
    """{app key: (version or None, image)} from `docker ps --format {{.Image}}` output."""
    found = {}
    for line in (text or "").splitlines():
        name, tag = parse_image(line)
        key = IMAGE_PRODUCTS.get(name)
        if not key:
            continue
        version = parse_version(tag)
        if key not in found or (version and not found[key][0]):
            found[key] = (version, line.strip())
    return found


def ollama_flaws(version, system):
    flaws = advisories_for(version, OLLAMA_ADVISORIES)
    flaws += [desc for low, fixed, desc in OLLAMA_RANGED_ADVISORIES if low <= version < fixed]
    low, fixed, desc = OLLAMA_WINDOWS_UPDATER
    windows_flaw = desc if system == "Windows" and low <= version < fixed else None
    return flaws, windows_flaw


def ollama_feature_flaws(version):
    return [desc for low, fixed, desc in OLLAMA_FEATURE_ADVISORIES if low <= version < fixed]


def nvidia_driver_problem(driver, compute_cap):
    """Why Ollama may not use this NVIDIA GPU, or None. compute_cap is a string such as "6.1" or None."""
    cap = parse_compute_cap(compute_cap)
    m = re.match(r"\s*(\d+)", str(driver or ""))
    major = int(m.group(1)) if m else None
    if cap and cap < OLLAMA_MIN_COMPUTE:
        return (f"Its compute capability is {vstr(cap)}, below the 5.0 that Ollama supports, "
                "so Ollama runs every model on the CPU.")
    if major is None:
        return None
    if cap and cap <= (6, 2) and major < OLLAMA_MIN_DRIVER_OLD_CARDS:
        return (f"Ollama needs NVIDIA driver {OLLAMA_MIN_DRIVER_OLD_CARDS} or newer for cards with compute "
                f"capability 5.0-6.2 (this one is {vstr(cap)}), and this machine has driver {driver}. "
                "Ollama may quietly fall back to the CPU.")
    if major < OLLAMA_MIN_DRIVER:
        return (f"Ollama needs NVIDIA driver {OLLAMA_MIN_DRIVER} or newer, and this machine has driver {driver}. "
                "Ollama may quietly fall back to the CPU.")
    return None


def forced_cpu_settings(env):
    """Settings in env (a name -> value dict) that keep Ollama off the GPU."""
    hits = [f"{k}={env[k]}" for k in FORCE_CPU_VARS if str(env.get(k, "")).strip() == "-1"]
    lib = str(env.get("OLLAMA_LLM_LIBRARY") or "")
    if lib.lower().startswith("cpu"):
        hits.append(f"OLLAMA_LLM_LIBRARY={lib}")
    return hits


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
        if gpus:
            # Separate query: older drivers don't know this field and would fail the one above.
            caps = [parse_compute_cap(line) for line in
                    (run(["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"]) or "").splitlines()]
            for g, cap in zip(gpus, caps):
                g["compute_capability"] = vstr(cap) if cap else None
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
    """Ollama-related settings from this shell and, on Linux, from the systemd service."""
    found = {}
    for k in SETTINGS_KEYS:
        if os.environ.get(k):
            found[k] = (os.environ[k], "this shell")
    if platform.system() == "Linux" and shutil.which("systemctl"):
        svc = parse_systemd_environment(run(["systemctl", "show", "ollama", "-p", "Environment", "--value"]))
        for k in SETTINGS_KEYS:
            if svc.get(k):
                found[k] = (svc[k], "the ollama systemd service")
    return found


def wide_host(value):
    return bool(re.match(r"^(https?://)?(0\.0\.0\.0|\[?::\]?)?(:\d+)?/?$", value or "")) and value not in ("", None)


def check_ollama_gpu(rep, settings):
    forced = forced_cpu_settings({k: v[0] for k, v in settings.items()})
    if forced:
        rep.add("warn", "A setting keeps Ollama off the GPU",
                ", ".join(forced) + " hides the GPU from Ollama or picks a CPU-only library, so every model "
                "runs on the CPU.",
                "Remove it, or set it to your GPU's ID or UUID (from `nvidia-smi -L` or `rocminfo`), "
                "then restart Ollama.")
    for g in rep.facts.get("gpus") or []:
        if g.get("driver") == "ROCm":
            continue
        problem = nvidia_driver_problem(g.get("driver"), g.get("compute_capability"))
        if problem:
            rep.add("warn", f"Ollama may not be able to use the {g['name']}", problem,
                    "Install the current driver from https://www.nvidia.com/drivers and restart Ollama. "
                    f"Requirements: {OLLAMA_GPU_DOCS}")


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
    check_ollama_gpu(rep, settings)

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


def app_version_from_port(host, key):
    """Version string the app reports on its own port, or None if it isn't that app."""
    port, path, field = APP_ENDPOINTS[key]
    j = get_json(f"http://{host}:{port}{path}")
    return field(j) if isinstance(j, dict) else None


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
    if port == 3001:
        # Identified even when it reports no version (appVersion is null outside the Docker image).
        mt = get_json(f"http://{host}:{port}/api/utils/metrics")
        if isinstance(mt, dict) and "vectorDB" in mt and "online" in mt:
            return "AnythingLLM"
    for key, (app_port, _, _) in APP_ENDPOINTS.items():
        if port == app_port and app_version_from_port(host, key):
            return APP_ADVISORIES[key]["name"]
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
            elif port == 4000:
                detail += " A LiteLLM proxy holds the API keys of every model provider it routes to."
            elif port == 3001:
                detail += (" AnythingLLM in single-user mode has no password unless you set one in its "
                           "Security settings, and its agents can read files and run tools.")
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
                        "; ".join(flaws),
                        f"Update Open WebUI to {vstr(newest_fix(OPEN_WEBUI_ADVISORIES))} or newer; the latest "
                        "release is best (for Docker: pull the new image and recreate the container; your data "
                        "volume is kept). Until then, ENABLE_COMMUNITY_SHARING=False closes the cross-site "
                        "token theft (GHSA-vpq8-f445-hcq7).")
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


def report_app(rep, key, app):
    """Add the finding for one self-hosted app. app: {"version": tuple or None, "source": str, "lan": bool}."""
    name, version = APP_ADVISORIES[key]["name"], app["version"]
    page = f"{SITE_URL}{key}.html"
    rep.facts.setdefault("apps", {})[key] = {"version": vstr(version) if version else None,
                                             "source": app["source"]}
    if not version:
        rep.add("info", f"{name} found ({app['source']}) but its version could not be read",
                "Image tags such as latest, main or nightly don't say which release is running.",
                f"Look up the version in {name} itself and check it at {SITE_URL}?product={key}")
        return
    flaws, upgrade, unfixed = app_flaws(key, version)
    rep.facts["apps"][key]["advisories"] = len(flaws)
    if not flaws:
        rep.add("ok", f"{name} {vstr(version)} is past the advisories this script knows about",
                "Newer advisories may exist; the latest release is always the safest choice.")
        return
    fix = (f"Update {name} to {vstr(upgrade)} or newer; the latest release is best."
           if upgrade else f"Update {name} to the latest release.")
    if unfixed:
        fix += (f" {unfixed} of these list no fixed release yet, so updating won't clear "
                f"{'it' if unfixed == 1 else 'them'}; follow the mitigations on {page}")
    else:
        fix += f" Details: {page}"
    rep.add("risk" if app["lan"] else "warn",
            f"{name} {vstr(version)} ({app['source']}) has {len(flaws)} known security "
            f"{'advisory' if len(flaws) == 1 else 'advisories'}",
            "; ".join(flaws), fix)


def check_apps(rep, ports):
    """n8n, Dify, RAGFlow, AnythingLLM, Langflow, Flowise, LiteLLM and vLLM: version from the app's own port,
    or from the tag of its running Docker image (Dify and RAGFlow only ship as images, so package scanners
    miss them)."""
    found = {}
    for key, (port, _, _) in APP_ENDPOINTS.items():
        info = ports.get(port)
        if not info or info["identified_as"] != APP_ADVISORIES[key]["name"]:
            continue
        host = "127.0.0.1" if info["local"] else rep.facts.get("lan_ip")
        found[key] = {"version": parse_version(app_version_from_port(host, key)), "source": f"port {port}",
                      "lan": info["lan"]}
    if shutil.which("docker"):
        published = {d["image"] for d in rep.facts.get("docker_published_ai_ports") or []}
        images = parse_docker_images(run(["docker", "ps", "--format", "{{.Image}}"], timeout=10))
        for key, (version, image) in images.items():
            if key in found and found[key]["version"]:
                continue
            found[key] = {"version": version, "source": f"Docker image {image}",
                          "lan": image in published or found.get(key, {}).get("lan", False)}
    for key in APP_ADVISORIES:
        if key in found:
            report_app(rep, key, found[key])


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
    print(f"local-ai-checkup {__version__}  by MV2 of Munim, Inc.")
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
    print(f"Free CVE checker and model fit calculator: {SITE_URL}")
    print("Want a written review of your setup with exact fixes? MV2 of Munim, Inc. does a")
    print(f"$49 local AI health check: {PAID_CHECK_URL}")
    print(f"or $199 for up to 5 machines or one shared team server: {SMALL_OFFICE_URL}")


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
    check_apps(rep, ports)
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
