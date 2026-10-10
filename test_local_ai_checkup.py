"""Unit tests for the pure parts of local_ai_checkup.

Run from this folder with `python -m unittest -v`, or from anywhere with
`python path/to/test_local_ai_checkup.py -v`.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import local_ai_checkup as lac  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(lac.parse_version("ollama version is 0.17.1"), (0, 17, 1))
        self.assertEqual(lac.parse_version("v0.40.2-rc1"), (0, 40, 2))
        self.assertIsNone(lac.parse_version(None))
        self.assertIsNone(lac.parse_version("unknown"))

    def test_ollama_flaws(self):
        flaws, win = lac.ollama_flaws((0, 1, 30), "Linux")
        self.assertEqual(len(flaws), 2)
        self.assertIsNone(win)
        flaws, win = lac.ollama_flaws((0, 17, 1), "Linux")
        self.assertEqual(flaws, [])
        flaws, win = lac.ollama_flaws((0, 17, 1), "Windows")
        self.assertIsNotNone(win)
        flaws, win = lac.ollama_flaws((0, 23, 2), "Windows")
        self.assertIsNotNone(win)
        self.assertIsNone(lac.ollama_flaws((0, 24, 0), "Windows")[1])
        self.assertIsNone(lac.ollama_flaws((0, 12, 9), "Windows")[1])

    def test_ollama_pull_path_traversal_range(self):
        self.assertEqual(lac.ollama_flaws((0, 34, 1), "Linux")[0], [])
        flaws = lac.ollama_flaws((0, 34, 2), "Linux")[0]
        self.assertEqual(len(flaws), 1)
        self.assertIn("CVE-2026-103663", flaws[0])
        self.assertEqual(len(lac.ollama_flaws((0, 34, 9), "Windows")[0]), 1)
        self.assertEqual(lac.ollama_flaws((0, 35, 0), "Linux")[0], [])
        self.assertEqual(lac.ollama_flaws((0, 40, 2), "Linux")[0], [])

    def test_ollama_pull_ssrf_range(self):
        flaws = lac.ollama_flaws((0, 32, 4), "Linux")[0]
        self.assertEqual(len(flaws), 1)
        self.assertIn("CVE-2026-85180", flaws[0])
        self.assertEqual(lac.ollama_flaws((0, 29, 9), "Linux")[0], [])
        self.assertEqual(lac.ollama_flaws((0, 33, 3), "Linux")[0], [])

    def test_ollama_feature_flaws(self):
        self.assertEqual(len(lac.ollama_feature_flaws((0, 31, 1))), 1)
        self.assertEqual(lac.ollama_feature_flaws((0, 31, 2)), [])
        self.assertEqual(lac.ollama_feature_flaws((0, 13, 9)), [])

    def test_open_webui_and_comfyui_advisories(self):
        self.assertEqual(len(lac.advisories_for((0, 8, 5), lac.OPEN_WEBUI_ADVISORIES)), 4)
        self.assertEqual(len(lac.advisories_for((0, 9, 5), lac.OPEN_WEBUI_ADVISORIES)), 2)
        self.assertEqual(len(lac.advisories_for((0, 10, 0), lac.OPEN_WEBUI_ADVISORIES)), 1)
        self.assertEqual(lac.advisories_for((0, 11, 0), lac.OPEN_WEBUI_ADVISORIES), [])
        self.assertEqual(len(lac.advisories_for((0, 3, 76), lac.COMFYUI_ADVISORIES)), 1)
        self.assertEqual(lac.advisories_for((0, 28, 0), lac.COMFYUI_ADVISORIES), [])

    def test_wide_host(self):
        for v in ("0.0.0.0", "0.0.0.0:11434", "http://0.0.0.0:11434", "::", "[::]:11434", ":11434"):
            self.assertTrue(lac.wide_host(v), v)
        for v in ("", None, "127.0.0.1", "127.0.0.1:11434", "localhost", "192.168.1.5"):
            self.assertFalse(lac.wide_host(v), v)

    def test_parse_systemd_environment(self):
        env = lac.parse_systemd_environment('OLLAMA_HOST=0.0.0.0 "OLLAMA_ORIGINS=*" PATH=/usr/bin')
        self.assertEqual(env["OLLAMA_HOST"], "0.0.0.0")
        self.assertEqual(env["OLLAMA_ORIGINS"], "*")
        self.assertEqual(lac.parse_systemd_environment(None), {})

    def test_parse_docker_ps(self):
        text = ("ollama/ollama|0.0.0.0:11434->11434/tcp, :::11434->11434/tcp\n"
                "ghcr.io/open-webui/open-webui:main|127.0.0.1:3000->8080/tcp\n"
                "postgres|5432/tcp\n")
        self.assertEqual(lac.parse_docker_ps(text), [("ollama/ollama", 11434, 11434)])
        self.assertEqual(lac.parse_docker_ps(None), [])
        self.assertEqual(lac.parse_docker_ps("Cannot connect to the Docker daemon"), [])

    def test_parse_rocm(self):
        vram = json.dumps({"card0": {"VRAM Total Memory (B)": "17163091968",
                                     "VRAM Total Used Memory (B)": "1048576"}})
        names = json.dumps({"card0": {"Card Series": "Radeon RX 7800 XT"}})
        gpus = lac.parse_rocm(vram, names)
        self.assertEqual(len(gpus), 1)
        self.assertEqual(gpus[0]["vram_bytes"], 17163091968)
        self.assertEqual(gpus[0]["vram_used_bytes"], 1048576)
        self.assertIn("Radeon RX 7800 XT", gpus[0]["name"])
        self.assertEqual(lac.parse_rocm("not json", None), [])
        self.assertEqual(lac.parse_rocm(None, None), [])


class SmokeTest(unittest.TestCase):
    def test_main_runs_and_emits_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = lac.main(["--json"])
        self.assertIn(code, (0, 1, 2))
        data = json.loads(buf.getvalue())
        self.assertEqual(data["version"], lac.__version__)
        self.assertIn("findings", data)


if __name__ == "__main__":
    unittest.main()
