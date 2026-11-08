# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Checks that skills/local-ai-checkup/SKILL.md stays true to the script it describes.

The SKILL.md checks always run. The checks against local_ai_checkup.py run whenever the
script sits next to this file (a checkout of the repository); a copy of only the skill
files, without the script, skips them and says so.
"""
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "skills", "local-ai-checkup")
SKILL = os.path.join(SKILL_DIR, "SKILL.md")
SCRIPT = os.path.join(HERE, "local_ai_checkup.py")
HAVE_SCRIPT = os.path.exists(SCRIPT)
NO_SCRIPT = "local_ai_checkup.py is not next to this test (skill files only)"


def read_skill():
    with open(SKILL, encoding="utf-8") as f:
        return f.read().replace("\r\n", "\n")


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        raise AssertionError("SKILL.md must start with YAML frontmatter between --- lines")
    fields = {}
    for line in m.group(1).splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or line.startswith(" "):
            raise AssertionError("only simple 'key: value' lines are used here: %r" % line)
        fields[key.strip()] = value.strip()
    return fields, text[m.end():]


class SkillFrontmatter(unittest.TestCase):
    def test_name_matches_folder_and_spec(self):
        fields, _ = frontmatter(read_skill())
        self.assertEqual(fields.get("name"), os.path.basename(SKILL_DIR))
        self.assertRegex(fields["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(fields["name"]), 64)

    def test_description_present_and_short(self):
        fields, _ = frontmatter(read_skill())
        desc = fields.get("description", "")
        self.assertGreater(len(desc), 50)
        self.assertLessEqual(len(desc), 1024)
        self.assertIn("MV2 of Munim, Inc.", desc)
        self.assertIn("AI agents", desc)
        self.assertIn("Apache-2.0", desc)
        self.assertNotIn("MIT", desc)
        # a plain YAML scalar must not contain ": " or start with a YAML indicator
        self.assertNotIn(": ", desc)
        self.assertFalse(desc[:1] in "[]{}&*!|>'\"%@`#")

    def test_only_known_keys(self):
        fields, _ = frontmatter(read_skill())
        self.assertEqual(set(fields), {"name", "description"})


class SkillText(unittest.TestCase):
    def test_documented_flags_and_exit_codes(self):
        body = frontmatter(read_skill())[1]
        for text in ("--json", "--version", "`0` all clear", "`1` warnings only",
                     "`2` at least one risk"):
            self.assertIn(text, body)

    def test_documented_levels_and_keys(self):
        body = frontmatter(read_skill())[1]
        for word in ("risk", "warn", "ok", "info", "version", "facts", "findings",
                     "level", "title", "detail", "fix"):
            self.assertIn("`%s`" % word, body)

    def test_safety_rules_present(self):
        body = frontmatter(read_skill())[1]
        self.assertIn("Apply no fix on your own", body)
        self.assertIn("Never suggest it unprompted", body)
        self.assertIn("HARDENING.md", body)

    def test_no_secrets_or_address_fields(self):
        body = read_skill().lower()
        for word in ("password:", "api_key=", "token="):
            self.assertNotIn(word, body)


@unittest.skipUnless(HAVE_SCRIPT, NO_SCRIPT)
class SkillMatchesScript(unittest.TestCase):
    def run_script(self, *args):
        return subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True,
                              text=True, timeout=300, env=dict(os.environ))

    def test_version_flag(self):
        r = self.run_script("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex((r.stdout + r.stderr).strip(), r"^\d+\.\d+\.\d+$")

    def test_json_shape_and_exit_code_as_documented(self):
        r = self.run_script("--json")
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(set(data), {"version", "facts", "findings"})
        levels = set()
        for f in data["findings"]:
            self.assertEqual(set(f), {"level", "title", "detail", "fix"})
            levels.add(f["level"])
        self.assertLessEqual(levels, {"risk", "warn", "ok", "info"})
        expected = 2 if "risk" in levels else (1 if "warn" in levels else 0)
        self.assertEqual(r.returncode, expected)

    def test_documented_flags_exist_in_script(self):
        with open(SCRIPT, encoding="utf-8") as f:
            src = f.read()
        for flag in ("--json", "--version"):
            self.assertIn('"%s"' % flag, src)

    def test_linked_repo_files_exist(self):
        self.assertTrue(os.path.exists(os.path.join(HERE, "HARDENING.md")))


if __name__ == "__main__":
    unittest.main()
