"""Regression checks for reviewed and outdated manual translations."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import manual


class TranslationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lippycat-manual-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "src").mkdir()
        (self.root / "po").mkdir()
        (self.root / "book.toml").write_text(
            '[book]\ntitle = "Test manual"\nlanguage = "en"\nsrc = "src"\n'
            '[output.html]\n[preprocessor.gettext]\nafter = ["links"]\n'
        )
        (self.root / "languages.json").write_text(
            json.dumps(
                [
                    {
                        "code": code,
                        "name": code,
                        "path": path,
                        "title": "Test manual",
                        "description": "Test description",
                    }
                    for code, path in [("en", ""), ("de", "de/")]
                ]
            )
        )
        (self.root / "src" / "SUMMARY.md").write_text(
            "# Summary\n\n- [Introduction](introduction.md)\n"
        )
        (self.root / "src" / "introduction.md").write_text(
            "# Introduction {#introduction}\n\nRun `lc sniff --new`.\n"
        )
        patcher = patch.multiple(manual, ROOT=self.root, OUTPUT=self.root / "book")
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog(self, fuzzy):
        header = (
            "Project-Id-Version: Test manual\n"
            "PO-Revision-Date: 2026-09-27 00:00+0000\n"
            "Last-Translator: Test\nLanguage-Team: Test\nLanguage: de\n"
            "MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n"
            "Content-Transfer-Encoding: 8bit\n"
            "Plural-Forms: nplurals=2; plural=(n != 1);\n"
        )
        flag = "#, fuzzy\n" if fuzzy else ""
        (self.root / "po" / "de.po").write_text(
            f'msgid ""\nmsgstr {json.dumps(header)}\n\n'
            "#: src/SUMMARY.md:3 src/introduction.md:1\n"
            f'{flag}msgid "Introduction"\nmsgstr "Veralteter Titel"\n\n'
            "#: src/introduction.md:3\n"
            f'{flag}msgid "Run `lc sniff --new`."\n'
            'msgstr "Starten Sie `lc sniff --old`."\n'
        )

    def test_fuzzy_titles_and_commands_render_in_english(self):
        self.catalog(fuzzy=True)
        original = (self.root / "po" / "de.po").read_bytes()
        manual.build()
        html = (self.root / "book" / "de" / "introduction.html").read_text()
        self.assertIn('href="#introduction">Introduction</a>', html)
        self.assertIn("lc sniff --new", html)
        self.assertNotIn("Veralteter Titel", html)
        self.assertNotIn("lc sniff --old", html)
        self.assertEqual(original, (self.root / "po" / "de.po").read_bytes())

    def test_fuzzy_old_commands_do_not_block_catalog_checks(self):
        self.catalog(fuzzy=True)
        with contextlib.redirect_stdout(io.StringIO()):
            manual.check()
            with self.assertRaisesRegex(ValueError, "messages need translation"):
                manual.check(require_complete=True)

    def test_reviewed_translations_cannot_change_commands(self):
        self.catalog(fuzzy=False)
        with (
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(ValueError, "changed code or link target"),
        ):
            manual.check()


if __name__ == "__main__":
    unittest.main()
