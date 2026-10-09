"""Regression tests for localized glossary extraction and annotation invariants."""

import json
import tempfile
import unittest
from pathlib import Path

import term_hints


def row(key, label, definition):
    return (
        f'<tr><td><span id="term-{key}" data-glossary-term="{key}">'
        f"<strong>{label}</strong></span></td><td>{definition}</td></tr>"
    )


def glossary(*rows):
    return "<html><main><table>" + "".join(rows) + "</table></main></html>"


def edition(code="en"):
    return {"code": code, "termHints": {"glossary": "Glossary", "close": "Close"}}


def rule(automatic=True, sensitive=True, aliases=None):
    return {
        "automatic": automatic,
        "caseSensitive": sensitive,
        "aliases": aliases or {},
    }


class DictionaryTests(unittest.TestCase):
    def test_formatted_unicode_definitions_and_punctuation_remain_plain_text(self):
        html = glossary(
            row("pcap", "PCAP", "Captura &amp; anàlisi: <code>.pcap</code>."),
            row(
                "aho-corasick", "Aho–Corasick", "<p>Many patterns.</p><p>One pass.</p>"
            ),
        )
        data = term_hints.dictionary(
            html, edition("ca"), {"pcap": rule(), "aho-corasick": rule()}
        )
        self.assertEqual(data["language"], "ca")
        self.assertEqual(data["terms"][0]["definition"], "Captura & anàlisi: .pcap.")
        self.assertEqual(data["terms"][1]["definition"], "Many patterns. One pass.")
        self.assertEqual(data["terms"][1]["aliases"], ["Aho–Corasick"])

    def test_localized_label_and_only_current_language_aliases(self):
        policy = {
            "flow": rule(sensitive=False, aliases={"en": ["Flow"], "de": ["Fluss"]})
        }
        html = glossary(row("flow", "Flusssteuerung", "Steuert den Fluss."))
        data = term_hints.dictionary(html, edition("de"), policy)
        self.assertEqual(data["terms"][0]["aliases"], ["Flusssteuerung", "Fluss"])
        self.assertEqual(data["terms"][0]["href"], "appendices/glossary.html#term-flow")
        self.assertFalse(data["terms"][0]["caseSensitive"])

    def test_explicit_only_terms_have_no_automatic_aliases(self):
        data = term_hints.dictionary(
            glossary(row("tap", "Tap", "Standalone capture.")),
            edition(),
            {"tap": rule(automatic=False)},
        )
        self.assertEqual(data["terms"][0]["aliases"], [])

    def test_missing_and_extra_identifiers_are_actionable(self):
        for html, policy in [
            (glossary(), {"pcap": rule()}),
            (glossary(row("tls", "TLS", "Encryption.")), {"pcap": rule()}),
        ]:
            with (
                self.subTest(html=html),
                self.assertRaisesRegex(ValueError, "identifiers differ"),
            ):
                term_hints.dictionary(html, edition(), policy)

    def test_unmarked_glossary_row_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "row missing"):
            term_hints.Glossary(glossary("<tr><td>PCAP</td><td>Capture.</td></tr>"))

    def test_duplicate_identifiers_and_incorrect_destination_are_rejected(self):
        html = row("pcap", "PCAP", "Capture.")
        for content, error in [
            (html + html, "Duplicate glossary identifier"),
            (html.replace('id="term-pcap"', 'id="wrong"'), "use span"),
            (
                html.replace('data-glossary-term="pcap"', 'data-glossary-term="PCAP"'),
                "Invalid glossary",
            ),
        ]:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                term_hints.Glossary(glossary(content))

    def test_empty_label_or_definition_is_rejected(self):
        for label, definition in [("", "Capture."), ("PCAP", "<br> \n")]:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "empty label or definition"),
            ):
                term_hints.Glossary(glossary(row("pcap", label, definition)))

    def test_marker_in_definition_is_rejected(self):
        html = '<tr><td>PCAP</td><td><span id="term-pcap" data-glossary-term="pcap">Capture.</span></td></tr>'
        with self.assertRaisesRegex(ValueError, "marker must be in the term cell"):
            term_hints.Glossary(glossary(html))

    def test_alias_collisions_respect_both_case_rules(self):
        html = glossary(row("one", "PCAP", "One."), row("two", "pcap", "Two."))
        term_hints.dictionary(html, edition(), {"one": rule(), "two": rule()})
        for policy in [
            {"one": rule(sensitive=False), "two": rule()},
            {"one": rule(), "two": rule(sensitive=False)},
            {"one": rule(aliases={"en": ["pcap"]}), "two": rule()},
        ]:
            with (
                self.subTest(policy=policy),
                self.assertRaisesRegex(ValueError, "conflicting alias"),
            ):
                term_hints.dictionary(html, edition(), policy)

    def test_unicode_alias_collision(self):
        html = glossary(row("one", "Ärger", "One."), row("two", "ÄRGER", "Two."))
        with self.assertRaisesRegex(ValueError, "conflicting alias"):
            term_hints.dictionary(
                html, edition(), {"one": rule(sensitive=False), "two": rule()}
            )

    def test_missing_localized_controls_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "configure termHints"):
            term_hints.dictionary(glossary(), {"code": "de"}, {})

    def test_generation_writes_into_root_or_nested_edition(self):
        with tempfile.TemporaryDirectory(prefix="lippycat-term-hints-") as directory:
            for language, prefix in [("ca", ""), ("en", "en")]:
                destination = Path(directory) / prefix
                (destination / "appendices").mkdir(parents=True)
                (destination / "part1").mkdir()
                (destination / "appendices" / "glossary.html").write_text(
                    glossary(row("pcap", "PCAP", f"{language}: capture."))
                )
                (destination / "part1" / "nested.html").write_text(
                    '<main><span data-term="pcap">PCAP</span></main>'
                )
                ids = term_hints.generate(
                    destination, edition(language), {"pcap": rule()}
                )
                self.assertEqual(ids, {"pcap"})
                data = json.loads((destination / "term-hints.json").read_text())
                self.assertEqual(data["language"], language)
                self.assertEqual(
                    data["terms"][0]["href"], "appendices/glossary.html#term-pcap"
                )

    def test_unknown_explicit_id_rejected_with_chapter_context(self):
        with tempfile.TemporaryDirectory(prefix="lippycat-term-hints-") as directory:
            destination = Path(directory)
            (destination / "appendices").mkdir()
            (destination / "appendices" / "glossary.html").write_text(
                glossary(row("pcap", "PCAP", "Capture."))
            )
            (destination / "chapter.html").write_text(
                '<span data-term="wrong">Word</span>'
            )
            with self.assertRaisesRegex(
                ValueError, "unknown explicit term 'wrong' in chapter.html"
            ):
                term_hints.generate(destination, edition(), {"pcap": rule()})


class PolicyTests(unittest.TestCase):
    def test_policy_schema_and_explicit_alias_rules(self):
        with tempfile.TemporaryDirectory(prefix="lippycat-term-hints-") as directory:
            path = Path(directory) / "policy.json"
            valid = {"pcap": rule(aliases={"de": ["Paketmitschnitt"]})}
            path.write_text(json.dumps(valid))
            self.assertEqual(term_hints.load_policy(path, {"en", "de"}), valid)
            for invalid in [
                {},
                {"PCAP": rule()},
                {"pcap": rule(automatic="true")},
                {"pcap": rule(aliases={"zz": ["Capture"]})},
                {"pcap": rule(aliases={"en": [""]})},
                {"pcap": rule(aliases={"en": "Capture"})},
                {"pcap": rule(automatic=False, aliases={"en": ["Capture"]})},
            ]:
                path.write_text(json.dumps(invalid))
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    term_hints.load_policy(path, {"en", "de"})

    def test_annotation_fingerprints_preserve_attributes_and_translate_text(self):
        original = '<span data-term="processor">processor</span><span data-no-term-hints>Tap</span>'
        translated = original.replace(">processor<", ">Prozessor<").replace(
            ">Tap<", ">Knoten<"
        )
        self.assertEqual(
            term_hints.annotation_fingerprint(original),
            term_hints.annotation_fingerprint(translated),
        )
        self.assertNotEqual(
            term_hints.annotation_fingerprint(original),
            term_hints.annotation_fingerprint(
                translated.replace('data-term="processor"', 'data-term="prozessor"')
            ),
        )
        self.assertEqual(
            term_hints.annotation_fingerprint('&lt;span data-term="wrong"&gt;'), []
        )


if __name__ == "__main__":
    unittest.main()
