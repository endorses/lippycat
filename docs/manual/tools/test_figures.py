"""Checks for localized figure numbering and validated diagram/image markup."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import figures

SCRIPT = Path(figures.__file__).resolve()


def figure(identifier="fig-overview", caption="Overview of the nodes."):
    return (
        f'<figure id="{identifier}">\n\n'
        "<!-- i18n:skip -->\n\n"
        "```mermaid\ngraph LR\n    A --> B\n```\n\n"
        f"<figcaption>{caption}</figcaption>\n\n</figure>\n"
    )


def image_figure(identifier="fig-capture", caption="Live capture with details."):
    return (
        f'<figure id="{identifier}">\n\n'
        "![Live packet list with packet details.](images/capture.png)\n\n"
        f"<figcaption>{caption}</figcaption>\n\n</figure>\n"
    )


def chapter(content, name="Overview", children=None):
    return {
        "Chapter": {
            "name": name,
            "source_path": f"{name.lower()}.md",
            "content": content,
            "sub_items": children or [],
        }
    }


class FigureTests(unittest.TestCase):
    def test_nested_reading_order_and_original_book_preserved(self):
        original = {
            "sections": [
                {"PartTitle": "Foundations"},
                chapter(
                    figure(),
                    children=[chapter(figure("fig-detail"), "Detail")],
                ),
                {"Separator": None},
                chapter(figure("fig-later"), "Later"),
            ],
            "metadata": {"unchanged": True},
        }
        output = figures.preprocess(original, "en")
        parent = output["sections"][1]["Chapter"]
        contents = [
            parent["content"],
            parent["sub_items"][0]["Chapter"]["content"],
            output["sections"][3]["Chapter"]["content"],
        ]
        for number, content in enumerate(contents, 1):
            self.assertIn(f' data-figure-number="{number}"', content)
            self.assertIn(f"Figure\u00a0{number}:</span>", content)
        self.assertIn('aria-labelledby="fig-overview-caption"', contents[0])
        self.assertIn('<figcaption id="fig-overview-caption">', contents[0])
        self.assertEqual(original["sections"][1]["Chapter"]["content"], figure())
        self.assertEqual(output["metadata"], original["metadata"])

    def test_localized_labels_and_caption_markup(self):
        for language, label in figures.LABELS.items():
            with self.subTest(language=language):
                content = figures.preprocess(
                    {"sections": [chapter(figure(caption="Überblick <em>àgil</em>."))]},
                    language,
                )["sections"][0]["Chapter"]["content"]
                self.assertIn(
                    f"{label}\u00a01:</span> Überblick <em>àgil</em>.", content
                )
        with self.assertRaisesRegex(ValueError, "unsupported figure language"):
            figures.preprocess({"sections": []}, "xx")

    def test_current_mdbook_items_protocol(self):
        output = figures.preprocess({"items": [chapter(figure())]}, "en")
        self.assertNotIn("sections", output)
        self.assertIn("Figure\u00a01:", output["items"][0]["Chapter"]["content"])

    def test_image_figures_share_numbering_references_and_localized_list(self):
        captions = {
            "en": "Live capture with details.",
            "de": "Live-Erfassung mit Paketdetails.",
            "ca": "Captura en directe amb detalls.",
        }
        for language, label in figures.LABELS.items():
            with self.subTest(language=language):
                image = image_figure(caption=captions[language])
                original = (
                    "See {{#figure fig-capture}}.\n\n"
                    + figure()
                    + "\n"
                    + image
                    + "\n{{#figure-list}}\n"
                )
                output = figures.preprocess({"items": [chapter(original)]}, language)[
                    "items"
                ][0]["Chapter"]["content"]
                self.assertIn(f"[{label}\u00a02](#fig-capture)", output)
                self.assertIn(f"{label}\u00a02:</span> {captions[language]}", output)
                self.assertIn(
                    f"- [{label}\u00a02: {captions[language][:-1]}\\.](#fig-capture)",
                    output,
                )
                self.assertIn(
                    "![Live packet list with packet details.](images/capture.png)",
                    output,
                )
                self.assertEqual(
                    figures.annotation_fingerprint(original),
                    ["fig-overview", "fig-capture"],
                )

    def test_unnumbered_images_remain_unchanged(self):
        content = "![Introduction demo.](images/demo.gif)\n"
        self.assertEqual(figures.parse_figures(content), [])
        self.assertEqual(
            figures.preprocess({"items": [chapter(content)]}, "en")["items"][0][
                "Chapter"
            ]["content"],
            content,
        )

    def test_image_alt_escapes_and_optional_title(self):
        for markup in (
            r'![Packet \[details\].](images/capture.png "Capture")',
            "![Packet details.](<images/packet capture.png>)",
        ):
            with self.subTest(markup=markup):
                self.assertEqual(
                    len(
                        figures.parse_figures(
                            image_figure().replace(
                                "![Live packet list with packet details.](images/capture.png)",
                                markup,
                            )
                        )
                    ),
                    1,
                )

    def test_forward_nested_and_same_chapter_references(self):
        detail = chapter(
            "See {{#figure fig-overview}}.\n\n" + figure("fig-detail"), "Detail"
        )
        detail["Chapter"]["source_path"] = "foundations/nested/detail.md"
        overview = chapter(
            "See {{#figure fig-later}} and {{#figure fig-overview}}.\n\n" + figure(),
            children=[detail],
        )
        overview["Chapter"]["source_path"] = "foundations/overview.md"
        later = chapter(figure("fig-later"), "Later")
        later["Chapter"]["source_path"] = "advanced/later.md"
        output = figures.preprocess({"items": [overview, later]}, "de")
        content = output["items"][0]["Chapter"]["content"]
        self.assertIn("[Abbildung\u00a03](../advanced/later.md#fig-later)", content)
        self.assertIn("[Abbildung\u00a01](#fig-overview)", content)
        self.assertIn(
            "[Abbildung\u00a01](../overview.md#fig-overview)",
            output["items"][0]["Chapter"]["sub_items"][0]["Chapter"]["content"],
        )

    def test_list_uses_localized_catalog_captions_and_reading_order(self):
        overview = chapter(
            figure(caption="Els <em>nodes</em> [A] &amp; B."),
            children=[chapter(figure("fig-detail", "Un detall."), "Detail")],
        )
        index = chapter("# Figures\n\n{{#figure-list}}\n", "List")
        index["Chapter"]["source_path"] = "appendices/list.md"
        output = figures.preprocess({"sections": [overview, index]}, "ca")
        content = output["sections"][1]["Chapter"]["content"]
        self.assertIn('<div class="figure-list">\n\n', content)
        self.assertIn(
            "- [Figura\u00a01: Els nodes \\[A\\] & B\\.](../overview.md#fig-overview)",
            content,
        )
        self.assertIn(
            "- [Figura\u00a02: Un detall\\.](../detail.md#fig-detail)", content
        )
        self.assertLess(content.index("Figura\u00a01"), content.index("Figura\u00a02"))
        self.assertNotIn("<em>", content)
        self.assertNotIn("{{#figure", content)

    def test_reference_fingerprints_preserve_literal_examples(self):
        examples = (
            "`{{#figure fig-inline}}`\n"
            "`` {{#figure fig-inline-two}} ``\n"
            "````markdown\n{{#figure fig-code}}\n{{#figure-list}}\n````\n"
        )
        content = (
            examples
            + "See {{#figure fig-overview}}.\n\n{{#figure-list}}\n\n"
            + figure()
        )
        self.assertEqual(
            figures.reference_fingerprint(content), ["fig-overview", "figure-list"]
        )
        output = figures.preprocess({"sections": [chapter(content)]}, "en")["sections"][
            0
        ]["Chapter"]["content"]
        self.assertTrue(output.startswith(examples))
        self.assertIn("See [Figure\u00a01](#fig-overview).", output)

    def test_unknown_and_malformed_references_report_chapter_context(self):
        for content, message in [
            ("{{#figure fig-missing}}", "unknown figure fig-missing"),
            ("{{#figure}}", "malformed figure reference"),
            ("{{#figure fig-Capital}}", "malformed figure reference"),
            ("{{#figure fig-overview}", "malformed figure reference"),
            ("Text {{#figure-list}}", "figure-list marker must be on its own line"),
        ]:
            with (
                self.subTest(content=content),
                self.assertRaisesRegex(ValueError, "overview.md:1: " + message),
            ):
                figures.preprocess({"sections": [chapter(content)]}, "en")

    def test_mermaid_reference_lookalikes_are_preserved(self):
        content = figure().replace(
            "    A --> B", '    A["{{#figure fig-literal}}"] --> B'
        )
        self.assertEqual(figures.reference_fingerprint(content), [])
        output = figures.preprocess({"sections": [chapter(content)]}, "en")["sections"][
            0
        ]["Chapter"]["content"]
        self.assertIn('    A["{{#figure fig-literal}}"] --> B', output)

    def test_only_wrapper_and_caption_lines_change(self):
        before = (
            "# Overview {#overview}\n\nRun `lc hunt`.\n\n"
            + figure()
            + "\n```sh\nlc process --pcap-command 'gzip %pcap%'\n```\n"
        )
        after = figures.preprocess({"sections": [chapter(before)]}, "en")["sections"][
            0
        ]["Chapter"]["content"]
        changed = [
            (old, new)
            for old, new in zip(before.splitlines(), after.splitlines(), strict=True)
            if old != new
        ]
        self.assertEqual(len(changed), 2)
        self.assertTrue(changed[0][0].startswith("<figure"))
        self.assertTrue(changed[1][0].startswith("<figcaption"))
        self.assertIn("```mermaid\ngraph LR\n    A --> B\n```", after)

    def test_fenced_author_examples_are_ignored(self):
        example = "````markdown\n" + figure() + "````\n"
        self.assertEqual(figures.annotation_fingerprint(example), [])
        content = example + figure("fig-real")
        self.assertEqual(figures.annotation_fingerprint(content), ["fig-real"])
        output = figures.preprocess({"sections": [chapter(content)]}, "en")["sections"][
            0
        ]["Chapter"]["content"]
        self.assertTrue(output.startswith(example))
        self.assertIn("Figure\u00a01:", output)

    def test_reject_invalid_author_markup_with_chapter_context(self):
        examples = {
            "unwrapped": "```mermaid\ngraph LR\n A --> B\n```\n",
            "missing id": figure().replace(' id="fig-overview"', ""),
            "invalid id": figure("fig-Wrong"),
            "unclosed": figure().replace("</figure>", ""),
            "missing caption": figure().replace(
                "<figcaption>Overview of the nodes.</figcaption>", ""
            ),
            "empty caption": figure(caption=" <em></em>&nbsp; "),
            "duplicate caption": figure().replace(
                "</figure>", "<figcaption>Again.</figcaption>\n</figure>"
            ),
            "duplicate diagram": figure().replace(
                "<figcaption>", "```mermaid\ngraph LR\n A --> C\n```\n\n<figcaption>"
            ),
            "caption outside": "<figcaption>Caption.</figcaption>\n",
            "closing outside": "</figure>\n",
            "nested": figure().replace("</figure>", figure("fig-inner") + "</figure>"),
            "malformed caption": figure().replace(
                "</figcaption>", "</figcaption> trailing"
            ),
            "additional body": figure().replace("</figure>", "Extra text.\n</figure>"),
            "other code": figure().replace("```mermaid", "```sh"),
            "caption first": '<figure id="fig-first">\n<figcaption>First.</figcaption>\n',
            "duplicate image": image_figure().replace(
                "<figcaption>", "![Another image.](other.png)\n\n<figcaption>"
            ),
            "mixed media": figure().replace(
                "<figcaption>", "![Another image.](other.png)\n\n<figcaption>"
            ),
            "mixed media image first": image_figure().replace(
                "<figcaption>", "```mermaid\ngraph LR\n A --> B\n```\n\n<figcaption>"
            ),
            "empty alt": image_figure().replace(
                "Live packet list with packet details.", " &nbsp; "
            ),
            "malformed image": image_figure().replace("capture.png)", "capture.png"),
            "two images on a line": image_figure().replace(
                "capture.png)", "capture.png) ![Other.](other.png)"
            ),
            "image after caption": image_figure().replace(
                "</figure>", "![Other.](other.png)\n\n</figure>"
            ),
        }
        for name, content in examples.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, r"broken\.md:\d+:"),
            ):
                figures.parse_figures(content, "broken.md")

    def test_duplicate_ids_in_same_and_different_chapters(self):
        with self.assertRaisesRegex(ValueError, "duplicate figure identifier"):
            figures.parse_figures(figure() + figure())
        with self.assertRaisesRegex(
            ValueError, "later.md: duplicate figure identifier"
        ):
            figures.preprocess(
                {"sections": [chapter(figure()), chapter(figure(), "Later")]}, "en"
            )

    def test_generated_caption_ids_cannot_conflict_with_figure_ids(self):
        with self.assertRaisesRegex(ValueError, "generated caption ID"):
            figures.parse_figures(figure() + figure("fig-overview-caption"))
        for contents in [
            [figure(), figure("fig-overview-caption")],
            [figure("fig-overview-caption"), figure()],
        ]:
            with self.assertRaisesRegex(ValueError, "duplicate figure identifier"):
                figures.preprocess(
                    {"sections": [chapter(item) for item in contents]}, "en"
                )

    def test_cli_renderer_support_and_json_roundtrip(self):
        for renderer, exit_code in [("html", 0), ("pdf", 1), ("markdown", 1)]:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "supports", renderer],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, exit_code)
            self.assertEqual(result.stdout, "")
        context = {"renderer": "html", "config": {"book": {"language": "ca"}}}
        book = {"sections": [chapter(figure())]}
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps([context, book]),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertIn("Figura\u00a01:", output["sections"][0]["Chapter"]["content"])
        book["sections"][0]["Chapter"]["content"] = "```mermaid\nx\n```"
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps([context, book]),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("overview.md:", result.stderr)

    @unittest.skipUnless(shutil.which("mdbook"), "mdBook is not installed")
    def test_mdbook_renders_semantic_caption_and_print_number_without_js(self):
        with tempfile.TemporaryDirectory(prefix="lippycat-figures-test-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "SUMMARY.md").write_text(
                "# Summary\n\n- [Overview](overview.md)\n"
            )
            (root / "src" / "overview.md").write_text(
                "# Overview\n\n" + figure() + "\n" + image_figure()
            )
            (root / "book.toml").write_text(
                '[book]\ntitle = "Test figures"\nlanguage = "de"\nsrc = "src"\n'
                "[output.html]\n[preprocessor.figures]\n"
                f"command = {json.dumps(f'{sys.executable} {SCRIPT}')}\n"
            )
            result = subprocess.run(
                ["mdbook", "build", str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("overview.html", "print.html"):
                output = (root / "book" / name).read_text()
                self.assertIn('<figure id="fig-overview" aria-labelledby=', output)
                self.assertIn('class="figure-label">Abbildung\u00a01:</span>', output)
                self.assertIn('class="language-mermaid"', output)
                self.assertNotIn("```mermaid", output)
                self.assertIn('<figure id="fig-capture" aria-labelledby=', output)
                self.assertIn('class="figure-label">Abbildung\u00a02:</span>', output)
                self.assertIn(
                    '<img src="images/capture.png" alt="Live packet list with packet details."',
                    output,
                )

    @unittest.skipUnless(shutil.which("mdbook"), "mdBook is not installed")
    def test_mdbook_resolves_cross_references_and_list_in_chapters_and_print(self):
        with tempfile.TemporaryDirectory(
            prefix="lippycat-figure-links-test-"
        ) as directory:
            root = Path(directory)
            (root / "src" / "appendices").mkdir(parents=True)
            (root / "src" / "SUMMARY.md").write_text(
                "# Summary\n\n- [Overview](overview.md)\n"
                "- [Detail](detail.md)\n- [Figures](appendices/list.md)\n"
            )
            (root / "src" / "overview.md").write_text(
                "# Overview\n\nSee {{#figure fig-detail}} and {{#figure fig-overview}}.\n\n"
                + figure()
            )
            (root / "src" / "detail.md").write_text(
                "# Detail\n\n" + figure("fig-detail", "Details of the nodes.")
            )
            (root / "src" / "appendices" / "list.md").write_text(
                "# Figures\n\n{{#figure-list}}\n"
            )
            (root / "book.toml").write_text(
                '[book]\ntitle = "Test figures"\nlanguage = "en"\nsrc = "src"\n'
                "[output.html]\n[preprocessor.figures]\n"
                f"command = {json.dumps(f'{sys.executable} {SCRIPT}')}\n"
            )
            result = subprocess.run(
                ["mdbook", "build", str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            overview = (root / "book" / "overview.html").read_text()
            self.assertIn('href="detail.html#fig-detail">Figure\u00a02</a>', overview)
            self.assertIn('href="#fig-overview">Figure\u00a01</a>', overview)
            index = (root / "book" / "appendices" / "list.html").read_text()
            self.assertIn('href="../overview.html#fig-overview">Figure\u00a01:', index)
            self.assertIn('href="../detail.html#fig-detail">Figure\u00a02:', index)
            printed = (root / "book" / "print.html").read_text()
            self.assertIn('href="#fig-detail">Figure\u00a02</a>', printed)
            self.assertIn('href="#fig-overview">Figure\u00a01:', printed)
            self.assertIn('href="#fig-detail">Figure\u00a02:', printed)
            self.assertNotIn("{{#figure", printed)


if __name__ == "__main__":
    unittest.main()
