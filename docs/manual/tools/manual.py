#!/usr/bin/env python3
"""Build and maintain the manual's language editions using one source tree."""

import argparse
import ast
import contextlib
import gettext
import http.server
import json
import os
import re
import shutil
import subprocess
import tempfile
from functools import partial
from html.parser import HTMLParser
from pathlib import Path

import term_hints

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "book"


def languages():
    editions = json.loads((ROOT / "languages.json").read_text())
    codes = [edition["code"] for edition in editions]
    if not editions or "en" not in codes or len(codes) != len(set(codes)):
        raise ValueError("Configure English and use unique language codes")
    if editions[0]["path"] != "":
        raise ValueError("Configure the root edition first with an empty path")
    for index, edition in enumerate(editions):
        code = edition["code"]
        if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]+)*", code):
            raise ValueError(f"Invalid language code: {code}")
        if edition["path"] != ("" if index == 0 else f"{code}/"):
            raise ValueError(f"Use a single language directory for {code}")
        for key in ("name", "title", "description"):
            if not isinstance(edition[key], str) or not edition[key]:
                raise ValueError(f"Missing {key} for {code}")
    return editions


def run(args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, cwd=ROOT, **kwargs)


def environment(edition):
    env = os.environ.copy()
    env.update(
        MDBOOK_BOOK__LANGUAGE=edition["code"],
        MDBOOK_BOOK__TITLE=edition["title"],
        MDBOOK_BOOK__DESCRIPTION=edition["description"],
        MDBOOK_OUTPUT__HTML__SITE_URL=f"https://lippy.cat/{edition['path']}",
    )
    if edition["code"] != "en":
        env["MDBOOK_OUTPUT__HTML__EDIT_URL_TEMPLATE"] = (
            f"https://github.com/endorses/lippycat/edit/main/docs/manual/po/{edition['code']}.po"
        )
    return env


class Chapter(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.language = None
        self.heading_ids = []
        self.links = []
        self.examples = []
        self.code_spans = []
        self.term_markers = term_hints.annotation_fingerprint(path.read_text())
        self.in_main = False
        self.in_pre = False
        self.in_code = False
        self.feed(path.read_text())

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "html":
            self.language = attributes.get("lang")
        if tag == "main":
            self.in_main = True
        if not self.in_main:
            return
        if re.fullmatch(r"h[1-6]", tag):
            self.heading_ids.append(attributes.get("id"))
        if tag == "a":
            self.links.append(attributes.get("href"))
        if tag == "pre":
            self.in_pre = True
            self.examples.append("")
        if tag == "code" and not self.in_pre:
            self.in_code = True
            self.code_spans.append("")

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main = False
        elif tag == "pre":
            self.in_pre = False
        elif tag == "code":
            self.in_code = False

    def handle_data(self, data):
        if self.in_main and self.in_pre:
            self.examples[-1] += data
        elif self.in_main and self.in_code:
            self.code_spans[-1] += data


def verify_build(editions):
    english = next(edition for edition in editions if edition["code"] == "en")
    for source in (ROOT / "src").rglob("*.md"):
        if source.name == "SUMMARY.md":
            continue
        chapter = source.relative_to(ROOT / "src").with_suffix(".html")
        original = Chapter(OUTPUT / english["path"] / chapter)
        if original.language != "en":
            raise ValueError(f"en: wrong HTML language in {chapter}")
        for edition in editions:
            if edition["code"] == "en":
                continue
            translated = Chapter(OUTPUT / edition["path"] / chapter)
            if translated.language != edition["code"]:
                raise ValueError(f"{edition['code']}: wrong HTML language in {chapter}")
            for field in (
                "heading_ids",
                "examples",
                "links",
                "code_spans",
                "term_markers",
            ):
                before, after = getattr(original, field), getattr(translated, field)
                if field in ("links", "code_spans"):
                    before, after = sorted(before), sorted(after)
                if before != after:
                    raise ValueError(f"{edition['code']}: changed {field} in {chapter}")
    print(
        "Verified chapter paths, heading IDs, examples, code spans, links, and term annotations across editions",
        flush=True,
    )


def build():
    editions = languages()
    policy = term_hints.load_policy(
        ROOT / "term-hints.json", {edition["code"] for edition in editions}
    )
    glossary_ids = None
    # The root edition must run first: its clean build removes the output tree.
    with tempfile.TemporaryDirectory(prefix="lippycat-manual-") as directory:
        for edition in editions:
            env = environment(edition)
            if edition["code"] != "en":
                catalog = ROOT / "po" / f"{edition['code']}.po"
                if not catalog.is_file():
                    raise ValueError(f"Missing catalog for {edition['code']}")
                # The pinned helper drops fuzzy flags when normalizing SUMMARY
                # titles. Remove those entries so every message falls back to
                # English until reviewed, including navigation and headings.
                sanitized = Path(directory) / catalog.name
                run(
                    [
                        "msgattrib",
                        "--no-fuzzy",
                        "--no-obsolete",
                        "-o",
                        sanitized,
                        catalog,
                    ]
                )
                env["MDBOOK_PREPROCESSOR__GETTEXT__PO_DIR"] = directory
            destination = OUTPUT / edition["path"]
            run(["mdbook", "build", ROOT, "-d", destination], env=env)
            shutil.copyfile(ROOT / "languages.json", destination / "languages.json")
            edition_ids = term_hints.generate(destination, edition, policy)
            if glossary_ids is not None and edition_ids != glossary_ids:
                raise ValueError(f"{edition['code']}: changed glossary identifiers")
            glossary_ids = edition_ids
    verify_build(editions)


def extract():
    env = os.environ.copy()
    env["MDBOOK_BOOK__LANGUAGE"] = "en"
    env["MDBOOK_OUTPUT"] = '{"xgettext": {}}'
    run(["mdbook", "build", ROOT, "-d", ROOT / "po"], env=env)
    return ROOT / "po" / "messages.pot"


def update():
    template = extract()
    for edition in languages():
        if edition["code"] == "en":
            continue
        catalog = ROOT / "po" / f"{edition['code']}.po"
        if catalog.exists():
            run(["msgmerge", "--update", "--backup=none", catalog, template])
        else:
            run(
                [
                    "msginit",
                    "--no-translator",
                    "-i",
                    template,
                    "-l",
                    edition["code"],
                    "-o",
                    catalog,
                ]
            )


def entries(path):
    """Read singular messages for invariant checks; msgfmt validates PO syntax."""
    result = []
    current = None
    field = None
    for line in path.read_text().splitlines():
        if line.startswith("msgid "):
            current = {"msgid": ast.literal_eval(line[6:]), "msgstr": ""}
            result.append(current)
            field = "msgid"
        elif line.startswith("msgstr "):
            field = "msgstr"
            current[field] = ast.literal_eval(line[7:])
        elif line.startswith('"') and current is not None:
            current[field] += ast.literal_eval(line)
    return result


def check(require_complete=False):
    template = extract()
    expected = {entry["msgid"] for entry in entries(template) if entry["msgid"]}
    for edition in languages():
        if edition["code"] == "en":
            continue
        catalog = ROOT / "po" / f"{edition['code']}.po"
        run(["msgfmt", "--check", "--statistics", "-o", os.devnull, catalog])
        # Merge into a temporary file to detect new/changed English messages
        # without modifying contributors' catalogs during CI.
        with tempfile.TemporaryDirectory(prefix="lippycat-manual-") as directory:
            merged = Path(directory) / "merged.po"
            run(
                [
                    "msgmerge",
                    "--quiet",
                    "--no-fuzzy-matching",
                    "-o",
                    merged,
                    catalog,
                    template,
                ]
            )
            compiled = Path(directory) / "merged.mo"
            run(["msgfmt", "-o", compiled, merged])
            with compiled.open("rb") as stream:
                available = gettext.GNUTranslations(stream)._catalog
            missing = sum(message not in available for message in expected)
        print(
            f"{edition['code']}: {len(expected) - missing}/{len(expected)} current messages translated",
            flush=True,
        )
        if missing and require_complete:
            raise ValueError(f"{edition['code']}: {missing} messages need translation")
        # Check only active current translations: fuzzy text can retain old
        # commands/links while the rendered book correctly uses English.
        for source in expected:
            translation = available.get(source)
            if not translation:
                continue
            # Code spans and explicit Markdown link targets must stay verbatim.
            for pattern in (r"`+[^`]+`+", r"\]\(([^\s)]+)"):
                if sorted(re.findall(pattern, source)) != sorted(
                    re.findall(pattern, translation)
                ):
                    raise ValueError(
                        f"{edition['code']}: changed code or link target in {source!r}"
                    )
            if term_hints.annotation_fingerprint(
                source
            ) != term_hints.annotation_fingerprint(translation):
                raise ValueError(
                    f"{edition['code']}: changed term annotations in {source!r}"
                )


def serve(port):
    build()
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(OUTPUT))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as server:
        for edition in languages():
            print(
                f"{edition['name']}: http://localhost:{port}/{edition['path']}",
                flush=True,
            )
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["build", "extract", "update", "check", "serve"]
    )
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()
    try:
        if args.command == "check":
            check(args.require_complete)
        elif args.command == "serve":
            serve(args.port)
        else:
            {"build": build, "extract": extract, "update": update}[args.command]()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Manual: {error}\n")


if __name__ == "__main__":
    main()
