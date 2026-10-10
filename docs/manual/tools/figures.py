"""Number semantic Mermaid figures before mdBook renders the manual."""

import copy
import html
import json
import posixpath
import re
import sys
from dataclasses import dataclass
from urllib.parse import quote

LABELS = {"en": "Figure", "de": "Abbildung", "ca": "Figura"}
OPENING = re.compile(r'<figure id="(fig-[a-z][a-z0-9]*(?:-[a-z0-9]+)*)">')
CAPTION = re.compile(r"<figcaption>(.*?)</figcaption>")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
REFERENCE = re.compile(r"\{\{#figure (fig-[a-z][a-z0-9]*(?:-[a-z0-9]+)*)\}\}")
LIST_MARKER = "{{#figure-list}}"
INLINE_CODE = re.compile(r"(?<!`)(`+)(?!`)(.*?)\1(?!`)")


@dataclass(frozen=True)
class Figure:
    identifier: str
    opening: int
    caption: int
    text: str


@dataclass(frozen=True)
class Reference:
    identifier: str
    line: int
    start: int
    end: int


def parse_references(content, chapter="<content>"):
    """Find author references in prose, preserving fenced and inline examples."""
    references = []
    fence = None
    for index, line in enumerate(content.splitlines(keepends=True)):
        if fence is not None:
            character, length = fence
            if re.fullmatch(rf" {{0,3}}{re.escape(character)}{{{length},}}\s*", line):
                fence = None
            continue
        match = FENCE.match(line)
        if match:
            marker, info = match.groups()
            if marker[0] != "`" or "`" not in info:
                fence = (marker[0], len(marker))
                continue
        code = [(match.start(), match.end()) for match in INLINE_CODE.finditer(line)]
        for candidate in re.finditer(r"\{\{#figure", line):
            start = candidate.start()
            if any(begin <= start < end for begin, end in code):
                continue
            if line.startswith(LIST_MARKER, start):
                if line.strip() != LIST_MARKER:
                    raise ValueError(
                        f"{chapter}:{index + 1}: figure-list marker must be on its own line"
                    )
                references.append(
                    Reference("figure-list", index, start, start + len(LIST_MARKER))
                )
            else:
                match = REFERENCE.match(line, start)
                if match is None:
                    raise ValueError(
                        f"{chapter}:{index + 1}: malformed figure reference"
                    )
                references.append(Reference(match.group(1), index, start, match.end()))
    return references


def reference_fingerprint(content):
    """Ordered referenced IDs; figure-list is a sentinel for the list placeholder."""
    return [reference.identifier for reference in parse_references(content)]


def parse_figures(content, chapter="<content>"):
    """Validate author markup, ignoring syntax inside ordinary fenced examples."""
    figures = []
    identifiers = set()
    current = None
    fence = None
    diagram_count = 0
    caption = None

    def fail(message, line):
        raise ValueError(f"{chapter}:{line + 1}: {message}")

    for index, line in enumerate(content.splitlines(keepends=True)):
        stripped = line.strip()
        if fence is not None:
            character, length, mermaid = fence
            if re.fullmatch(rf" {{0,3}}{re.escape(character)}{{{length},}}\s*", line):
                fence = None
            continue

        match = FENCE.match(line)
        if match:
            marker, info = match.groups()
            if marker[0] == "`" and "`" in info:
                continue
            mermaid = info.strip().split()[:1] == ["mermaid"]
            if mermaid:
                if info.strip() != "mermaid":
                    fail("use a plain mermaid fence for figures", index)
                if current is None:
                    fail("Mermaid diagram must be wrapped in a numbered figure", index)
                if caption is not None:
                    fail("figure caption must follow its diagram", index)
                diagram_count += 1
                if diagram_count > 1:
                    fail("figure must contain exactly one Mermaid diagram", index)
            elif current is not None:
                fail("figure may contain only a Mermaid diagram and its caption", index)
            fence = (marker[0], len(marker), mermaid)
            continue

        if re.search(r"<figure\b", stripped):
            if current is not None:
                fail("nested figure wrappers are not supported", index)
            opening = OPENING.fullmatch(stripped)
            if not opening:
                fail('use <figure id="fig-descriptive-id"> on its own line', index)
            identifier = opening.group(1)
            if identifier in identifiers:
                fail(f"duplicate figure identifier {identifier}", index)
            identifiers.add(identifier)
            current = (identifier, index)
            diagram_count = 0
            caption = None
        elif "<figcaption" in stripped or "</figcaption" in stripped:
            if current is None:
                fail("figure caption is outside a figure", index)
            matched = CAPTION.fullmatch(stripped)
            if matched is None:
                fail("use one complete figcaption on its own line", index)
            if caption is not None:
                fail("figure must contain exactly one caption", index)
            text = matched.group(1)
            visible = html.unescape(re.sub(r"<[^>]*>", "", text)).strip()
            if not visible:
                fail("figure caption must not be empty", index)
            if diagram_count != 1:
                fail("figure caption must follow exactly one Mermaid diagram", index)
            caption = (index, text)
        elif "</figure" in stripped:
            if stripped != "</figure>" or current is None:
                fail("unmatched or malformed figure closing tag", index)
            if diagram_count != 1 or caption is None:
                fail(
                    "figure requires exactly one Mermaid diagram and one caption", index
                )
            figures.append(Figure(*current, *caption))
            current = None
        elif current is not None and stripped not in ("", "<!-- i18n:skip -->"):
            fail("figure may contain only a Mermaid diagram and its caption", index)

    if current is not None:
        fail("unclosed figure or Mermaid fence", current[1])
    if fence is not None and fence[2]:
        fail("unclosed Mermaid fence", len(content.splitlines()))
    for figure in figures:
        if f"{figure.identifier}-caption" in identifiers:
            fail(
                "figure identifier conflicts with a generated caption ID",
                figure.opening,
            )
    return figures


def annotation_fingerprint(content):
    """Stable figure identifiers for source/translation invariant checks."""
    return [figure.identifier for figure in parse_figures(content)]


def preprocess(book, language):
    """Return a copy with continuous numbering in chapter reading order."""
    if language not in LABELS:
        raise ValueError(f"unsupported figure language: {language!r}")
    result = copy.deepcopy(book)
    identifiers = set()
    catalog = {}
    chapters = []

    def visit(sections):
        for section in sections:
            if "Chapter" not in section:
                continue
            chapter = section["Chapter"]
            context = chapter.get("source_path") or chapter.get("name", "<chapter>")
            content = chapter["content"]
            parsed = parse_figures(content, context)
            path = chapter.get("path") or chapter.get("source_path")
            if path is None and parsed:
                raise ValueError(f"{context}: numbered figure needs a chapter path")
            chapters.append((chapter, context, path, parsed))
            for figure in parsed:
                caption_id = f"{figure.identifier}-caption"
                if figure.identifier in identifiers or caption_id in identifiers:
                    raise ValueError(
                        f"{context}: duplicate figure identifier {figure.identifier}"
                    )
                identifiers.update((figure.identifier, caption_id))
                catalog[figure.identifier] = (len(catalog) + 1, path, figure.text)
            visit(chapter.get("sub_items", []))

    # mdBook 0.5 renamed the serialized root collection from sections to items.
    visit(result["items"] if "items" in result else result["sections"])

    def href(source, target, identifier):
        if source == target:
            return f"#{identifier}"
        relative = posixpath.relpath(target, posixpath.dirname(source) or ".")
        return f"{quote(relative, safe='/.-')}#{identifier}"

    for chapter, context, path, parsed in chapters:
        content = chapter["content"]
        references = parse_references(content, context)
        lines = content.splitlines(keepends=True)
        for reference in reversed(references):
            if path is None:
                raise ValueError(f"{context}: figure reference needs a chapter path")
            if reference.identifier == "figure-list":
                links = []
                for identifier, (number, target, caption) in catalog.items():
                    visible = " ".join(
                        html.unescape(re.sub(r"<[^>]*>", "", caption)).split()
                    )
                    escaped = re.sub(r"([\\`*_{}\[\]()#+.!<>|])", r"\\\1", visible)
                    links.append(
                        f"- [{LABELS[language]} {number}: {escaped}]({href(path, target, identifier)})"
                    )
                replacement = (
                    '<div class="figure-list">\n\n' + "\n".join(links) + "\n\n</div>"
                )
            else:
                if reference.identifier not in catalog:
                    raise ValueError(
                        f"{context}:{reference.line + 1}: unknown figure {reference.identifier}"
                    )
                number, target, _caption = catalog[reference.identifier]
                replacement = f"[{LABELS[language]} {number}]({href(path, target, reference.identifier)})"
            line = lines[reference.line]
            lines[reference.line] = (
                line[: reference.start] + replacement + line[reference.end :]
            )

        # Number figures only after reference replacement; list expansions can
        # add lines, so use original figure offsets before joining the chapter.
        for figure in parsed:
            number, _target, _caption = catalog[figure.identifier]
            caption_id = f"{figure.identifier}-caption"
            opening_ending = "\n" if lines[figure.opening].endswith("\n") else ""
            caption_ending = "\n" if lines[figure.caption].endswith("\n") else ""
            lines[figure.opening] = (
                f'<figure id="{figure.identifier}" aria-labelledby="{caption_id}" '
                f'data-figure-number="{number}">{opening_ending}'
            )
            lines[figure.caption] = (
                f'<figcaption id="{caption_id}"><span class="figure-label">'
                f"{LABELS[language]} {number}:</span> {figure.text}</figcaption>{caption_ending}"
            )
        chapter["content"] = "".join(lines)
    return result


def main():
    if len(sys.argv) > 1:
        if len(sys.argv) == 3 and sys.argv[1] == "supports":
            return 0 if sys.argv[2] == "html" else 1
        print("usage: figures.py [supports html]", file=sys.stderr)
        return 1
    try:
        context, book = json.load(sys.stdin)
        language = context["config"]["book"].get("language", "en")
        if context.get("renderer") != "html":
            raise ValueError("numbered figures support only the html renderer")
        result = preprocess(book, language)
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    except (ValueError, KeyError, TypeError) as error:
        print(f"numbered figures: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
