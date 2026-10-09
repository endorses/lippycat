"""Extract localized glossary hints and validate stable author annotations."""

import json
import re
from html.parser import HTMLParser

TERM_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


class Annotations(HTMLParser):
    """Fingerprint semantic attributes without freezing translated visible text."""

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.markers = []
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if "data-term" in attributes:
            self.markers.append(("term", attributes["data-term"]))
        if "data-no-term-hints" in attributes:
            self.markers.append(("exclude", attributes["data-no-term-hints"]))
        if "data-glossary-term" in attributes:
            self.markers.append(
                ("glossary", attributes["data-glossary-term"], attributes.get("id"))
            )

    handle_startendtag = handle_starttag


def annotation_fingerprint(text):
    return Annotations(text).markers


class Glossary(HTMLParser):
    """Read marked rows from mdBook's rendered glossary, preserving full text."""

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.in_main = False
        self.cells = None
        self.cell = None
        self.key = None
        self.data_row = False
        self.terms = {}
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "main":
            self.in_main = True
        if not self.in_main:
            return
        if tag == "tr":
            self.cells = []
            self.key = None
            self.data_row = False
        if tag in ("td", "th") and self.cells is not None:
            self.cell = []
            self.cells.append(self.cell)
            self.data_row = self.data_row or tag == "td"
        if tag in ("br", "p", "div", "li") and self.cell is not None:
            self.cell.append(" ")
        if "data-glossary-term" not in attributes:
            return
        key = attributes["data-glossary-term"]
        if not key or not TERM_ID.fullmatch(key):
            raise ValueError(f"Invalid glossary identifier: {key!r}")
        if tag != "span" or attributes.get("id") != f"term-{key}":
            raise ValueError(f'Glossary {key}: use span id="term-{key}"')
        if self.cells is None or len(self.cells) != 1 or self.cell is None:
            raise ValueError(f"Glossary {key}: marker must be in the term cell")
        if self.key is not None or key in self.terms:
            raise ValueError(f"Duplicate glossary identifier: {key}")
        self.key = key

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main = False
        if tag in ("p", "div", "li") and self.cell is not None:
            self.cell.append(" ")
        if tag in ("td", "th"):
            self.cell = None
        if tag == "tr" and self.cells is not None:
            if self.data_row and self.key is None:
                raise ValueError("Glossary row missing data-glossary-term identifier")
            if self.key is not None:
                if len(self.cells) != 2:
                    raise ValueError(
                        f"Glossary {self.key}: expected term/definition row"
                    )
                label, definition = [
                    " ".join("".join(cell).split()) for cell in self.cells
                ]
                if not label or not definition:
                    raise ValueError(f"Glossary {self.key}: empty label or definition")
                self.terms[self.key] = (label, definition)
            self.cells = None
            self.key = None

    def handle_data(self, data):
        if self.in_main and self.cell is not None:
            self.cell.append(data)


def load_policy(path, language_codes):
    policy = json.loads(path.read_text())
    if not isinstance(policy, dict) or not policy:
        raise ValueError("Term hint policy must be a nonempty object")
    for key, rule in policy.items():
        if not TERM_ID.fullmatch(key):
            raise ValueError(f"Invalid term hint policy identifier: {key!r}")
        if not isinstance(rule, dict):
            # Malformed JSON configuration is reported through the CLI's value errors.
            raise ValueError(
                f"Term hint {key}: policy must be an object"
            )  # noqa: TRY004
        for field in ("automatic", "caseSensitive"):
            if not isinstance(rule.get(field), bool):
                raise ValueError(
                    f"Term hint {key}: {field} must be a boolean"
                )  # noqa: TRY004
        aliases = rule.get("aliases")
        if not isinstance(aliases, dict):
            raise ValueError(
                f"Term hint {key}: aliases must map languages to lists"
            )  # noqa: TRY004
        for language, values in aliases.items():
            if language not in language_codes:
                raise ValueError(f"Term hint {key}: unknown alias language {language}")
            if not isinstance(values, list) or any(
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
                for value in values
            ):
                raise ValueError(
                    f"Term hint {key}/{language}: aliases must be nonempty strings"
                )
            if values and not rule["automatic"]:
                raise ValueError(
                    f"Term hint {key}: explicit-only terms cannot have aliases"
                )
    return policy


def dictionary(glossary_html, edition, policy):
    terms = Glossary(glossary_html).terms
    missing = sorted(set(policy) - set(terms))
    extra = sorted(set(terms) - set(policy))
    if missing or extra:
        raise ValueError(
            f"{edition['code']}: glossary/policy identifiers differ; missing={missing}, extra={extra}"
        )
    ui = edition.get("termHints")
    if not isinstance(ui, dict) or any(
        not isinstance(ui.get(key), str) or not ui[key].strip()
        for key in ("glossary", "close")
    ):
        raise ValueError(
            f"{edition['code']}: configure termHints glossary and close labels"
        )
    result = []
    seen = []
    for key, (label, definition) in terms.items():
        rule = policy[key]
        aliases = []
        if rule["automatic"]:
            for alias in [label, *rule["aliases"].get(edition["code"], [])]:
                if alias not in aliases:
                    aliases.append(alias)
        for alias in aliases:
            for previous_alias, previous_key, sensitive in seen:
                collision = (
                    alias == previous_alias
                    if sensitive and rule["caseSensitive"]
                    else alias.casefold() == previous_alias.casefold()
                )
                if collision and previous_key != key:
                    raise ValueError(
                        f"{edition['code']}: conflicting alias {alias!r} for {previous_key} and {key}"
                    )
            seen.append((alias, key, rule["caseSensitive"]))
        result.append(
            {
                "id": key,
                "label": label,
                "definition": definition,
                "aliases": aliases,
                "caseSensitive": rule["caseSensitive"],
                "href": f"appendices/glossary.html#term-{key}",
            }
        )
    return {"language": edition["code"], "ui": ui, "terms": result}


def generate(destination, edition, policy):
    path = destination / "appendices" / "glossary.html"
    data = dictionary(path.read_text(), edition, policy)
    for chapter in destination.rglob("*.html"):
        # At the root edition, only its own pages exist when generation runs.
        for marker in annotation_fingerprint(chapter.read_text()):
            if marker[0] == "term" and marker[1] not in policy:
                raise ValueError(
                    f"{edition['code']}: unknown explicit term {marker[1]!r} in {chapter.relative_to(destination)}"
                )
    (destination / "term-hints.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    )
    return {term["id"] for term in data["terms"]}
