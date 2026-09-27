# Building and translating the manual

English Markdown in `src/` is the authoritative source. German translations live
in `po/de.po`. Every edition shares chapter filenames, examples, diagrams, and
explicit heading IDs. English is published at the existing site root; German is
published at `/de/`. Generated HTML and translation templates are not committed.

## Tools

Install Python 3, GNU Gettext (`msginit`, `msgmerge`, `msgfmt`, `msgcat`, `msgattrib`), and a
current Rust toolchain. On Linux x86_64, install the pinned mdBook tools with:

```bash
bash docs/manual/tools/install.sh "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

The installer pins mdBook, mdbook-mermaid, and mdbook-i18n-helpers in one place
for both local builds and CI. The translation helpers use a pinned Git revision
because released versions target mdBook 0.4, while this manual uses mdBook 0.5.
On other platforms, build the same versions with Cargo (see the installer for
version numbers and the exact translation-helper revision).

## Build and preview

Run these commands from the repository root:

```bash
make manual                # Build English and every configured translation
make manual-check          # Validate catalogs and report translation coverage
make manual-serve          # Build and serve the whole site on localhost:3000
make manual-serve MANUAL_PORT=3001
```

Open `http://localhost:3000/` for English or `http://localhost:3000/de/` for German.
The language selector preserves the current chapter, heading fragment, and query
string. The preview server binds to localhost. Rebuild/restart it after edits;
it serves the assembled site rather than providing mdBook's single-edition live
reload. `make manual-clean` removes generated HTML.

GitHub Actions builds all configured editions into one Pages artifact. The CNAME
stays at the artifact root. Pull-request checks validate catalogs and build both
editions without publishing them.

## Updating translations

After editing the English source:

```bash
make manual-translations
```

This regenerates the ignored `po/messages.pot` template and merges it into each
catalog. Existing translations are retained; new entries are empty and changed
entries may be marked **fuzzy** (needing review). Use a PO editor or carefully
edit `msgstr` values. Do not edit `msgid` values: fix the English source instead.

Review changed entries against their English text, then remove the fuzzy marker.
Missing and fuzzy translations render in English. The build filters fuzzy entries
from temporary copies of the catalogs, including chapter titles; it never changes
the committed catalogs. CI reports coverage so English
changes can ship while translation updates follow separately. To require a fully
translated current manual, run:

```bash
python3 docs/manual/tools/manual.py check --require-complete
```

Catalog checks run regression tests for fuzzy fallback, validate Gettext syntax,
and preserve inline code and Markdown link targets. They do not replace a review of technical meaning and German wording.
Avoid unrelated catalog reformatting; `msgcat --sort-by-file` provides standard PO
formatting when needed. `make manual-extract` only regenerates the template.

## German conventions

Use formal **Sie**, **Ihnen**, and **Ihr** when addressing readers directly.
Prefer neutral phrasing when it reads naturally. Never mix formal and informal
address. For example: “Starten Sie den Prozessor mit folgendem Befehl.”

Use clear technical German and retain established acronyms such as CLI, TUI,
PCAP, TLS, SIP, and RTP. Keep these terms consistent:

| English                  | German                                         |
| ------------------------ | ---------------------------------------------- |
| packet capture (process) | Paketerfassung                                 |
| capture (result)         | Paketmitschnitt / Mitschnitt                   |
| capture file             | Mitschnittdatei / PCAP-Datei                   |
| packet                   | Paket                                          |
| processor                | Prozessor                                      |
| hunter node              | Hunter-Knoten                                  |
| tap node                 | Tap-Knoten                                     |
| network interface        | Netzwerkschnittstelle                          |
| network segment          | Netzwerksegment                                |
| protocol analysis        | Protokollanalyse                               |
| LI delivery              | Ausleitung                                     |
| data/event delivery      | Übermittlung                                   |
| lawful interception      | rechtmäßige Telekommunikationsüberwachung (LI) |

Distinguish the process from its result: use **Paketerfassung** or **Pakete
erfassen** for the activity, and **Paketmitschnitt**, **Mitschnitt**, or
**Mitschnittdatei** for captured data and saved files. For example, “Starten Sie
die Paketerfassung”, but “Öffnen Sie den gespeicherten Mitschnitt”. Avoid
“gespeicherte Erfassungen” and “Erfassungsdateien”. In an already clear context,
“Erfassung” is sufficient for the process.

For lawful interception, translate **delivery** as **Ausleitung** (for example,
“X2-IRI-Ausleitung” and “X3-CC-Ausleitung”). Use **Übermittlung** for general
data/event transport and when describing the transmission itself. Avoid
“Auslieferung” in the LI context. Keep technical identifiers such as
`--li-delivery-*` and `delivery_type` unchanged. The Bundesnetzagentur uses
“Ausleitung” for interception copies and IRI data in its
[TR TKÜV terminology](https://www.bundesnetzagentur.de/DE/Allgemeines/Presse/Amtsblatt/Einzeldownloads/Amtsblatt_26_5.pdf?__blob=publicationFile&v=3).

Translate prose, headings, chapter titles, and descriptive table cells. Preserve
command names, flags, configuration keys, environment variables, paths, protocol
identifiers, and link destinations. Fenced blocks use `<!-- i18n:skip -->` so
commands, configuration examples, expected output, and Mermaid diagrams remain
identical across languages. Explain examples in the surrounding translated prose.

Retain explicit `{#heading-id}` attributes when renaming headings. For a new
heading, choose an explicit stable ID before translating it. These IDs preserve
existing English fragment URLs and cross-language navigation.

## Adding another language

- [ ] Add an entry to `languages.json` with its code, native name, `<code>/` path,
      translated title, and description. Keep English first with an empty path.
- [ ] Run `make manual-translations` to initialize `po/<code>.po`.
- [ ] Translate the catalog and document any language-specific style conventions.
- [ ] Run `make manual-check manual` and preview navigation, search, and diagrams.

The build, deployment, and language selector discover editions from this manifest;
there is no separate workflow or source tree to maintain for each language.
