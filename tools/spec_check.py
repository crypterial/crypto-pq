"""Checks the specification under spec/: links and anchors, decision and principle references,
citation tags, table shapes, section numbering and the use of the requirement keywords."""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SPEC = os.path.join(ROOT, "spec")

CHAPTERS = [
    "00-contents.md", "01-introduction.md", "02-terminology.md", "03-principles.md", "04-scope.md",
    "05-algorithms.md", "06-api.md", "07-errors.md", "08-key-encapsulation.md", "09-signatures.md",
    "10-key-formats.md", "11-stateful-signatures.md", "12-symmetric-primitives.md", "13-hazmat.md",
    "14-security.md", "15-platforms.md", "16-naming.md", "17-implementation-conventions.md",
    "18-testing.md", "19-conformance.md", "20-versioning.md", "21-references.md",
    "22-profile-rules.md", "profiles/rust.md", "decisions.md", "principles-review.md",
]

# The profiles of the other languages are maintained with their implementations; this repository
# holds the Rust one.
PROFILES = {"rust": 23}

LINK_RE = re.compile(r"\[([^\[\]]*)\]\(([^)\s]*)\)")

failures = []


def fail(message):
    failures.append(message)

    print("FAIL", message)


def read(path):
    with open(path, encoding="utf-8") as file:
        return file.read()


def slug(title):
    text = LINK_RE.sub(r"\1", title).strip().lower()

    text = re.sub(r"[^\w\- ]", "", text)

    return text.replace(" ", "-")


def anchors_of(path):
    seen, result = {}, set()

    for line in read(path).split("\n"):
        match = re.match(r"^#{1,6} (.*)$", line)

        if not match:
            continue

        base = slug(match.group(1))

        count = seen.get(base, 0)

        seen[base] = count + 1

        result.add(base if count == 0 else f"{base}-{count}")

    return result


def unfenced(lines):
    """Yields (number, line) for every line outside fenced code blocks."""
    fence = False

    for number, line in enumerate(lines, 1):
        if line.strip().startswith("```"):
            fence = not fence

            continue

        if not fence:
            yield number, line


def plain_segments(line):
    pieces = line.split("`")

    return [pieces[i] for i in range(0, len(pieces), 2)]


def all_markdown():
    found = [os.path.join(ROOT, name) for name in os.listdir(ROOT) if name.endswith(".md")]

    for root, _dirs, names in os.walk(SPEC):
        found += [os.path.join(root, name) for name in names if name.endswith(".md")]

    return sorted(found)


def chapter(name):
    return read(os.path.join(SPEC, name))


def check_files():
    present = {
        os.path.relpath(os.path.join(root, name), SPEC).replace(os.sep, "/")
        for root, _dirs, names in os.walk(SPEC)
        for name in names
        if name.endswith(".md")
    }

    expected = set(CHAPTERS) | {"VERSIONS.md"}

    for name in sorted(expected - present):
        fail(f"missing {name}")

    for name in sorted(present - expected):
        fail(f"unlisted file {name}")

    print(f"files: {len(present)} present, {len(expected)} expected")


def check_links():
    total = 0

    for path in all_markdown():
        for number, line in unfenced(read(path).split("\n")):
            for segment in plain_segments(line):
                for _text, url in LINK_RE.findall(segment):
                    total += 1

                    if re.match(r"^[a-z]+:", url):
                        continue

                    file_part, _, anchor = url.partition("#")

                    target = os.path.normpath(os.path.join(os.path.dirname(path), file_part)) if file_part else path

                    if not os.path.isfile(target):
                        fail(f"{path}:{number}: missing file {url}")
                    elif anchor and anchor not in anchors_of(target):
                        fail(f"{path}:{number}: missing anchor {url}")

    print(f"links: {total} checked")


# Lists section numbers of this text written without their link; informational only.
def check_unlinked_references():
    sections, chapters = set(), set()

    for name in CHAPTERS:
        for line in chapter(name).split("\n"):
            match = re.match(r"^#{1,4} (\d+)((?:\.\d+)*)[. ]", line)

            if match:
                (sections if match.group(2) else chapters).add(match.group(1) + match.group(2))

    token_re = re.compile(r"(?<![\w.§/\-′^])(\d{1,2}(?:\.\d{1,2}){1,2})(?![\w′]|\.\d)")

    leftovers = []

    for name in CHAPTERS:
        for number, line in unfenced(chapter(name).split("\n")):
            if line.startswith("#"):
                continue

            for segment in plain_segments(line):
                bare = LINK_RE.sub("", segment)

                for match in token_re.finditer(bare):
                    if match.group(1) in sections:
                        leftovers.append(f"{name}:{number}: {bare[max(0, match.start() - 25):match.end() + 10].strip()}")

                for match in re.finditer(r"Sections? (\d+)\b(?!\.\d)", bare):
                    if match.group(1) in chapters:
                        leftovers.append(f"{name}:{number}: unlinked '{match.group(0)}'")

    print(f"section-number tokens without a link, to review (versions and steps also match): {len(leftovers)}")

    for item in leftovers:
        print("  ", item)


def check_decisions():
    text = chapter("decisions.md")

    defined = re.findall(r"^## Decision (D-\d\d)", text, re.M)

    expected = [f"D-{n:02d}" for n in range(1, len(defined) + 1)]

    if defined != expected:
        fail(f"decisions.md defines {defined}, not D-01 to D-{len(defined):02d} in order")

    referenced = set()

    for path in all_markdown():
        for line in read(path).split("\n"):
            for segment in plain_segments(line):
                referenced.update(re.findall(r"(?<![\w\-])(D-\d\d)(?!\d)", LINK_RE.sub(r"\1", segment)))

    missing = sorted(referenced - set(defined))

    if missing:
        fail(f"decisions referenced but not defined: {missing}")

    print(f"decisions: {len(defined)} defined, {len(referenced)} referenced")


def check_principles_and_citations():
    defined = set(re.findall(r"^\| (P\d+) \|", chapter("03-principles.md"), re.M))

    tags = set()

    for row in re.findall(r"^\| (\[[^|]*\]) \|", chapter("21-references.md"), re.M):
        tags.update(re.findall(r"\[([A-Z0-9][A-Za-z0-9.\-]*)\]", row))

    used_principles, used_tags = set(), set()

    for name in CHAPTERS:
        for _number, line in unfenced(chapter(name).split("\n")):
            for segment in plain_segments(line):
                bare = LINK_RE.sub(r"\1", segment)

                used_principles.update(re.findall(r"\b(P\d+)\b", bare))

                used_tags.update(re.findall(r"\[([A-Z][A-Z0-9.\-]+)\](?!\()", bare))

    used_tags = {tag for tag in used_tags if not re.fullmatch(r"D-\d\d", tag)}

    if used_principles - defined:
        fail(f"principles referenced but not defined: {sorted(used_principles - defined)}")

    if used_tags - tags:
        fail(f"citation tags without a reference entry: {sorted(used_tags - tags)}")

    print(f"principles: {len(defined)} defined; citations: {len(used_tags)} tags used")


def cells(row):
    row = row.strip()

    if row.startswith("|"):
        row = row[1:]

    if row.endswith("|") and not row.endswith("\\|"):
        row = row[:-1]

    return len(re.split(r"(?<!\\)\|", row))


def check_markdown():
    tables = 0

    for path in all_markdown():
        raw = read(path).split("\n")

        kept = {number for number, _line in unfenced(raw)}

        lines = [line if number in kept else "" for number, line in enumerate(raw, 1)]

        if sum(1 for line in raw if line.strip().startswith("```")) % 2:
            fail(f"{path}: unbalanced code fence")

        index = 0

        while index < len(lines):
            line = lines[index]

            following = lines[index + 1] if index + 1 < len(lines) else ""

            if line.lstrip().startswith("|") and re.match(r"^\s*\|(\s*:?-+:?\s*\|)+\s*$", following):
                tables += 1

                width = cells(line)

                if cells(following) != width:
                    fail(f"{path}:{index + 2}: separator has {cells(following)} cells, header {width}")

                index += 2

                while index < len(lines) and lines[index].lstrip().startswith("|"):
                    if cells(lines[index]) != width:
                        fail(f"{path}:{index + 1}: row has {cells(lines[index])} cells, header {width}")

                    index += 1

                continue

            if line.lstrip().startswith("|") and not (index > 0 and lines[index - 1].lstrip().startswith("|")):
                fail(f"{path}:{index + 1}: table row without a separator line")

            index += 1

        for block in re.split(r"\n\s*\n", "\n".join(lines)):
            if block.count("`") % 2:
                fail(f"{path}: block with an odd number of backticks: {block[:60]}")

        for number, line in unfenced(lines):
            for segment in plain_segments(line):
                bare = LINK_RE.sub(r"\1", segment).replace("**", "")

                if re.search(r"(?<!\\)\*", bare):
                    fail(f"{path}:{number}: bare asterisk may render as emphasis: {bare.strip()[:80]}")

                if "~~" in bare:
                    fail(f"{path}:{number}: '~~' renders as strikethrough")

                if re.search(r"<[A-Za-z/!]", bare):
                    fail(f"{path}:{number}: raw HTML-like text: {bare.strip()[:80]}")

    print(f"markdown: {tables} tables checked")


def check_structure():
    front = chapter("00-contents.md")

    wanted = {
        "title": front.startswith("# crypto-pq Specification"),
        "version, status, date and license rows": all(f"| {row} |" in front for row in ("Version", "Status", "Date", "License")),
        "abstract": "## Abstract" in front,
        "contents": "## Contents" in front,
        "quick reference": "Quick reference" in front,
        "introduction: purpose, audience, structure, how to read": all(
            heading in chapter("01-introduction.md")
            for heading in ("## 1.1 Purpose", "## 1.2 Audience", "## 1.3 Structure", "## 1.5 How to read this document")
        ),
        "conventions and terminology": "## 2.2 Terms" in chapter("02-terminology.md"),
        "security considerations": "## 14.8 Security considerations" in chapter("14-security.md"),
        "normative and informative references": "## 21.1 Normative references" in chapter("21-references.md")
        and "## 21.2 Informative references" in chapter("21-references.md"),
        "appendices A and B": chapter("decisions.md").startswith("# Appendix A.")
        and chapter("principles-review.md").startswith("# Appendix B."),
    }

    for name, ok in wanted.items():
        if not ok:
            fail(f"structure: missing {name}")

    numbered = sorted(name for name in CHAPTERS if re.match(r"\d\d-.*\.md$", name))

    for name in numbered[1:]:
        if not chapter(name).startswith(f"# {int(name[:2])}. "):
            fail(f"structure: {name} does not start with Section {int(name[:2])}")

    for name, number in PROFILES.items():
        if not chapter(f"profiles/{name}.md").startswith(f"# {number}. "):
            fail(f"structure: profiles/{name}.md does not start with Section {number}")

    print(f"structure: {sum(wanted.values())}/{len(wanted)} parts, {len(numbered) - 1} sections and {len(PROFILES)} profile numbered")


# BCP 14 keywords in capitals in the normative text only; their lowercase forms nowhere in it.
def check_keywords():
    lower = re.compile(r"\b(must|shall|should|required|recommended|optional|may)\b")

    upper = re.compile(r"\b(MUST|SHALL|SHOULD|REQUIRED|RECOMMENDED|MAY|OPTIONAL)\b")

    found = []

    for name in CHAPTERS:
        informative = name in ("decisions.md", "principles-review.md", "00-contents.md")

        section = ""

        for number, line in unfenced(chapter(name).split("\n")):
            heading = re.match(r"^#+ (\d+(?:\.\d+)*)", line)

            if heading:
                section = heading.group(1)

            for segment in plain_segments(line):
                text = LINK_RE.sub(r"\1", segment)

                if not informative:
                    for match in lower.finditer(text):
                        found.append(f"{name}:{number}: lowercase '{match.group(1)}'")

                if informative or section in ("1.5", "14.8"):
                    for match in upper.finditer(text):
                        if "BCP 14" not in text:
                            found.append(f"{name}:{number}: informative text uses '{match.group(1)}'")

    for item in found:
        fail(f"keyword: {item}")

    print(f"keywords: {len(found)} misused")


def main():
    check_files()

    check_links()

    check_unlinked_references()

    check_decisions()

    check_principles_and_citations()

    check_markdown()

    check_structure()

    check_keywords()

    print("RESULT:", "PASS" if not failures else f"FAIL ({len(failures)})")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
