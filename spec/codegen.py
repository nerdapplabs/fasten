#!/usr/bin/env python3
"""
Generate the enum constants in each SDK, and the redact patterns in the
Python, Go and Rust SDKs, from spec/row-schema.json, between the FASTEN
GENERATED markers.

Usage:
    python spec/codegen.py --write   update adapter files in place
    python spec/codegen.py --check   exit 1 if any adapter is out of date

Covers the Python, Go, JS, Rust and C++ SDKs. gen_java is not in ADAPTERS, so
the generated block in java/ is not checked.

The output matches what the formatters leave (gofmt for Go, Biome for JS), so
a formatted file passes --check.

--check also compares the redaction key lists that are written by hand with
the spec: fasten-core's reference list (used by Python, Go and C++ over the
C ABI, and by Rust as a crate), and the lists in the JS and Swift redactors,
which run on their own. Those keep comments and regex syntax of their own,
so they are read and compared, not generated. --write checks them too and
exits 1 when one differs, since it can't change them.
"""
from __future__ import annotations

import argparse
import difflib
import json
import pathlib
import re
import sys
from typing import Callable

ROOT   = pathlib.Path(__file__).parent.parent
SCHEMA = ROOT / "spec" / "row-schema.json"

MARK_B = "── FASTEN GENERATED"
MARK_E = "── END FASTEN GENERATED"

def load_spec() -> dict:
    return json.loads(SCHEMA.read_text())

def enum_def(spec: dict, key: str) -> dict:
    """Return the schema definition for a named enum (properties or $defs)."""
    if key in spec.get("properties", {}):
        return spec["properties"][key]
    pascal = "".join(w.capitalize() for w in key.split("_"))
    defs = spec.get("$defs", {})
    if pascal in defs:
        return defs[pascal]
    if key in defs:
        return defs[key]
    raise KeyError(f"enum definition not found for {key!r}")

def vals(defn: dict) -> list[tuple[str, str]]:
    """Return [(wire_value, doc), ...] preserving spec order."""
    xv = defn.get("x-values", {})
    return [(v, xv.get(v, "")) for v in defn["enum"]]

def redact(spec: dict) -> dict:
    return spec["x-fasten-redact"]

def upper(s: str) -> str:
    return s.upper()

def pascal(s: str) -> str:
    return "".join(w.capitalize() for w in s.split("_"))

# Go style writes acronyms in all caps (MethodHTTP, not MethodHttp).
_GO_ACRONYMS = {"http", "mqtt", "cli", "ui", "sdk"}

def go_pascal(s: str) -> str:
    return "".join(w.upper() if w in _GO_ACRONYMS else w.capitalize()
                   for w in s.split("_"))

def dquote(s: str) -> str:
    """Return s as a double-quoted string literal (valid in Go, Rust, C++, Java)."""
    return json.dumps(s)

# Each generator returns the lines between the markers, without the markers.

def gen_python(spec: dict) -> str:
    L: list[str] = []

    enums = [
        ("severity",        "Severity",       "Ascending severity. Wire value: lowercase string."),
        ("retention_class", "RetentionClass", "Row retention bucket. Wire value: lowercase string."),
        ("actor_kind",      "ActorKind",      "WHO anchor — who initiated the action. Wire value: lowercase string."),
        ("method",          "Method",         "HOW anchor — how the event was triggered. Wire value: lowercase string."),
    ]
    for field, cls, doc in enums:
        d = enum_def(spec, field)
        vs = vals(d)
        pad = max(len(upper(v)) for v, _ in vs)
        L.append(f'class {cls}(str, Enum):')
        L.append(f'    """{doc}"""')
        for v, dv in vs:
            suffix = f"  # {dv}" if dv else ""
            L.append(f'    {upper(v).ljust(pad)} = {json.dumps(v)}{suffix}')
        L.append("")
        L.append("    def __str__(self) -> str: return self.value")
        L.append("")

    r = redact(spec)
    L.append(f'_REDACT_REPLACEMENT = {r["replacement"]!r}')
    L.append("_REDACT_PATTERNS = (")
    for p in r["patterns"]:
        L.append(f'    {p!r},')
    L.append(")")
    return "\n".join(L)


def gen_go(spec: dict) -> str:
    L: list[str] = []

    typed_enums = [
        ("severity",        "Severity",       "Sev"),
        ("retention_class", "RetentionClass", "Ret"),
        ("actor_kind",      "ActorKind",      "Actor"),
    ]
    for field, type_name, prefix in typed_enums:
        d = enum_def(spec, field)
        vs = vals(d)
        dflt = d.get("default", "")
        L.append(f"type {type_name} string")
        L.append("")
        L.append("const (")
        pad = max(len(prefix + go_pascal(v)) for v, _ in vs)
        vpad = max(len(dquote(v)) for v, _ in vs)
        for v, dv in vs:
            const = (prefix + go_pascal(v)).ljust(pad)
            doc = f"{dv} (default)" if (dv and v == dflt) else dv if dv else ("(default)" if v == dflt else "")
            value = f"{dquote(v).ljust(vpad)} // {doc}" if doc else dquote(v)
            L.append(f'\t{const} {type_name} = {value}')
        L.append(")")
        L.append("")

    d = enum_def(spec, "method")
    vs = vals(d)
    dflt = d.get("default", "")
    L.append("const (")
    pad = max(len("Method" + go_pascal(v)) for v, _ in vs)
    vpad = max(len(dquote(v)) for v, _ in vs)
    for v, dv in vs:
        const = ("Method" + go_pascal(v)).ljust(pad)
        doc = f"{dv} (default)" if (dv and v == dflt) else dv if dv else ("(default)" if v == dflt else "")
        value = f"{dquote(v).ljust(vpad)} // {doc}" if doc else dquote(v)
        L.append(f'\t{const} = {value}')
    L.append(")")
    L.append("")

    r = redact(spec)
    L.append(f'const RedactReplacement = {dquote(r["replacement"])}')
    L.append("")
    L.append("// RedactPatterns are the default PII field key patterns (case-insensitive regex on keys).")
    L.append("var RedactPatterns = []string{")
    for p in r["patterns"]:
        L.append(f'\t{dquote(p)},')
    L.append("}")
    L.append("")
    return "\n".join(L)


def gen_js(spec: dict) -> str:
    L: list[str] = []

    for field, name in [
        ("severity",        "Severity"),
        ("retention_class", "RetentionClass"),
        ("actor_kind",      "ActorKind"),
        ("method",          "Method"),
    ]:
        d = enum_def(spec, field)
        L.append(f"export const {name} = Object.freeze({{")
        for v, _ in vals(d):
            L.append(f"\t{upper(v)}: {dquote(v)},")
        L.append("});")
    return "\n".join(L)


def gen_rust(spec: dict) -> str:
    L: list[str] = []

    for field, type_name in [("severity", "Severity"), ("retention_class", "RetentionClass")]:
        d = enum_def(spec, field)
        vs = vals(d)
        L.append("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]")
        L.append(f"pub enum {type_name} {{")
        for v, dv in vs:
            suffix = f"  // {dv}" if dv else ""
            L.append(f"    {pascal(v)},{suffix}")
        L.append("}")
        L.append("")
        L.append(f"impl fmt::Display for {type_name} {{")
        L.append("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
        L.append("        match self {")
        for v, _ in vs:
            L.append(f'            {type_name}::{pascal(v)} => f.write_str("{v}"),')
        L.append("        }")
        L.append("    }")
        L.append("}")
        L.append("")

    for field, prefix, doc in [
        ("actor_kind", "ACTOR", "WHO anchor wire values."),
        ("method",     "METHOD", "HOW anchor wire values."),
    ]:
        d = enum_def(spec, field)
        L.append(f"// {doc}")
        for v, dv in vals(d):
            suffix = f"  // {dv}" if dv else ""
            L.append(f'pub const {prefix}_{upper(v)}: &str = "{v}";{suffix}')
        L.append("")

    r = redact(spec)
    L.append("pub use fasten_core::redact::DEFAULT_REPLACEMENT as REDACT_REPLACEMENT;")
    L.append("pub const REDACT_PATTERNS: &[&str] = &[")
    for p in r["patterns"]:
        L.append(f'    {dquote(p)},')
    L.append("];")
    return "\n".join(L)


def gen_java(spec: dict) -> str:
    L: list[str] = []
    ind = "    "  # inside class body

    for field, type_name in [("severity", "Severity"), ("retention_class", "RetentionClass")]:
        d = enum_def(spec, field)
        vs = vals(d)
        members = ", ".join(upper(v) for v, _ in vs)
        L.append(f"{ind}public enum {type_name} {{")
        L.append(f"{ind}    {members};")
        L.append("")
        L.append(f"{ind}    @Override public String toString() {{")
        L.append(f"{ind}        switch (this) {{")
        for v, _ in vs:
            L.append(f'{ind}            case {upper(v)}: return "{v}";')
        L.append(f"{ind}            default: throw new IllegalStateException();")
        L.append(f"{ind}        }}")
        L.append(f"{ind}    }}")
        L.append(f"{ind}}}")
        L.append("")

    for field, prefix, doc in [
        ("actor_kind", "ACTOR",  "WHO anchor wire values."),
        ("method",     "METHOD", "HOW anchor wire values."),
    ]:
        d = enum_def(spec, field)
        L.append(f"{ind}// {doc}")
        for v, dv in vals(d):
            suffix = f"  // {dv}" if dv else ""
            L.append(f'{ind}public static final String {prefix}_{upper(v)} = "{v}";{suffix}')
        L.append("")

    r = redact(spec)
    L.append(f'{ind}public static final String REDACT_REPLACEMENT = "{r["replacement"]}";')
    L.append(f"{ind}public static final String[] REDACT_PATTERNS = {{")
    for p in r["patterns"]:
        L.append(f'{ind}    "{p}",')
    L.append(f"{ind}}};")
    return "\n".join(L)


def gen_cpp(spec: dict) -> str:
    L: list[str] = []

    sev_vals = vals(enum_def(spec, "severity"))
    ret_vals = vals(enum_def(spec, "retention_class"))

    L.append("enum class Sev       { " + ", ".join(pascal(v) for v, _ in sev_vals) + " };")
    L.append("enum class Retention { " + ", ".join(pascal(v) for v, _ in ret_vals) + " };")
    L.append("")

    L.append("inline std::string to_string(Sev s) {")
    L.append("    switch (s) {")
    for v, _ in sev_vals:
        L.append(f'        case Sev::{pascal(v)}: return "{v}";')
    L.append("    }")
    L.append(f'    return "{enum_def(spec, "severity").get("default", "info")}";')
    L.append("}")
    L.append("inline std::string to_string(Retention r) {")
    L.append("    switch (r) {")
    for v, _ in ret_vals:
        L.append(f'        case Retention::{pascal(v)}: return "{v}";')
    L.append("    }")
    L.append(f'    return "{enum_def(spec, "retention_class").get("default", "medium")}";')
    L.append("}")
    L.append("")

    for field, sname, doc in [
        ("actor_kind", "ActorKind", "WHO anchor wire values."),
        ("method",     "Method",    "HOW anchor — set by transport shims. Use Method::sdk for direct calls."),
    ]:
        d = enum_def(spec, field)
        L.append(f"// {doc}")
        L.append(f"struct {sname} {{")
        for v, dv in vals(d):
            suffix = f"  // {dv}" if dv else ""
            L.append(f'    static constexpr const char* {v} = "{v}";{suffix}')
        L.append("};")
        L.append("")

    r = redact(spec)
    L.append(f'constexpr const char* kRedactReplacement = {json.dumps(r["replacement"])};')
    return "\n".join(L)


class Adapter:
    def __init__(self, lang: str, path: pathlib.Path,
                 comment: str, generator: Callable[[dict], str]) -> None:
        self.lang      = lang
        self.path      = path
        self.comment   = comment
        self.generator = generator

    def marker_begin(self) -> str:
        return (f"{self.comment} ── FASTEN GENERATED"
                f" ─ source: spec/row-schema.json"
                f" ─ run: python spec/codegen.py ──")

    def marker_end(self) -> str:
        return f"{self.comment} ── END FASTEN GENERATED {'─' * 50}"


ADAPTERS = [
    Adapter("python", ROOT / "python" / "fasten" / "codes.py",
            "#",  gen_python),
    Adapter("go",     ROOT / "go" / "fasten.go",
            "//", gen_go),
    Adapter("js",     ROOT / "js" / "src" / "index.js",
            "//", gen_js),
    Adapter("rust",   ROOT / "rust" / "src" / "lib.rs",
            "//", gen_rust),
    Adapter("cpp",    ROOT / "cpp" / "include" / "fasten.hpp",
            "//", gen_cpp),
]


def _find_marker(text: str, marker: str) -> tuple[int, int]:
    """Return (line_start, line_end_exclusive) for the line containing marker."""
    count = text.count(marker)
    if count == 0:
        return -1, -1
    if count > 1:
        raise ValueError(f"marker {marker!r} appears {count} times (expected exactly 1)")
    idx   = text.find(marker)
    start = text.rfind("\n", 0, idx) + 1
    end   = text.find("\n", idx)
    end   = end + 1 if end != -1 else len(text)
    return start, end


def process(adapter: Adapter, spec: dict, check: bool) -> bool:
    """Generate and inject. Returns True if the file was (or would be) changed."""
    if not adapter.path.exists():
        print(f"  ? {adapter.lang}: file not found — {adapter.path.relative_to(ROOT)}")
        return True

    text = adapter.path.read_text()
    b_start, b_end = _find_marker(text, MARK_B)
    e_start, e_end = _find_marker(text, MARK_E)

    if b_start == -1 or e_start == -1:
        print(f"  ? {adapter.lang}: markers not found — add {MARK_B!r} / {MARK_E!r} to {adapter.path.name}")
        return True

    generated = adapter.generator(spec)
    new_block  = adapter.marker_begin() + "\n" + generated + "\n" + adapter.marker_end() + "\n"
    current_block = text[b_start:e_end]

    if new_block == current_block:
        print(f"  ✓ {adapter.lang}")
        return False

    if check:
        print(f"  ✗ {adapter.lang}: out of date — run: python spec/codegen.py --write")
        diff = difflib.unified_diff(
            current_block.splitlines(keepends=True),
            new_block.splitlines(keepends=True),
            fromfile=f"{adapter.lang} (current)",
            tofile=f"{adapter.lang} (generated)",
        )
        sys.stdout.writelines(diff)
        return True

    new_text = text[:b_start] + new_block + text[e_end:]
    adapter.path.write_text(new_text)
    print(f"  ✓ {adapter.lang}: updated")
    return False


# Hand-written redaction key lists, checked against the spec. Each entry:
# name, file, the line that opens the list, the line that closes it, the
# regex that finds one pattern (comments are removed first), and how to turn
# a match into the spec's form. A form the language must not use raises
# ValueError.
_RUST_STR  = re.compile(r'r"((?:[^"\\]|\\.)*)"')
_JS_REGEX  = re.compile(r'/((?:[^/\\\n]|\\.)+)/([A-Za-z]*)')
_SWIFT_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _plain(m: re.Match[str]) -> str:
    return m.group(1)


def _js_pattern(m: re.Match[str]) -> str:
    # Exactly the i flag: with g, .test() keeps its position between keys
    # and misses every other match; m changes what $ means.
    if m.group(2) != "i":
        raise ValueError(f"/{m.group(1)}/{m.group(2)} must have exactly the i flag")
    return m.group(1)


def _swift_pattern(m: re.Match[str]) -> str:
    # The string literal escapes its backslash, and Swift writes \z where the
    # spec has $: ICU's $ also matches before a final newline.
    p = m.group(1).replace("\\\\", "\\")
    if "$" in p:
        raise ValueError(f"{p!r} uses $; write \\z, since ICU's $ also matches "
                         "before a final newline")
    return re.sub(r"\\z$", "$", p)


PATTERN_LISTS = [
    ("fasten-core", ROOT / "fasten-core" / "src" / "redact.rs",
     "static REDACT_PATTERNS: &[&str] = &[", "];", _RUST_STR, _plain),
    ("js",          ROOT / "js" / "src" / "core.js",
     "const _DEFAULT_PATTERNS = [", "];", _JS_REGEX, _js_pattern),
    ("swift",       ROOT / "swift" / "Sources" / "Fasten" / "Redactor.swift",
     "let specs = [", "]", _SWIFT_STR, _swift_pattern),
]

# The hand-written replacement tokens: fasten-core's, which the Rust SDK
# re-exports and Python, Go and C++ redact with, and the JS and Swift
# redactors' own. Each pattern must match exactly once in its file.
_SWIFT_SRC = ROOT / "swift" / "Sources" / "Fasten"
REPLACEMENTS: list[tuple[str, pathlib.Path, re.Pattern[str]]] = [
    ("fasten-core", ROOT / "fasten-core" / "src" / "redact.rs",
     re.compile(r'pub const DEFAULT_REPLACEMENT: &str = "([^"]*)";')),
    ("js", ROOT / "js" / "src" / "core.js",
     re.compile(r'const REDACT_REPLACEMENT = "([^"]*)";')),
    ("swift Redactor", _SWIFT_SRC / "Redactor.swift",
     re.compile(r'\breplacement:\s+String\s+= "([^"]*)"')),
    ("swift Engine", _SWIFT_SRC / "Engine.swift",
     re.compile(r'\bredactReplacement:\s+String\s+= "([^"]*)"')),
    ("swift env default", _SWIFT_SRC / "Fasten.swift",
     re.compile(r's\.isEmpty \? "([^"]*)" : s')),
]


def without_comments(lines: list[str]) -> list[str]:
    """The lines with // and /* */ comments removed, so a pattern that is
    only in a comment doesn't count. None of the key patterns contain // or
    /*."""
    out: list[str] = []
    in_block = False
    for line in lines:
        kept = ""
        rest = line
        while rest:
            if in_block:
                end = rest.find("*/")
                if end < 0:
                    rest = ""
                    break
                rest = rest[end + 2:]
                in_block = False
                continue
            starts = [i for i in (rest.find("//"), rest.find("/*")) if i >= 0]
            if not starts:
                kept += rest
                break
            cut = min(starts)
            kept += rest[:cut]
            if rest.startswith("//", cut):
                break
            rest = rest[cut + 2:]
            in_block = True
        out.append(kept)
    return out


def read_pattern_list(path: pathlib.Path, opens: str, closes: str,
                      token: re.Pattern[str],
                      convert: Callable[[re.Match[str]], str]) -> list[str]:
    lines = without_comments(path.read_text().splitlines())
    starts = [i for i, line in enumerate(lines) if line.strip() == opens.strip()]
    if len(starts) != 1:
        raise ValueError(f"expected one line {opens!r}, found {len(starts)}")
    out: list[str] = []
    for line in lines[starts[0] + 1:]:
        text = line.strip()
        if text == closes:
            return out
        out.extend(convert(m) for m in token.finditer(text))
    raise ValueError(f"no closing {closes!r} after {opens!r}")


def check_pattern_lists(spec: dict) -> int:
    """Compare the hand-written key lists and replacement tokens with the
    spec. Returns how many differ or can't be read."""
    want = redact(spec)["patterns"]
    drift = 0
    for name, path, opens, closes, token, convert in PATTERN_LISTS:
        rel = path.relative_to(ROOT)
        try:
            got = read_pattern_list(path, opens, closes, token, convert)
        except (OSError, ValueError) as exc:
            print(f"  ✗ {name} key list ({rel}): {exc}")
            drift += 1
            continue
        if got == want:
            print(f"  ✓ {name} key list")
            continue
        print(f"  ✗ {name} key list ({rel}) differs from x-fasten-redact.patterns; edit it by hand:")
        sys.stdout.writelines(difflib.unified_diff(
            [p + "\n" for p in got], [p + "\n" for p in want],
            fromfile=f"{name} (current)", tofile="spec"))
        drift += 1

    for name, path, pattern in REPLACEMENTS:
        rel = path.relative_to(ROOT)
        try:
            text = "\n".join(without_comments(path.read_text().splitlines()))
        except OSError as exc:
            print(f"  ✗ {name} replacement ({rel}): {exc}")
            drift += 1
            continue
        found = pattern.findall(text)
        if found == [redact(spec)["replacement"]]:
            print(f"  ✓ {name} replacement")
        else:
            print(f"  ✗ {name} replacement ({rel}) is {found}, "
                  f"x-fasten-redact.replacement is {redact(spec)['replacement']!r}; edit it by hand")
            drift += 1
    return drift


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true",
                       help="update all adapter files in place")
    group.add_argument("--check", action="store_true",
                       help="exit 1 if any adapter is out of date (CI gate)")
    args = parser.parse_args()

    spec  = load_spec()
    drift = 0
    for adapter in ADAPTERS:
        try:
            if process(adapter, spec, check=args.check):
                drift += 1
        except Exception as exc:
            print(f"  ✗ {adapter.lang}: {exc}")
            drift += 1

    lists = check_pattern_lists(spec)

    print()
    if lists:
        print(f"{lists} hand-written key list(s) differ from the spec; edit them by hand.")
        sys.exit(1)
    if drift == 0:
        print("All adapters up to date.")
    elif args.check:
        print(f"{drift} adapter(s) out of date.")
        sys.exit(1)
    else:
        print(f"{drift} adapter(s) updated.")


if __name__ == "__main__":
    main()
