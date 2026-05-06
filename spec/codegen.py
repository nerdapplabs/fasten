#!/usr/bin/env python3
"""
spec/codegen.py — generate enum/constant blocks for all fasten language adapters.

Single source of truth: spec/row-schema.json

Usage:
    python spec/codegen.py --write   update adapter files in place
    python spec/codegen.py --check   exit 1 if any adapter is out of date (CI gate)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Callable

ROOT   = pathlib.Path(__file__).parent.parent
SCHEMA = ROOT / "spec" / "row-schema.json"

MARK_B = "FASTEN GENERATED"
MARK_E = "END FASTEN GENERATED"

# ── Spec helpers ──────────────────────────────────────────────────────────────

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

# ── Name helpers ──────────────────────────────────────────────────────────────

def upper(s: str) -> str:
    return s.upper()

def pascal(s: str) -> str:
    return "".join(w.capitalize() for w in s.split("_"))

# Go treats short all-caps tokens as acronyms per effective-go conventions.
_GO_ACRONYMS = {"http", "mqtt", "cli", "ui", "sdk"}

def go_pascal(s: str) -> str:
    return "".join(w.upper() if w in _GO_ACRONYMS else w.capitalize()
                   for w in s.split("_"))

def dquote(s: str) -> str:
    """Return s as a double-quoted string literal (valid in Go, Rust, C++, Java)."""
    return json.dumps(s)

# ── Language generators ───────────────────────────────────────────────────────
# Each returns the *content* between the markers (no marker lines).

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
            L.append(f'    {upper(v).ljust(pad)} = "{v}"{suffix}')
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
        for v, dv in vs:
            const = (prefix + go_pascal(v)).ljust(pad)
            doc = f"{dv} (default)" if (dv and v == dflt) else dv if dv else ("(default)" if v == dflt else "")
            suffix = f"  // {doc}" if doc else ""
            L.append(f'\t{const} {type_name} = {dquote(v)}{suffix}')
        L.append(")")
        L.append("")

    d = enum_def(spec, "method")
    vs = vals(d)
    dflt = d.get("default", "")
    L.append("const (")
    pad = max(len("Method" + go_pascal(v)) for v, _ in vs)
    for v, dv in vs:
        const = ("Method" + go_pascal(v)).ljust(pad)
        doc = f"{dv} (default)" if (dv and v == dflt) else dv if dv else ("(default)" if v == dflt else "")
        suffix = f"  // {doc}" if doc else ""
        L.append(f'\t{const} = {dquote(v)}{suffix}')
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
        items = ", ".join(f"{upper(v)}: '{v}'" for v, _ in vals(d))
        L.append(f"export const {name} = Object.freeze({{ {items} }});")

    L.append("")
    r = redact(spec)
    L.append(f"export const REDACT_REPLACEMENT = '{r['replacement']}';")
    L.append("export const REDACT_PATTERNS = [")
    for p in r["patterns"]:
        L.append(f"  '{p}',")
    L.append("];")
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
    L.append(f'pub const REDACT_REPLACEMENT: &str = {dquote(r["replacement"])};')
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
    L.append("")
    L.append("// Default PII field key patterns (case-insensitive regex on keys).")
    L.append("inline const std::vector<std::string>& redact_patterns() {")
    L.append("    static const std::vector<std::string> kPatterns = {")
    for p in r["patterns"]:
        L.append(f'        {json.dumps(p)},')
    L.append("    };")
    L.append("    return kPatterns;")
    L.append("}")
    return "\n".join(L)


# ── File injection ────────────────────────────────────────────────────────────

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
    idx = text.find(marker)
    if idx == -1:
        return -1, -1
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
        return True

    new_text = text[:b_start] + new_block + text[e_end:]
    adapter.path.write_text(new_text)
    print(f"  ✓ {adapter.lang}: updated")
    return False


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

    print()
    if drift == 0:
        print("All adapters up to date.")
    elif args.check:
        print(f"{drift} adapter(s) out of date.")
        sys.exit(1)
    else:
        print(f"{drift} adapter(s) updated.")


if __name__ == "__main__":
    main()
