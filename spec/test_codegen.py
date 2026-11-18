"""The key list reader in codegen.py: a list that is wrong must not pass.

Run: python3 -m unittest spec/test_codegen.py
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import codegen  # noqa: E402

RUST = ("fasten-core", "static REDACT_PATTERNS: &[&str] = &[", "];",
        codegen._RUST_STR, codegen._plain)
JS = ("js", "const _DEFAULT_PATTERNS = [", "];", codegen._JS_REGEX, codegen._js_pattern)
SWIFT = ("swift", "let specs = [", "]", codegen._SWIFT_STR, codegen._swift_pattern)


def read(kind: tuple, body: str) -> list[str]:
    _, opens, closes, token, convert = kind
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "list"
        path.write_text(f"before\n{opens}\n{body}\n{closes}\nafter\n")
        return codegen.read_pattern_list(path, opens, closes, token, convert)


class ReadPatternList(unittest.TestCase):
    def test_reads_each_language(self) -> None:
        self.assertEqual(read(RUST, '    r"token",\n    r"[_-]pwd$",'), ["token", "[_-]pwd$"])
        self.assertEqual(read(JS, "\t/token/i,\n\t/[_-]pwd$/i,"), ["token", "[_-]pwd$"])
        self.assertEqual(read(SWIFT, '"token", "[_-]pwd\\\\z",'), ["token", "[_-]pwd$"])

    def test_two_patterns_on_a_line(self) -> None:
        self.assertEqual(read(RUST, '    r"token", r"cookie",'), ["token", "cookie"])

    def test_a_pattern_only_in_a_comment_does_not_count(self) -> None:
        self.assertEqual(read(RUST, '    r"session[_-]?id", // r"cookie",'), ["session[_-]?id"])
        self.assertEqual(read(JS, "\t/session[_-]?id/i, // was /cookie/i"), ["session[_-]?id"])
        self.assertEqual(read(SWIFT, '"[_-]pwd\\\\z", // "passphrase",'), ["[_-]pwd$"])

    def test_block_comments_do_not_count(self) -> None:
        self.assertEqual(read(RUST, '    /* r"token", */ r"cookie",'), ["cookie"])
        self.assertEqual(read(JS, "\t/* /token/i, */\n\t/cookie/i,"), ["cookie"])
        self.assertEqual(read(SWIFT, '/*\n"token",\n*/ "cookie",'), ["cookie"])

    def test_js_needs_exactly_the_i_flag(self) -> None:
        for bad in ("/token/ig,", "/dsn$/im,", "/token/g,", "/token/,"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                read(JS, "\t" + bad)

    def test_swift_must_write_z_not_dollar(self) -> None:
        with self.assertRaises(ValueError):
            read(SWIFT, '"dsn$",')

    def test_opening_line_must_appear_once(self) -> None:
        _, opens, closes, token, convert = RUST
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "list"
            path.write_text(f"{opens}\n{closes}\n{opens}\n{closes}\n")
            with self.assertRaises(ValueError):
                codegen.read_pattern_list(path, opens, closes, token, convert)

    def test_missing_closing_line(self) -> None:
        _, opens, closes, token, convert = RUST
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "list"
            path.write_text(f'{opens}\n    r"token",\n')
            with self.assertRaises(ValueError):
                codegen.read_pattern_list(path, opens, closes, token, convert)


class RepoLists(unittest.TestCase):
    def test_the_repo_passes(self) -> None:
        self.assertEqual(codegen.check_pattern_lists(codegen.load_spec()), 0)


if __name__ == "__main__":
    unittest.main()
