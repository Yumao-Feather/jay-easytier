#!/usr/bin/env python3
"""Build a symbol index of easytier/src for Jay's maintainers.

Writes .jay-index/symbols.tsv (file, line, kind, name, enclosing impl) and
.jay-index/files.tsv (file, lines, first doc comment), then lets you query:

    python3 tools/jay-index.py            # rebuild
    python3 tools/jay-index.py find get_256_key
    python3 tools/jay-index.py file peer_conn

It only reads source files; it never runs cargo or any build script.
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC = os.path.join(ROOT, "easytier", "src")
OUT = os.path.join(ROOT, ".jay-index")

ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?"
    r"(fn|struct|enum|trait|type|mod|const|static|macro_rules!)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
IMPL = re.compile(r"^\s*impl(?:<[^>]*>)?\s+(?:([A-Za-z0-9_:<>, ]+?)\s+for\s+)?([A-Za-z0-9_:<>]+)")


def build():
    os.makedirs(OUT, exist_ok=True)
    symbols, files = [], []
    for dirpath, _, names in os.walk(SRC):
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().split("\n")
            doc = next((l.strip().lstrip("/!").strip() for l in lines[:40] if l.strip().startswith(("//!", "///"))), "")
            files.append((rel, str(len(lines)), doc))
            impl = ""
            depth = 0
            impl_depth = None
            for i, line in enumerate(lines, 1):
                m = IMPL.match(line)
                if m and depth == 0:
                    impl = (m.group(1).strip() + " for " if m.group(1) else "") + m.group(2)
                    impl_depth = depth
                m = ITEM.match(line)
                if m:
                    symbols.append((rel, str(i), m.group(1).rstrip("!"), m.group(2), impl if impl_depth is not None else ""))
                depth += line.count("{") - line.count("}")
                if impl_depth is not None and depth <= impl_depth:
                    impl, impl_depth = "", None
    with open(os.path.join(OUT, "symbols.tsv"), "w", encoding="utf-8") as f:
        f.write("file\tline\tkind\tname\timpl\n")
        f.writelines("\t".join(s) + "\n" for s in symbols)
    with open(os.path.join(OUT, "files.tsv"), "w", encoding="utf-8") as f:
        f.write("file\tlines\tdoc\n")
        f.writelines("\t".join(x) + "\n" for x in sorted(files))
    print(f"{len(symbols)} symbols in {len(files)} files -> {os.path.relpath(OUT)}")


def query(kind, term):
    table = "symbols.tsv" if kind == "find" else "files.tsv"
    path = os.path.join(OUT, table)
    if not os.path.exists(path):
        build()
    term = term.lower()
    with open(path, encoding="utf-8") as f:
        next(f)
        for row in f:
            cols = row.rstrip("\n").split("\t")
            hay = cols[3] if kind == "find" else cols[0]
            if term in hay.lower():
                print("  ".join(c for c in cols if c))


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] in ("find", "file"):
        query(sys.argv[1], sys.argv[2])
    else:
        build()
