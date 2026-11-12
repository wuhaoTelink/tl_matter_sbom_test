#!/usr/bin/env python3
"""Keep only the packages that actually contribute to the firmware.

zspdx lists every module present in the west workspace, including the ~50
vendor HALs that `west update` fetches but a TL3238 build never compiles.
Those are development-environment noise, not product components: an SBOM
describes the binary, not the disk.

The discriminator is the linker map. A module is part of the product if

  * the map references one of its archives (modules/<name>/...a), or
  * any of its sources was compiled, or
  * the package carries file entries anyway.

Packages that only carry a purl and "Utility target; no files" are dropped,
together with the relationships that point at them. build.spdx references
zephyr.spdx by SHA1, so that checksum is recomputed afterwards.

Usage:
    filter_sbom.py --sbom-dir DIR --map zephyr.map [--dry-run]
"""

import argparse
import hashlib
import os
import re
import sys

SOURCES_SUFFIX = "-sources"
DEPS_SUFFIX = "-deps"


def parse_blocks(path):
    text = open(path, encoding="utf-8").read()
    parts = text.split("##### Package: ")
    header = parts[0]
    blocks = []
    for chunk in parts[1:]:
        lines = chunk.splitlines(keepends=True)
        blocks.append((lines[0].strip(), lines[1:]))
    return header, blocks


def block_id(lines):
    for line in lines:
        if line.startswith("SPDXID:"):
            return line.split(":", 1)[1].strip()
    return None


def has_files(lines):
    return any(line.startswith("FileName:") for line in lines)


def module_of(name, suffix):
    if not name.endswith(suffix):
        return None
    return name[: -len(suffix)]


def norm(name):
    """Module names appear as both chip-module and chip_module."""
    return re.sub(r"[-_]", "", name).lower()


def linked_modules(map_path):
    """Module directory names referenced by the linker map."""
    mods = set()
    with open(map_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if ".a(" not in line:
                continue
            m = re.match(r"(?:[^:]*:)?(?:\s*)(modules/([A-Za-z0-9_.-]+)/)", line)
            if m:
                mods.add(m.group(2))
    return mods


def linked_archives(map_path):
    """Basenames of archives the linker pulled objects from."""
    names = set()
    with open(map_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            for m in re.finditer(r"([^/\s()]+\.a)\(", line):
                names.add(m.group(1))
    return names


def filter_doc(path, linked, is_deps=False):
    header, blocks = parse_blocks(path)
    kept, dropped_ids, dropped_names = [], set(), []
    for name, lines in blocks:
        mod = module_of(name, DEPS_SUFFIX if is_deps else SOURCES_SUFFIX)
        keep = True
        if mod is not None:
            keep = has_files(lines) or norm(mod) in linked
        if keep:
            kept.append((name, lines))
        else:
            dropped_ids.add(block_id(lines))
            dropped_names.append(name)
    return header, kept, dropped_ids, dropped_names


def drop_relationships(text, dropped_ids):
    if not dropped_ids:
        return text
    out = []
    for line in text.splitlines(keepends=True):
        if line.startswith("Relationship:") and any(i and i in line for i in dropped_ids):
            continue
        out.append(line)
    return "".join(out)


def rewrite(path, header, blocks, dropped_ids):
    text = header + "".join("##### Package: " + n + "\n" + "".join(l) for n, l in blocks)
    text = drop_relationships(text, dropped_ids)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return hashlib.sha1(text.encode()).hexdigest()


def update_refs(build_spdx, namespace_suffix, new_sha1):
    """Point build.spdx's ExternalDocumentRef at the rewritten document."""
    text = open(build_spdx, encoding="utf-8").read()
    pat = re.compile(r"(ExternalDocumentRef:\s+\S+\s+\S*" + re.escape(namespace_suffix) + r"\s+SHA1:\s*)([0-9a-f]{40})")
    new_text, n = pat.subn(lambda m: m.group(1) + new_sha1, text)
    if n:
        with open(build_spdx, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom-dir", required=True)
    ap.add_argument("--map", required=True, help="zephyr.map produced by the build")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    linked = {norm(m) for m in linked_modules(args.map)}
    print(f"linked modules in map: {len(linked)}")
    print("  " + ", ".join(sorted(linked)))

    summary = {}
    changed = {}
    for doc, is_deps in (("zephyr.spdx", False), ("modules-deps.spdx", True)):
        path = os.path.join(args.sbom_dir, doc)
        if not os.path.exists(path):
            continue
        header, kept, dropped_ids, dropped_names = filter_doc(path, linked, is_deps)
        summary[doc] = (len(kept), len(dropped_names))
        print(f"{doc}: keep {len(kept)}, drop {len(dropped_names)}")
        if dropped_names:
            print("  dropped: " + ", ".join(sorted(dropped_names)[:10]) + (" ..." if len(dropped_names) > 10 else ""))
        if not args.dry_run:
            changed[doc] = (header, kept, dropped_ids)

    if args.dry_run:
        return

    new_hashes = {}
    all_dropped = set()
    for doc, (header, kept, dropped_ids) in changed.items():
        new_hashes[doc] = rewrite(os.path.join(args.sbom_dir, doc), header, kept, dropped_ids)
        all_dropped |= dropped_ids

    build_path = os.path.join(args.sbom_dir, "build.spdx")
    if os.path.exists(build_path):
        for doc, sha in new_hashes.items():
            n = update_refs(build_path, "/" + doc.split(".")[0], sha)
            print(f"build.spdx -> {doc}: updated {n} reference(s)")
        if all_dropped:
            text = open(build_path, encoding="utf-8").read()
            new_text = drop_relationships(text, all_dropped)
            if new_text != text:
                with open(build_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(new_text)
                print("build.spdx: dropped dangling relationships")


if __name__ == "__main__":
    main()
