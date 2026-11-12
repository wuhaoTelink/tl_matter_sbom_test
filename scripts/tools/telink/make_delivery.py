#!/usr/bin/env python3
"""Assemble the customer-facing delivery bundle for one firmware build.

Layout produced:

    delivery/
      firmware/zephyr.bin, zephyr.elf
      sbom/{app,zephyr,build,modules-deps,matter-sources}.spdx
      sbom/telink-matter.cdx.json
      sbom/prebuilt-binaries.txt
      sbom/trivy-sbom.json          (when vulnerability scanning ran)
      MANIFEST.json
      SHA256SUMS

The manifest records the repository, commit and per-file hashes so the bundle
can be archived and diffed between releases without re-deriving anything.

Usage:
    make_delivery.py [--build-dir DIR] [--sbom-dir DIR] [--out-dir DIR] [--zip FILE]
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import zipfile

SINGLE_FILES = [
    ("firmware", "{build}/zephyr/zephyr.bin"),
    ("firmware", "{build}/zephyr/zephyr.elf"),
    ("sbom", "{sbom}/telink-matter.cdx.json"),
    ("sbom", "{sbom}/prebuilt-binaries.txt"),
    ("sbom", "{sbom}/trivy-sbom.json"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="out/telink-build")
    ap.add_argument("--sbom-dir", default="out/sbom")
    ap.add_argument("--out-dir", default="out/delivery")
    ap.add_argument("--zip", default="", help="also write a zip of the bundle")
    args = ap.parse_args()

    if os.path.exists(args.out_dir):
        shutil.rmtree(args.out_dir)
    os.makedirs(os.path.join(args.out_dir, "firmware"), exist_ok=True)
    os.makedirs(os.path.join(args.out_dir, "sbom"), exist_ok=True)

    for dest, pattern in SINGLE_FILES:
        src = pattern.format(build=args.build_dir, sbom=args.sbom_dir)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(args.out_dir, dest, os.path.basename(src)))
        else:
            print(f"skip (missing): {src}")

    enriched = os.path.join(args.sbom_dir, "enriched")
    if os.path.isdir(enriched):
        for name in sorted(os.listdir(enriched)):
            if name.endswith(".spdx"):
                shutil.copy2(os.path.join(enriched, name),
                             os.path.join(args.out_dir, "sbom", name))

    files = []
    for root, _, names in os.walk(args.out_dir):
        for name in sorted(names):
            p = os.path.join(root, name)
            files.append({"path": os.path.relpath(p, args.out_dir), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    manifest = {
        "project": os.environ.get("GITHUB_REPOSITORY", ""),
        "commit": os.environ.get("GITHUB_SHA") or git_head(),
        "generated_utc": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                                        capture_output=True, text=True).stdout.strip(),
        "files": files,
    }
    with open(os.path.join(args.out_dir, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    with open(os.path.join(args.out_dir, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for item in files:
            f.write(f"{item['sha256']}  {item['path']}\n")

    if args.zip:
        with zipfile.ZipFile(args.zip, "w", zipfile.ZIP_DEFLATED) as z:
            for item in files:
                p = os.path.join(args.out_dir, item["path"])
                z.write(p, item["path"])
            z.write(os.path.join(args.out_dir, "MANIFEST.json"), "MANIFEST.json")
            z.write(os.path.join(args.out_dir, "SHA256SUMS"), "SHA256SUMS")
        print(f"zip: {args.zip}")

    print(f"delivery: {args.out_dir} ({len(files)} payload files)")
    for item in files:
        print(f"  {item['sha256'][:12]}  {item['path']}")


if __name__ == "__main__":
    main()
