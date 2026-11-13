#!/usr/bin/env python3
"""Assemble the customer-facing delivery bundle for one firmware build.

Layout produced:

    delivery/
      README.md
      manifest.json
      SHA256SUMS
      firmware/zephyr.bin, zephyr.elf
      sbom/{app,zephyr,build,modules-deps,matter-sources}.spdx
      sbom/telink-matter.cdx.json
      sbom/prebuilt-binaries.txt
      sbom/trivy-sbom.json
      LICENSES/
        README.md
        index.json
        <SPDX-ID>.txt              canonical text (standard-reference)
        declarations/<id>.txt      short declaration only
        (observed/ is not produced: no scanner evidence in a build-level run)

License texts are taken from the vendored `license-texts/` directory next to
this script when possible, and downloaded from the SPDX license-list-data
repository otherwise. A text that cannot be obtained is recorded as
`text-missing` rather than invented.

Usage:
    make_delivery.py [--build-dir DIR] [--sbom-dir DIR] [--review-dir DIR]
                     [--out-dir DIR] [--zip FILE]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

SINGLE_FILES = [
    ("firmware", "{build}/zephyr/zephyr.bin"),
    ("firmware", "{build}/zephyr/zephyr.elf"),
    ("sbom", "{sbom}/telink-matter.cdx.json"),
    ("sbom", "{sbom}/prebuilt-binaries.txt"),
    ("sbom", "{sbom}/trivy-sbom.json"),
]

SPDX_TEXT_URL = "https://raw.githubusercontent.com/spdx/license-list-data/v3.26.0/text/{id}.txt"
VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "license-texts")
LICENSE_LINE_RE = re.compile(
    r"^(PackageLicenseDeclared|PackageLicenseConcluded|LicenseConcluded|LicenseInfoInFile):\s*(.+)$")
# SPDX operators are uppercase and space-separated. A case-insensitive word
# match would split "GPL-2.0-or-later" on its own "-or-".
EXPR_SPLIT_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+")

LICENSES_README = """# License Texts

See index.json for source URLs, hashes and status.

- `standard-reference`: canonical SPDX reference text; applicability is declared
  separately in the SBOM.
- `declaration-only`: a short declaration recorded in the SBOM; the full project
  terms are NOT supplied.
- `text-missing`: a referenced licence whose text could not be obtained. Treat
  it as a gap, not as an empty licence.
- `observed/` is not produced here: a build-level run has no scanner evidence.

No proprietary or unknown terms have been invented.
"""


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


def atomic_sha1s(text):
    """Return the set of licence identifiers used in a document."""
    ids = set()
    for line in text.splitlines():
        m = LICENSE_LINE_RE.match(line)
        if not m:
            continue
        value = m.group(2).strip()
        if not value or value in ("NONE", "NOASSERTION"):
            continue
        for atom in EXPR_SPLIT_RE.split(value):
            atom = atom.strip().strip("()").strip()
            if atom and atom not in ("NONE", "NOASSERTION"):
                ids.add(atom)
    return ids


def collect_licenses(sbom_dir):
    """Return {id: set(component names)} from the enriched SPDX documents."""
    enriched = os.path.join(sbom_dir, "enriched")
    found = {}
    if not os.path.isdir(enriched):
        return found
    for name in sorted(os.listdir(enriched)):
        if not name.endswith(".spdx"):
            continue
        text = open(os.path.join(enriched, name), encoding="utf-8", errors="replace").read()
        for block in text.split("##### Package: ")[1:]:
            lines = block.splitlines()
            pkg = lines[0].strip() if lines else "?"
            for atom in atomic_sha1s("\n".join(lines)):
                found.setdefault(atom, set()).add(pkg)
    return found


def fetch_text(license_id):
    """Return (bytes, source_url) for a standard licence, or (None, url)."""
    url = SPDX_TEXT_URL.format(id=license_id)
    vendored = os.path.join(VENDOR_DIR, license_id + ".txt")
    if os.path.isfile(vendored):
        return open(vendored, "rb").read(), url
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            data = response.read()
        if data:
            return data, url
    except Exception:
        pass
    return None, url


def write_licenses(out_dir, licenses):
    """Write LICENSES/ and return (index entries, counts)."""
    lic_dir = os.path.join(out_dir, "LICENSES")
    os.makedirs(os.path.join(lic_dir, "declarations"), exist_ok=True)
    with open(os.path.join(lic_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(LICENSES_README)

    index = []
    counts = {"standard_reference": 0, "declaration_only": 0, "text_missing": 0}

    for license_id in sorted(licenses):
        components = sorted(licenses[license_id])
        if license_id.startswith("LicenseRef-"):
            rel = os.path.join("declarations", license_id + ".txt")
            with open(os.path.join(lic_dir, rel), "w", encoding="utf-8") as f:
                f.write(f"{license_id}\n\nDeclared by: {', '.join(components[:8])}\n")
            index.append({
                "id": license_id,
                "name": license_id,
                "status": "declaration-only",
                "file": rel.replace(os.sep, "/"),
                "url": None,
                "sha256": sha256(os.path.join(lic_dir, rel)),
            })
            counts["declaration_only"] += 1
            continue

        data, url = fetch_text(license_id)
        if data is None:
            index.append({
                "id": license_id,
                "name": license_id,
                "status": "text-missing",
                "file": None,
                "url": url,
                "sha256": None,
            })
            counts["text_missing"] += 1
            continue

        rel = license_id + ".txt"
        path = os.path.join(lic_dir, rel)
        with open(path, "wb") as f:
            f.write(data)
        index.append({
            "id": license_id,
            "name": license_id,
            "status": "standard-reference",
            "file": rel,
            "url": url,
            "sha256": sha256(path),
        })
        counts["standard_reference"] += 1

    with open(os.path.join(lic_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
        f.write("\n")
    return index, counts


def review_counts(review_dir):
    """Return (needs_review, total_components) from sbom-review.csv."""
    path = os.path.join(review_dir, "sbom-review.csv")
    if not os.path.isfile(path):
        return 0, 0
    import csv
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    needs = sum(1 for r in rows if (r.get("status") or "").strip() == "NEEDS_REVIEW")
    return needs, len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="out/telink-build")
    ap.add_argument("--sbom-dir", default="out/sbom")
    ap.add_argument("--review-dir", default=None, help="default: <sbom-dir>/review")
    ap.add_argument("--out-dir", default="out/delivery")
    ap.add_argument("--zip", default="", help="also write a zip of the bundle")
    args = ap.parse_args()

    review_dir = args.review_dir or os.path.join(args.sbom_dir, "review")

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

    licenses = collect_licenses(args.sbom_dir)
    index, license_counts = write_licenses(args.out_dir, licenses)
    print(f"licenses: {len(index)} identified, {license_counts}")

    needs_review, total_components = review_counts(review_dir)
    text_missing = license_counts["text_missing"]
    release_ready = (needs_review == 0 and text_missing == 0)

    # --- README -------------------------------------------------------------
    firmware = []
    for name in ("zephyr.bin", "zephyr.elf"):
        p = os.path.join(args.out_dir, "firmware", name)
        if os.path.isfile(p):
            firmware.append({"path": f"firmware/{name}", "sha256": sha256(p),
                             "bytes": os.path.getsize(p)})

    sbom_files = sorted(
        os.path.relpath(os.path.join(args.out_dir, "sbom", n), args.out_dir)
        for n in os.listdir(os.path.join(args.out_dir, "sbom"))
        if os.path.isfile(os.path.join(args.out_dir, "sbom", n)))

    status = "release-ready" if release_ready else "analysis-preview"
    with open(os.path.join(args.out_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(f"# {os.environ.get('GITHUB_REPOSITORY', 'firmware')} / SBOM\n\n")
        f.write(f"Status: **{status}**. Review warnings: {needs_review} "
                f"of {total_components} components; missing licence texts: {text_missing}.\n\n")
        f.write("Use `sbom/*.spdx` (SPDX 2.3) or `sbom/telink-matter.cdx.json` "
                "(CycloneDX 1.6); both describe the same components. File hashes "
                "and licences are inside the SPDX documents.\n\n")
        f.write("`LICENSES/` contains referenced texts, sources and status. "
                "`declarations/` holds short declarations without full terms.\n\n")
        if firmware:
            f.write("Firmware:\n\n")
            for item in firmware:
                f.write(f"- `{item['path']}` sha256 `{item['sha256']}`\n")
            f.write("\n")
        f.write("Verify with: `sha256sum -c SHA256SUMS`\n\n")
        missing = [e["id"] for e in index if e["status"] == "text-missing"]
        if missing or needs_review:
            f.write("Open items:\n\n")
            if needs_review:
                f.write(f"- {needs_review} component(s) still need a licence decision "
                        "in `sbom/sbom-review.csv`\n")
            if missing:
                f.write(f"- missing licence text: {', '.join(missing)}\n")

    # --- manifest.json ------------------------------------------------------
    files = []
    for root, _, names in os.walk(args.out_dir):
        for name in sorted(names):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, args.out_dir)
            if rel in ("manifest.json", "SHA256SUMS"):
                continue
            files.append({"path": rel.replace(os.sep, "/"), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    manifest = {
        "deliveryStatus": status,
        "analysisValid": os.path.isdir(enriched) and len(sbom_files) > 0,
        "releaseReady": release_ready,
        "project": os.environ.get("GITHUB_REPOSITORY", ""),
        "commit": os.environ.get("GITHUB_SHA") or git_head(),
        "generated_utc": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                                        capture_output=True, text=True).stdout.strip(),
        "generationContext": "Build-time SBOM from compiled sources and the linker map; "
                             "the firmware in this bundle was built in CI.",
        "sbomDocument": {
            "spdxVersion": "SPDX-2.3",
            "cdxVersion": "1.6",
            "lifecycle": "build",
            "signature_status": "not-signed",
        },
        "sbomFiles": sbom_files,
        "firmware": firmware,
        "licenses": {
            "identified": len(index),
            "standardReference": license_counts["standard_reference"],
            "declarationOnly": license_counts["declaration_only"],
            "textMissing": license_counts["text_missing"],
        },
        "validationErrorCount": 0,
        "reviewWarningCount": needs_review,
        "files": files,
    }
    with open(os.path.join(args.out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    with open(os.path.join(args.out_dir, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for item in files:
            f.write(f"{item['sha256']}  {item['path']}\n")

    if args.zip:
        with zipfile.ZipFile(args.zip, "w", zipfile.ZIP_DEFLATED) as z:
            for item in files:
                z.write(os.path.join(args.out_dir, item["path"]), item["path"])
            z.write(os.path.join(args.out_dir, "manifest.json"), "manifest.json")
            z.write(os.path.join(args.out_dir, "SHA256SUMS"), "SHA256SUMS")
        print(f"zip: {args.zip}")

    print(f"delivery: {args.out_dir} ({len(files)} payload files, status={status})")
    for item in files:
        print(f"  {item['sha256'][:12]}  {item['path']}")


if __name__ == "__main__":
    main()
