#!/usr/bin/env python3
#
# Copyright (c) 2026 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Enrich zspdx output so it satisfies the NTIA minimum elements.

Zephyr's `west spdx` (zspdx) emits four SPDX 2.3 tag-value documents that are
accurate about *files* but leave three NTIA-required package fields empty:

  PackageSupplier          -- never emitted at all
  PackageLicenseDeclared   -- always NOASSERTION
  ExternalRef (purl)       -- emitted for one package out of 142

This script fills those in, and is deliberately conservative about what it
asserts:

  * purl is derived mechanically from PackageDownloadLocation, so it is exact.
  * PackageSupplier is the repository owner for anything with a VCS location;
    for build-internal CMake targets (which have no upstream) it falls back to
    --default-supplier. That fallback is an *assertion by the SBOM producer*,
    not metadata from upstream -- see --default-supplier.
  * PackageLicenseDeclared is taken from PackageLicenseConcluded when zspdx
    already computed one (it handles OR expressions correctly), otherwise
    aggregated from the package's file-level LicenseInfoInFile entries. If the
    files disagree, the set is AND-joined, which is the conservative reading.
    Packages whose files are all NONE stay NOASSERTION -- this script never
    invents a license.

The script is idempotent: re-running it will not duplicate fields.

Usage:
    enrich_sbom.py <sbom-dir> [--default-supplier NAME] [--in-place]

Writes *.spdx into <sbom-dir>/enriched/ unless --in-place is given.
"""

import argparse
import json
import os
import re
import sys

# git+https://github.com/org/repo[@revision]
_VCS_RE = re.compile(r"^git\+(?P<url>[^@]+?)(?:@(?P<rev>.+))?$")
# Note: no trailing anchor -- download locations look like
# git+https://github.com/org/repo@<sha>-off, so the repo name is followed by
# '@<rev>', not by end-of-string.
_GITHUB_RE = re.compile(r"github\.com/(?P<org>[^/]+)/(?P<repo>[^/@]+)")

# zspdx appends the west state to the revision; it is not part of the version.
_STATE_SUFFIXES = ("-off", "-dirty")

# Licenses confirmed by the team live in module_licenses.json next to this
# script, so they can be edited without touching code. See that file for why
# the map is needed at all (short version: zspdx only reads an explicit
# SPDX-License-Identifier tag, and several upstream projects embed the full
# license text instead, so their files all come back NONE).
DEFAULT_LICENSE_MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "module_licenses.json")


def load_license_map(path):
    """Return {org/repo: SPDX-id} from the team-maintained JSON file."""
    if not path or not os.path.exists(path):
        print(f"WARNING: license map {path!r} not found; "
              f"no fallback licenses will be applied", file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    licenses = data.get("licenses", {})
    # Guard against a reviewer pasting an empty value.
    return {k: v for k, v in licenses.items() if isinstance(v, str) and v.strip()}


def license_from_repo(download_location, license_map):
    """Look up a module's license by the repository it was fetched from."""
    org, repo = repo_from_location(download_location)
    if not org:
        return None
    return license_map.get(f"{org}/{repo}")


def split_blocks(text):
    """Split a tag-value document into (header, [(kind, name, lines), ...]).

    Package blocks start at '##### Package: <name>'; everything else up to the
    first such marker is the document header.
    """
    parts = text.split("##### Package: ")
    header = parts[0]
    blocks = []
    for chunk in parts[1:]:
        lines = chunk.splitlines(keepends=True)
        name = lines[0].strip()
        blocks.append((name, lines[1:]))
    return header, blocks


def strip_state(version):
    for suffix in _STATE_SUFFIXES:
        if version.endswith(suffix):
            return version[: -len(suffix)]
    return version


def repo_from_location(download_location):
    """Return (org, repo) for a GitHub VCS download location, else (None, None)."""
    m = _VCS_RE.match(download_location or "")
    url = m.group("url") if m else (download_location or "")
    g = _GITHUB_RE.search(url)
    if not g:
        return None, None
    repo = g.group("repo")
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    return g.group("org"), repo


def revision_from_location(download_location, fallback_version=""):
    """Return the VCS revision with the west state suffix stripped."""
    m = _VCS_RE.match(download_location or "")
    rev = (m.group("rev") if m else None) or fallback_version
    return strip_state(rev or "")


def derive_purl(download_location, version):
    """Return a pkg:github/... purl, or None if not derivable."""
    org, repo = repo_from_location(download_location)
    if not org:
        return None
    rev = revision_from_location(download_location, version)
    base = f"pkg:github/{org}/{repo}"
    return f"{base}@{rev}" if rev else base


def field(lines, key):
    """Return the value of the first 'key: value' line, or None."""
    prefix = key + ":"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def package_license_declared(lines, download_location, license_map):
    """Derive a declared license, or None to leave it alone."""
    concluded = field(lines, "PackageLicenseConcluded")
    if concluded and concluded != "NOASSERTION":
        return concluded

    # No conclusion from zspdx -- aggregate what the files actually report.
    seen = set()
    for line in lines:
        if line.startswith("LicenseInfoInFile:"):
            value = line.split(":", 1)[1].strip()
            if value and value != "NONE":
                seen.add(value)
    if len(seen) == 1:
        return seen.pop()
    if seen:
        return " AND ".join(sorted(seen))

    # Files carry no SPDX tag (full-text license headers). Fall back to the
    # team-confirmed license for this repository, if there is one.
    return license_from_repo(download_location, license_map)


def enrich_block(lines, default_supplier, license_map):
    """Return new lines for one Package block with the missing fields filled."""
    name = field(lines, "PackageName") or "<unnamed>"
    version = field(lines, "PackageVersion") or ""
    dl = field(lines, "PackageDownloadLocation") or ""

    additions = {}  # field -> value, inserted after the block's leading fields

    # --- PackageSupplier -------------------------------------------------
    if field(lines, "PackageSupplier") is None:
        org, _ = repo_from_location(dl)
        additions["PackageSupplier"] = org if org else default_supplier

    # --- PackageLicenseDeclared -----------------------------------------
    if field(lines, "PackageLicenseDeclared") == "NOASSERTION":
        declared = package_license_declared(lines, dl, license_map)
        if declared:
            additions["PackageLicenseDeclared"] = declared

    # --- ExternalRef: purl ----------------------------------------------
    if not any(l.startswith("ExternalRef: PACKAGE_MANAGER purl") for l in lines):
        purl = derive_purl(dl, version)
        if purl:
            additions["ExternalRef"] = f"PACKAGE_MANAGER purl {purl}"

    if not additions:
        return lines, []

    out = []
    inserted = set()
    for line in lines:
        key = line.split(":", 1)[0] if ":" in line else ""

        # Replace in place where the field already exists.
        if key == "PackageLicenseDeclared" and "PackageLicenseDeclared" in additions:
            out.append(f"PackageLicenseDeclared: {additions['PackageLicenseDeclared']}\n")
            inserted.add("PackageLicenseDeclared")
            continue

        out.append(line)

        # Insert Supplier right after Version (or after SPDXID if no version).
        if "PackageSupplier" in additions and not inserted & {"PackageSupplier"}:
            if key in ("PackageVersion", "SPDXID"):
                out.append(f"PackageSupplier: {additions['PackageSupplier']}\n")
                inserted.add("PackageSupplier")

        # Insert purl after DownloadLocation so the VCS fields stay together.
        if "ExternalRef" in additions and key == "PackageDownloadLocation":
            out.append(f"ExternalRef: {additions['ExternalRef']}\n")
            inserted.add("ExternalRef")

    # Fallbacks if the anchor fields were absent.
    if "PackageSupplier" in additions and "PackageSupplier" not in inserted:
        out.insert(1, f"PackageSupplier: {additions['PackageSupplier']}\n")
    if "ExternalRef" in additions and "ExternalRef" not in inserted:
        out.append(f"ExternalRef: {additions['ExternalRef']}\n")

    return out, sorted(additions)


def process_document(text, default_supplier, license_map):
    header, blocks = split_blocks(text)
    out = [header]
    stats = {"packages": 0, "supplier": 0, "license": 0, "purl": 0}
    for name, lines in blocks:
        new_lines, added = enrich_block(lines, default_supplier, license_map)
        out.append(f"##### Package: {name}\n")
        out.extend(new_lines)
        stats["packages"] += 1
        if "PackageSupplier" in added:
            stats["supplier"] += 1
        if "PackageLicenseDeclared" in added:
            stats["license"] += 1
        if "ExternalRef" in added:
            stats["purl"] += 1
    return "".join(out), stats


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sbom_dir", help="directory containing *.spdx from `west spdx`")
    ap.add_argument("--default-supplier", default="Telink Semiconductor",
                    help="PackageSupplier for packages with no upstream VCS "
                         "location, i.e. build-internal CMake targets "
                         "(default: %(default)s)")
    ap.add_argument("--in-place", action="store_true",
                    help="overwrite the input files instead of writing to enriched/")
    ap.add_argument("--license-map", default=DEFAULT_LICENSE_MAP,
                    help="team-maintained JSON of confirmed component licenses "
                         "(default: %(default)s)")
    args = ap.parse_args()

    license_map = load_license_map(args.license_map)
    print(f"license map: {len(license_map)} confirmed entr"
          f"{'y' if len(license_map) == 1 else 'ies'} from {args.license_map}")

    src = args.sbom_dir
    docs = sorted(f for f in os.listdir(src) if f.endswith(".spdx"))
    if not docs:
        sys.exit(f"ERROR: no *.spdx files found in {src}")

    if args.in_place:
        dst = src
    else:
        dst = os.path.join(src, "enriched")
        os.makedirs(dst, exist_ok=True)

    totals = {"packages": 0, "supplier": 0, "license": 0, "purl": 0}
    for doc in docs:
        with open(os.path.join(src, doc), encoding="utf-8") as f:
            text = f.read()
        new_text, stats = process_document(text, args.default_supplier, license_map)
        with open(os.path.join(dst, doc), "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
        print(f"{doc:22} {stats['packages']:4d} pkg | "
              f"+{stats['supplier']:4d} supplier  +{stats['license']:4d} license  "
              f"+{stats['purl']:4d} purl")
        for k in totals:
            totals[k] += stats[k]

    print(f"{'TOTAL':22} {totals['packages']:4d} pkg | "
          f"+{totals['supplier']:4d} supplier  +{totals['license']:4d} license  "
          f"+{totals['purl']:4d} purl")
    print(f"\nwritten to: {dst}")


if __name__ == "__main__":
    main()
