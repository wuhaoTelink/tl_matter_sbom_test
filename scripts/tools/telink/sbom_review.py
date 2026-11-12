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
"""Produce the human-review artefacts for an SBOM.

Two outputs:

  sbom-review.csv   one row per real component, with a confirmed_license column
                    for a reviewer to fill in. Opens directly in Excel, and
                    unlike .xlsx it is diffable in a PR -- which matters,
                    because the review itself is what compliance is auditing.

  sbom-gaps.md      a summary: NTIA element coverage, what is unresolved, and
                    why. Meant to be read first.

Only packages that carry a purl are listed as components. In this build that
is 21 of 142; the other 121 are CMake build targets (drivers--gpio, kernel,
zephyr-pre0, ...) which have no upstream and no independent license, so
putting them in front of a reviewer just wastes their time. They are counted
in the report so the exclusion is explicit rather than silent.

After a reviewer fills confirmed_license, fold the answers back with:

    sbom_review.py --merge sbom-review.csv

which rewrites module_licenses.json. That keeps one maintained source of truth
while still allowing a spreadsheet workflow.

Usage:
    sbom_review.py <sbom-dir> [--out-dir DIR] [--license-map FILE]
    sbom_review.py --merge <filled.csv> [--license-map FILE]
"""

import argparse
import csv
import json
import os
import re
import sys

DEFAULT_LICENSE_MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "module_licenses.json")

_GITHUB_RE = re.compile(r"github\.com/(?P<org>[^/]+)/(?P<repo>[^/@]+)")

CSV_FIELDS = ["status", "component", "repo", "version", "license",
              "confirmed_license", "purl", "notes"]


def parse_packages(text):
    for chunk in text.split("##### Package: ")[1:]:
        lines = chunk.splitlines()
        pkg = {"name": lines[0].strip()}
        for line in lines[1:]:
            if line.startswith("PackageName:"):
                pkg["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageVersion:"):
                pkg["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageDownloadLocation:"):
                pkg["download"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageLicenseDeclared:"):
                pkg["license"] = line.split(":", 1)[1].strip()
            elif line.startswith("ExternalRef: PACKAGE_MANAGER purl"):
                pkg["purl"] = line.split()[-1]
            elif line.startswith("FileName:"):
                break
        yield pkg


_PURL_RE = re.compile(r"^pkg:github/(?P<org>[^/]+)/(?P<repo>[^@]+)")


def repo_of(download_location, purl=""):
    """Return 'org/repo', preferring the download location.

    Packages in modules-deps.spdx carry a purl but no PackageDownloadLocation,
    so fall back to the purl -- otherwise those rows come out with an empty
    repo and a reviewer has nothing to look up.
    """
    m = _GITHUB_RE.search(download_location or "")
    if m:
        repo = m.group("repo")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        return f"{m.group('org')}/{repo}"

    m = _PURL_RE.match(purl or "")
    if m:
        return f"{m.group('org')}/{m.group('repo')}"
    return ""


def strip_state(version):
    for suffix in ("-off", "-dirty"):
        if version.endswith(suffix):
            return version[: -len(suffix)]
    return version


def collect(sbom_dir):
    """Return (components, all_packages) with components = those having a purl."""
    components, total = [], 0
    for fn in sorted(os.listdir(sbom_dir)):
        if not fn.endswith(".spdx"):
            continue
        with open(os.path.join(sbom_dir, fn), encoding="utf-8") as f:
            text = f.read()
        for pkg in parse_packages(text):
            total += 1
            if pkg.get("purl"):
                components.append(pkg)

    # The same component appears as <mod>-sources and <mod>-deps; keep the
    # entry that actually carries a license, and de-duplicate by purl.
    by_purl = {}
    for pkg in components:
        ref = pkg["purl"]
        prev = by_purl.get(ref)
        if prev is None or (prev.get("license") in (None, "NOASSERTION")
                            and pkg.get("license") not in (None, "NOASSERTION")):
            by_purl[ref] = pkg
    return list(by_purl.values()), total


def write_csv(path, components, license_map, needs_review):
    rows = []
    for pkg in sorted(components, key=lambda p: p["name"]):
        repo = repo_of(pkg.get("download", ""), pkg.get("purl", ""))
        detected = pkg.get("license", "NOASSERTION")
        resolved = detected not in ("", "NOASSERTION", None)
        rows.append({
            "status": "OK" if resolved else "NEEDS_REVIEW",
            "component": pkg["name"],
            "repo": repo,
            "version": strip_state(pkg.get("version", "")),
            "license": detected,
            # Deliberately left blank even when resolved: this column is the
            # reviewer's input and nothing else. Pre-filling it would make
            # --merge write auto-derived values into module_licenses.json,
            # bloating the map with entries zspdx already handles.
            "confirmed_license": "",
            "purl": pkg["purl"],
            "notes": "" if resolved else needs_review.get(repo, "unconfirmed"),
        })

    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    return rows


def write_report(path, rows, total, components):
    need = [r for r in rows if r["status"] != "OK"]
    lic_ok = sum(1 for r in rows if r["license"] not in ("NOASSERTION", "", None))
    sup_ok = sum(1 for r in rows if r["repo"])
    lines = [
        "# tl_matter SBOM review",
        "",
        "Generated by `scripts/tools/telink/sbom_review.py`. Read this first,",
        "then work through `sbom-review.csv`.",
        "",
        "## Scope",
        "",
        f"- Packages in the SPDX output: **{total}**",
        f"- Real components (carry a purl): **{len(rows)}**",
        f"- Build-internal CMake targets, not listed individually: "
        f"**{total - len(components)}**",
        "",
        "The CMake targets (`drivers--gpio`, `kernel`, `zephyr-pre0`, ...) are",
        "artifacts of the build itself. They have no upstream project and no",
        "independent license, so they are counted here but excluded from review.",
        "",
        "## Component status",
        "",
        f"- License resolved: **{lic_ok} / {len(rows)}**",
        f"- Upstream repository identified: **{sup_ok} / {len(rows)}**",
        f"- **Awaiting human confirmation: {len(need)}**",
        "",
    ]
    if need:
        lines += [
            "## Needs review",
            "",
            "| component | repo | why |",
            "| --- | --- | --- |",
        ]
        for r in need:
            lines.append(f"| `{r['component']}` | {r['repo'] or '-'} | {r['notes']} |")
        lines += [
            "",
            "## How to resolve",
            "",
            "1. Fill the `confirmed_license` column in `sbom-review.csv` with an",
            "   SPDX identifier or expression (e.g. `Apache-2.0`, or",
            "   `MIT OR GPL-2.0-or-later`).",
            "2. Fold the answers back:",
            "",
            "   ```",
            "   sbom_review.py --merge sbom-review.csv",
            "   ```",
            "",
            "3. Commit the updated `module_licenses.json`. The next CI run will",
            "   resolve these components automatically and this list will shrink.",
            "",
        ]
    else:
        lines += ["## Needs review", "",
                  "Nothing outstanding -- every component has a confirmed license.", ""]

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def merge_csv(csv_path, map_path):
    """Fold a filled review CSV back into module_licenses.json."""
    with open(map_path, encoding="utf-8") as f:
        data = json.load(f)
    licenses = data.setdefault("licenses", {})
    needs_review = data.setdefault("needs_review", {})

    added, skipped = [], []
    with open(csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            repo = (row.get("repo") or "").strip()
            value = (row.get("confirmed_license") or "").strip()
            if not repo:
                continue
            if not value:
                skipped.append(repo)
                continue
            licenses[repo] = value
            needs_review.pop(repo, None)  # now confirmed
            added.append(f"{repo} = {value}")

    with open(map_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"merged {len(added)} confirmed license(s) into {map_path}")
    for a in added:
        print(f"   + {a}")
    if skipped:
        print(f"still blank in the CSV ({len(skipped)}): {', '.join(sorted(set(skipped)))}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sbom_dir", nargs="?",
                    help="directory of enriched *.spdx documents")
    ap.add_argument("--out-dir", help="where to write the review artefacts "
                                      "(default: the sbom dir)")
    ap.add_argument("--license-map", default=DEFAULT_LICENSE_MAP,
                    help="team-maintained license JSON (default: %(default)s)")
    ap.add_argument("--merge", metavar="CSV",
                    help="fold a filled review CSV back into the license map, "
                         "then exit")
    args = ap.parse_args()

    if args.merge:
        merge_csv(args.merge, args.license_map)
        return

    if not args.sbom_dir:
        ap.error("sbom_dir is required unless --merge is used")

    needs_review = {}
    if os.path.exists(args.license_map):
        with open(args.license_map, encoding="utf-8") as f:
            needs_review = json.load(f).get("needs_review", {})

    components, total = collect(args.sbom_dir)
    if not components:
        sys.exit(f"ERROR: no packages with a purl found in {args.sbom_dir}")

    out = args.out_dir or args.sbom_dir
    os.makedirs(out, exist_ok=True)
    rows = write_csv(os.path.join(out, "sbom-review.csv"), components,
                     {}, needs_review)
    write_report(os.path.join(out, "sbom-gaps.md"), rows, total, components)

    need = sum(1 for r in rows if r["status"] != "OK")
    print(f"components        : {len(rows)}")
    print(f"  resolved        : {len(rows) - need}")
    print(f"  NEEDS_REVIEW    : {need}")
    print(f"build-internal pkg: {total - len(components)} (excluded from review)")
    print(f"written           : {os.path.join(out, 'sbom-review.csv')}")
    print(f"                    {os.path.join(out, 'sbom-gaps.md')}")


if __name__ == "__main__":
    main()
