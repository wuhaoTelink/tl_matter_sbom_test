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
"""Convert zspdx SPDX output to CycloneDX JSON.

Many commercial SCA platforms (Dependency-Track, and most customer-side
tooling) ingest CycloneDX but not SPDX tag-value. This reads the *enriched*
SPDX documents produced by enrich_sbom.py -- it needs the purl and supplier
fields that script adds -- and emits one CycloneDX 1.6 document.

Scope: by default only packages that carry a purl are emitted as components.
Those are the real third-party components (the Zephyr modules and the Matter
stack). The ~100 CMake targets in build.spdx are build-internal artifacts, not
components a consumer can act on, and they have no purl; pass --include-all to
keep them anyway.

The same component shows up twice in the raw zspdx output -- once in
zephyr.spdx as "<mod>-sources" and once in modules-deps.spdx as "<mod>-deps" --
so components are de-duplicated by purl, preferring the entry that carries a
license.

Usage:
    spdx_to_cyclonedx.py <sbom-dir> -o sbom.cdx.json \
        [--product-name NAME] [--product-version VER] [--include-all]
"""

import argparse
import glob
import json
import os
import sys
import uuid

# Stable namespace so re-running over the same input yields the same
# serialNumber, which lets consumers diff two builds.
_UUID_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# CycloneDX license ids are the SPDX ids; anything else must go in "name".
# We only emit "id" for values that look like plain SPDX identifiers.
def license_entry(value):
    if not value or value in ("NOASSERTION", "NONE"):
        return None
    # Compound expressions must use the "expression" form.
    if any(op in value for op in (" AND ", " OR ", " WITH ")):
        return {"expression": value}
    return {"license": {"id": value}}


def parse_packages(text):
    """Yield dicts of the fields we care about, one per Package block."""
    for chunk in text.split("##### Package: ")[1:]:
        lines = chunk.splitlines()
        pkg = {"name": lines[0].strip(), "licenses": []}
        for line in lines[1:]:
            if line.startswith("PackageName:"):
                pkg["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageVersion:"):
                pkg["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageSupplier:"):
                pkg["supplier"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageDownloadLocation:"):
                pkg["download"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageLicenseDeclared:"):
                pkg["declared"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageLicenseConcluded:"):
                pkg["concluded"] = line.split(":", 1)[1].strip()
            elif line.startswith("ExternalRef: PACKAGE_MANAGER purl"):
                pkg["purl"] = line.split()[-1]
            elif line.startswith("FileName:"):
                break  # file entries follow; not needed here
        yield pkg


def strip_state(version):
    for suffix in ("-off", "-dirty"):
        if version.endswith(suffix):
            return version[: -len(suffix)]
    return version


def build_components(packages, include_all):
    """De-duplicate by purl, preferring the entry that has a license."""
    by_ref = {}
    for pkg in packages:
        ref = pkg.get("purl")
        if not ref:
            if not include_all:
                continue
            ref = "spdx:" + pkg["name"]  # build-internal, no purl
        prev = by_ref.get(ref)
        if prev is None or (not prev.get("license") and pkg.get("license")):
            by_ref[ref] = pkg
    return by_ref


def to_component(ref, pkg):
    comp = {
        "type": "library",
        "bom-ref": ref,
        "name": pkg["name"],
    }
    if pkg.get("version"):
        comp["version"] = strip_state(pkg["version"])
    if pkg.get("supplier") and pkg["supplier"] != "NOASSERTION":
        comp["supplier"] = {"name": pkg["supplier"]}
    if ref.startswith("pkg:"):
        comp["purl"] = ref
    if pkg.get("license"):
        comp["licenses"] = [pkg["license"]]
    return comp


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sbom_dir", help="directory of enriched *.spdx documents")
    ap.add_argument("-o", "--output", required=True, help="CycloneDX JSON output path")
    ap.add_argument("--product-name", default="Telink Matter lighting-app (tl3238x)")
    ap.add_argument("--product-version", default="1.5.0")
    ap.add_argument("--product-license", default="Apache-2.0")
    ap.add_argument("--include-all", action="store_true",
                    help="also emit build-internal CMake targets (no purl)")
    args = ap.parse_args()

    docs = sorted(glob.glob(os.path.join(args.sbom_dir, "*.spdx")))
    if not docs:
        sys.exit(f"ERROR: no *.spdx files found in {args.sbom_dir}")

    packages = []
    timestamp = None
    for path in docs:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if timestamp is None:
            for line in text.splitlines():
                if line.startswith("Created:"):
                    timestamp = line.split(":", 1)[1].strip()
                    break
        for pkg in parse_packages(text):
            # Pick whichever license field is populated.
            for key in ("declared", "concluded"):
                entry = license_entry(pkg.get(key))
                if entry:
                    pkg["license"] = entry
                    break
            packages.append(pkg)

    by_ref = build_components(packages, args.include_all)
    root_ref = "urn:telink:tl_matter:lighting-app:tl3238x"

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(_UUID_NS, root_ref + str(len(by_ref)))),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Zephyr Project", "name": "zspdx",
                       "externalReferences": [
                           {"type": "website",
                            "url": "https://docs.zephyrproject.org/latest/develop/west/zephyr-cmds.html"}]}],
            "component": {
                "type": "firmware",
                "bom-ref": root_ref,
                "name": args.product_name,
                "version": args.product_version,
                "licenses": [{"license": {"id": args.product_license}}],
            },
        },
        "components": [to_component(ref, pkg) for ref, pkg in sorted(by_ref.items())],
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(by_ref.keys())},
        ],
    }

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")

    with_lic = sum(1 for c in doc["components"] if c.get("licenses"))
    print(f"components : {len(doc['components'])}")
    print(f"  with purl: {sum(1 for c in doc['components'] if c.get('purl'))}")
    print(f"  licensed : {with_lic}")
    print(f"written to : {args.output}")


if __name__ == "__main__":
    main()
