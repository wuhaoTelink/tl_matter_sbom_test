#!/usr/bin/env python3
"""Emit auxiliary SBOM views from the enriched SPDX tag-value documents.

Produces, next to the tag-value set:

  <doc>.spdx.json        SPDX 2.3 JSON view of each document
  files.spdx.json        one file-level SPDX JSON document for the product
  files.cdx.json         CycloneDX 1.6 file-level view
  dependency-graph.json  nodes and edges derived from SPDX relationships

These are best-effort views built from the same parsed data; the tag-value
documents remain the source of truth.

Usage:
    make_auxiliary.py --sbom-dir out/sbom/enriched --out-dir out/sbom/aux
"""

import argparse
import hashlib
import json
import os
import re
import sys

REL_RE = re.compile(r"^Relationship:\s*(\S+)\s+(\S+)\s+(\S+)\s*$")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_doc(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    header, *chunks = text.split("##### Package: ")
    doc = {
        "spdxVersion": "", "dataLicense": "", "name": "", "namespace": "",
        "created": "", "creators": [], "relationships": [], "external_refs": [],
        "packages": [], "files": [],
    }
    for line in header.splitlines():
        if line.startswith("SPDXVersion:"):
            doc["spdxVersion"] = line.split(":", 1)[1].strip()
        elif line.startswith("DataLicense:"):
            doc["dataLicense"] = line.split(":", 1)[1].strip()
        elif line.startswith("DocumentName:"):
            doc["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("DocumentNamespace:"):
            doc["namespace"] = line.split(":", 1)[1].strip()
        elif line.startswith("Creator:"):
            doc["creators"].append(line.split(":", 1)[1].strip())
        elif line.startswith("Created:"):
            doc["created"] = line.split(":", 1)[1].strip()
        elif line.startswith("ExternalDocumentRef:"):
            doc["external_refs"].append(line.split(":", 1)[1].strip())
        else:
            m = REL_RE.match(line)
            if m:
                doc["relationships"].append({"from": m.group(1), "type": m.group(2), "to": m.group(3)})

    for chunk in chunks:
        lines = chunk.splitlines()
        name = lines[0].strip()
        pkg = {"name": name, "files": [], "external_refs": []}
        current = None
        for line in lines[1:]:
            if line.startswith("FileName:"):
                current = {
                    "fileName": line.split(":", 1)[1].strip(),
                    "checksums": [], "licenseConcluded": "NOASSERTION",
                    "licenseInfo": [], "copyright": "NOASSERTION",
                    "spdxid": "SPDXRef-File-" + re.sub(r"[^A-Za-z0-9.-]", "-", os.path.basename(line.split(":", 1)[1].strip())),
                    "package": name,
                }
                pkg["files"].append(current)
                doc["files"].append(current)
            elif line.startswith("SPDXID:") and current is None:
                pkg["SPDXID"] = line.split(":", 1)[1].strip()
            elif current is not None and line.startswith("SPDXID:"):
                current["spdxid"] = line.split(":", 1)[1].strip()
            elif current is not None and line.startswith("FileChecksum:"):
                _, alg, value = line.split(":", 2)
                current["checksums"].append({"algorithm": alg.strip(), "value": value.strip()})
            elif current is not None and line.startswith("LicenseConcluded:"):
                current["licenseConcluded"] = line.split(":", 1)[1].strip()
            elif current is not None and line.startswith("LicenseInfoInFile:"):
                current["licenseInfo"].append(line.split(":", 1)[1].strip())
            elif current is not None and line.startswith("FileCopyrightText:"):
                current["copyright"] = line.split(":", 1)[1].strip()
            elif line.startswith("Package"):
                key, value = line.split(":", 1)
                pkg[key] = value.strip()
            elif line.startswith("ExternalRef:"):
                pkg["external_refs"].append(line.split(":", 1)[1].strip())
            elif line.startswith("Relationship:"):
                m = REL_RE.match(line)
                if m:
                    doc["relationships"].append({"from": m.group(1), "type": m.group(2), "to": m.group(3)})
        doc["packages"].append(pkg)
    return doc


def package_json(pkg):
    out = {
        "SPDXID": pkg.get("SPDXID", ""),
        "name": pkg.get("PackageName", pkg["name"]),
        "downloadLocation": pkg.get("PackageDownloadLocation", "NOASSERTION"),
        "filesAnalyzed": pkg.get("FilesAnalyzed", "false").lower() == "true",
        "licenseConcluded": pkg.get("PackageLicenseConcluded", "NOASSERTION"),
        "licenseDeclared": pkg.get("PackageLicenseDeclared", "NOASSERTION"),
        "copyrightText": pkg.get("PackageCopyrightText", "NOASSERTION"),
    }
    if pkg.get("PackageVersion"):
        out["versionInfo"] = pkg["PackageVersion"]
    if pkg.get("PackageSupplier"):
        out["supplier"] = pkg["PackageSupplier"]
    if pkg.get("PackageVerificationCode"):
        out["packageVerificationCode"] = {"packageVerificationCodeValue": pkg["PackageVerificationCode"]}
    refs = []
    for ref in pkg.get("external_refs", []):
        parts = ref.split()
        if len(parts) >= 3:
            refs.append({
                "referenceCategory": parts[0],
                "referenceType": parts[1],
                "referenceLocator": parts[2],
            })
    if refs:
        out["externalRefs"] = refs
    if pkg["files"]:
        out["hasFiles"] = [f["spdxid"] for f in pkg["files"]]
    return out


def file_json(f):
    out = {
        "SPDXID": f["spdxid"],
        "fileName": f["fileName"],
        "checksums": [
            {"algorithm": c["algorithm"].replace("-", ""), "checksumValue": c["value"]}
            for c in f["checksums"]
        ],
        "licenseConcluded": f["licenseConcluded"],
        "licenseInfoInFiles": f["licenseInfo"] or ["NONE"],
        "copyrightText": f["copyright"],
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    docs = []
    for name in sorted(os.listdir(args.sbom_dir)):
        if name.endswith(".spdx"):
            docs.append((name, parse_doc(os.path.join(args.sbom_dir, name))))
    if not docs:
        sys.exit("no enriched SPDX documents found")

    # Per-document SPDX JSON
    for name, doc in docs:
        payload = {
            "spdxVersion": doc["spdxVersion"] or "SPDX-2.3",
            "dataLicense": doc["dataLicense"] or "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc["name"] or name,
            "documentNamespace": doc["namespace"],
            "creationInfo": {"created": doc["created"], "creators": doc["creators"]},
            "packages": [package_json(p) for p in doc["packages"]],
            "files": [file_json(f) for f in doc["files"]],
            "relationships": [
                {"spdxElementId": r["from"], "relationshipType": r["type"], "relatedSpdxElement": r["to"]}
                for r in doc["relationships"]
            ],
        }
        if doc["external_refs"]:
            payload["externalDocumentRefs"] = doc["external_refs"]
        with open(os.path.join(args.out_dir, name + ".json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")

    # Combined file-level and graph views
    product = docs[0][1]["name"] or "product"
    namespace = docs[0][1]["namespace"]
    files, seen = [], set()
    for _, doc in docs:
        for f in doc["files"]:
            key = (f["fileName"], tuple(c["value"] for c in f["checksums"]))
            if key in seen:
                continue
            seen.add(key)
            item = dict(f)
            item["spdxid"] = "SPDXRef-File-" + hashlib.sha1(
                (f["fileName"] + "".join(c["value"] for c in f["checksums"])).encode()).hexdigest()[:16]
            files.append(item)

    verification = hashlib.sha1("".join(
        sorted(c["value"] for f in files for c in f["checksums"] if c["algorithm"].upper() == "SHA1")
    ).encode()).hexdigest()

    files_spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": product + " files",
        "documentNamespace": namespace.rstrip("/") + "/files",
        "creationInfo": {"created": docs[0][1]["created"], "creators": docs[0][1]["creators"]},
        "packages": [{
            "SPDXID": "SPDXRef-Package-files",
            "name": product + " files",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue": verification},
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "hasFiles": [f["spdxid"] for f in files],
        }],
        "files": [file_json(f) for f in files],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-files"},
            *[{"spdxElementId": "SPDXRef-Package-files", "relationshipType": "CONTAINS", "relatedSpdxElement": f["spdxid"]} for f in files],
        ],
    }
    with open(os.path.join(args.out_dir, "files.spdx.json"), "w", encoding="utf-8") as f:
        json.dump(files_spdx, f, indent=2)
        f.write("\n")

    cdx_alg = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512", "MD5": "MD5"}
    components = []
    for f in files:
        comp = {
            "type": "file",
            "bom-ref": f["spdxid"],
            "name": f["fileName"],
            "hashes": [
                {"alg": cdx_alg.get(c["algorithm"].replace("-", "").upper(), c["algorithm"]),
                 "content": c["value"]}
                for c in f["checksums"]
            ],
        }
        lic_entries = []
        for lic in f["licenseInfo"]:
            if lic in ("NONE", "NOASSERTION"):
                continue
            if re.search(r"\s+(AND|OR|WITH)\s+", lic):
                lic_entries.append({"expression": lic})
            else:
                lic_entries.append({"license": {"id": lic}})
        if lic_entries:
            comp["licenses"] = lic_entries
        components.append(comp)
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "bom-ref": "product-files", "name": product},
        },
        "components": components,
    }
    with open(os.path.join(args.out_dir, "files.cdx.json"), "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2)
        f.write("\n")

    nodes, edges, node_ids = [], [], set()
    for _, doc in docs:
        for p in doc["packages"]:
            pid = p.get("SPDXID")
            if pid and pid not in node_ids:
                node_ids.add(pid)
                nodes.append({"id": pid, "name": p.get("PackageName", p["name"]), "kind": "package",
                              "version": p.get("PackageVersion", "")})
        for r in doc["relationships"]:
            edges.append({"from": r["from"], "type": r["type"], "to": r["to"]})
    graph = {
        "product": product,
        "commit": os.environ.get("GITHUB_SHA", ""),
        "nodes": nodes,
        "edges": edges,
    }
    with open(os.path.join(args.out_dir, "dependency-graph.json"), "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
        f.write("\n")

    print(f"auxiliary: {len(docs)} documents, {len(files)} files, {len(nodes)} nodes, {len(edges)} edges")


if __name__ == "__main__":
    main()
