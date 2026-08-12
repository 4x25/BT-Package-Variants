#!/usr/bin/env python3
"""Build independently installable, consistently signed variants of an APK.

The APK's code namespace is deliberately left alone.  Only Android application
identity fields and the resource package namespace are changed.  The script is
strict by design: if the upstream layout no longer matches the assumptions that
make this transformation safe, it stops before publishing any APK.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


APKEDITOR_VERSION = "1.4.9"
ANDROID_URI = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_URI}}}"
TARGET_STRING_KEYS = (
    "settings_about_sideload_phone_hint",
    "settings_about_sideload_pkg_mismatch",
    "settings_about_sideload_subtitle",
)
TARGET_STRING_DIRS = ("values", "values-zh")

PACKAGE_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z"
)
DEX_RE = re.compile(r"classes(?:(\d+))?\.dex\Z")
SIGNATURE_SUFFIXES = {".SF", ".RSA", ".DSA", ".EC"}
SENSITIVE_ENVIRONMENT = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "KEYSTORE_PASSWORD",
    "KEY_PASSWORD",
}

# Attributes whose values are Java/Android class names.  Relative values must
# be made absolute before changing manifest@package or Android would resolve
# them in the new (code-less) namespace.
CLASS_ATTRIBUTES: Mapping[str, tuple[str, ...]] = {
    "application": (
        "name",
        "backupAgent",
        "manageSpaceActivity",
        "appComponentFactory",
        "zygotePreloadName",
    ),
    "activity": ("name", "parentActivityName"),
    "activity-alias": ("name", "targetActivity"),
    "service": ("name",),
    "receiver": ("name",),
    "provider": ("name",),
    "instrumentation": ("name",),
}

PERMISSION_DECLARATIONS = {"permission", "permission-group", "permission-tree"}
PERMISSION_REFERENCES = {"uses-permission", "uses-permission-sdk-23"}
PREFIX_IDENTITY_ATTRIBUTES = {
    "process",
    "taskAffinity",
    "targetPackage",
    "sharedUserId",
}
PERMISSION_ATTRIBUTES = {"permission", "readPermission", "writePermission"}


class RepackError(RuntimeError):
    """A safe, user-actionable repack failure."""


@dataclasses.dataclass(frozen=True)
class Badging:
    package: str
    version_code: str
    version_name: str
    min_sdk: int
    target_sdk: str
    launchable_activity: str | None


@dataclasses.dataclass(frozen=True)
class SourceModel:
    package: str
    badging: Badging
    dex_digests: Mapping[str, str]
    component_classes: collections.Counter[tuple[str, str, str]]


@dataclasses.dataclass(frozen=True)
class VariantExpectation:
    package: str
    identity: collections.Counter[tuple[str, str, str]]
    component_classes: collections.Counter[tuple[str, str, str]]


def local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def android_attr(element: ET.Element, name: str) -> str | None:
    return element.get(ANDROID + name)


def set_android_attr(element: ET.Element, name: str, value: str) -> None:
    element.set(ANDROID + name, value)


def package_prefixed(value: str, package: str) -> bool:
    return value == package or value.startswith(package + ".")


def replace_package_prefix(value: str, source: str, target: str) -> str:
    if value == source:
        return target
    if value.startswith(source + "."):
        return target + value[len(source) :]
    return value


def contains_package_token(value: str, package: str) -> bool:
    # A target such as com.chinasoul.bt1 contains the source text but not the
    # source package token.  Letters, numbers and '_' can extend a package
    # segment; a '.' starts a member within the source package.
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(package)}(?![A-Za-z0-9_])"
    return re.search(pattern, value) is not None


def contains_standalone_package(value: str, package: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9_.]){re.escape(package)}(?![A-Za-z0-9_.])"
    return re.search(pattern, value) is not None


def resolve_class_name(package: str, value: str) -> str:
    if value.startswith("."):
        return package + value
    if "." not in value:
        return package + "." + value
    return value


def run_checked(
    command: Sequence[str], *, env: Mapping[str, str] | None = None
) -> str:
    child_env = (
        {key: value for key, value in os.environ.items() if key not in SENSITIVE_ENVIRONMENT}
        if env is None
        else dict(env)
    )
    try:
        result = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=child_env,
        )
    except OSError as error:
        raise RepackError(f"unable to run {command[0]}: {error}") from error
    if result.returncode != 0:
        rendered = " ".join(command)
        raise RepackError(
            f"command failed ({result.returncode}): {rendered}\n{result.stdout.rstrip()}"
        )
    return result.stdout


def require_executable(value: str) -> str:
    if os.sep in value:
        path = Path(value)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RepackError(f"executable not found: {value}")
        return str(path)
    resolved = shutil.which(value)
    if resolved is None:
        raise RepackError(f"required executable not found on PATH: {value}")
    return resolved


def validate_package_name(package: str, label: str) -> None:
    if not PACKAGE_RE.fullmatch(package):
        raise RepackError(f"invalid {label} package name: {package!r}")


def dex_sort_key(name: str) -> int:
    match = DEX_RE.fullmatch(name)
    if match is None:
        raise ValueError(name)
    return 1 if match.group(1) is None else int(match.group(1))


def hash_stream(stream: object) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)  # type: ignore[attr-defined]
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def inspect_apk_zip(path: Path) -> dict[str, str]:
    if not path.is_file() or not zipfile.is_zipfile(path):
        raise RepackError(f"input is not a readable APK/ZIP: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            duplicates = sorted(
                name
                for name, count in collections.Counter(names).items()
                if count > 1
            )
            if duplicates:
                raise RepackError(
                    "APK contains duplicate ZIP entries: " + ", ".join(duplicates)
                )
            for info in infos:
                pure = PurePosixPath(info.filename)
                unix_mode = info.external_attr >> 16
                if (
                    info.filename.startswith("/")
                    or "\\" in info.filename
                    or ".." in pure.parts
                    or stat.S_ISLNK(unix_mode)
                ):
                    raise RepackError(f"unsafe ZIP entry: {info.filename!r}")
            for required in ("AndroidManifest.xml", "resources.arsc"):
                if required not in names:
                    raise RepackError(f"APK is missing {required}")
            bad_entry = archive.testzip()
            if bad_entry is not None:
                raise RepackError(f"corrupt ZIP entry: {bad_entry}")

            dex_names = sorted(
                (name for name in names if DEX_RE.fullmatch(name)), key=dex_sort_key
            )
            if not dex_names or dex_names[0] != "classes.dex":
                raise RepackError("APK has no root classes.dex")
            expected = ["classes.dex"] + [
                f"classes{number}.dex" for number in range(2, len(dex_names) + 1)
            ]
            if dex_names != expected:
                raise RepackError(
                    "APK DEX entries are not a consecutive classes*.dex set: "
                    + ", ".join(dex_names)
                )
            return {
                name: hash_stream(archive.open(name, "r")) for name in dex_names
            }
    except (OSError, zipfile.BadZipFile) as error:
        raise RepackError(f"unable to inspect APK {path}: {error}") from error


def parse_badging(text: str) -> Badging:
    package_line = next(
        (line for line in text.splitlines() if line.startswith("package: ")), None
    )
    if package_line is None:
        raise RepackError("aapt2 badging output has no package line")

    def package_field(name: str) -> str:
        match = re.search(rf"(?:^| ){re.escape(name)}='([^']*)'", package_line)
        if match is None:
            raise RepackError(f"aapt2 badging output has no {name}")
        return match.group(1)

    def line_value(prefix: str) -> str:
        match = re.search(rf"^{re.escape(prefix)}:'([^']*)'$", text, re.MULTILINE)
        if match is None:
            raise RepackError(f"aapt2 badging output has no {prefix}")
        return match.group(1)

    minimum = line_value("sdkVersion")
    if not minimum.isdecimal():
        raise RepackError(f"non-numeric minSdkVersion is unsupported: {minimum!r}")
    launch_match = re.search(
        r"^launchable-activity: name='([^']*)'", text, re.MULTILINE
    )
    return Badging(
        package=package_field("name"),
        version_code=package_field("versionCode"),
        version_name=package_field("versionName"),
        min_sdk=int(minimum),
        target_sdk=line_value("targetSdkVersion"),
        launchable_activity=launch_match.group(1) if launch_match else None,
    )


def read_badging(aapt2: str, apk: Path) -> Badging:
    return parse_badging(run_checked((aapt2, "dump", "badging", str(apk))))


def component_snapshot(
    root: ET.Element, package: str
) -> collections.Counter[tuple[str, str, str]]:
    result: collections.Counter[tuple[str, str, str]] = collections.Counter()
    for element in root.iter():
        tag = local_name(element.tag)
        for attribute in CLASS_ATTRIBUTES.get(tag, ()):
            value = android_attr(element, attribute)
            if value:
                result[(tag, attribute, resolve_class_name(package, value))] += 1
    return result


def identity_snapshot(root: ET.Element) -> collections.Counter[tuple[str, str, str]]:
    result: collections.Counter[tuple[str, str, str]] = collections.Counter()
    package = root.get("package")
    if package is not None:
        result[("manifest", "package", package)] += 1
    shared_user = android_attr(root, "sharedUserId")
    if shared_user:
        result[("manifest", "sharedUserId", shared_user)] += 1

    for element in root.iter():
        tag = local_name(element.tag)
        names: set[str] = set(PERMISSION_ATTRIBUTES | PREFIX_IDENTITY_ATTRIBUTES)
        if tag in PERMISSION_DECLARATIONS | PERMISSION_REFERENCES:
            names.add("name")
        if tag == "provider":
            names.add("authorities")
        for name in names:
            value = android_attr(element, name)
            if value:
                result[(tag, name, value)] += 1
    return result


def manifest_occurrence_is_preserved(
    tag: str, attribute: str, value: str, source: str
) -> bool:
    if attribute in CLASS_ATTRIBUTES.get(tag, ()):
        return True
    # Custom actions/categories and metadata are code-facing identifiers, not
    # install identity.  Rewriting them without rewriting DEX would be unsafe.
    if attribute == "name" and tag in {"action", "category", "meta-data"}:
        return True
    if attribute == "value" and tag == "meta-data":
        return True
    return not contains_package_token(value, source)


def transform_manifest(
    manifest: Path, target: str
) -> tuple[str, VariantExpectation]:
    ET.register_namespace("android", ANDROID_URI)
    try:
        tree = ET.parse(manifest)
    except (OSError, ET.ParseError) as error:
        raise RepackError(f"unable to parse decoded manifest: {error}") from error
    root = tree.getroot()
    if local_name(root.tag) != "manifest":
        raise RepackError("decoded AndroidManifest.xml root is not <manifest>")
    source = root.get("package")
    if source is None:
        raise RepackError("decoded manifest has no package attribute")
    validate_package_name(source, "source")
    validate_package_name(target, "target")
    if source == target:
        raise RepackError("target package must differ from source package")

    original_components = component_snapshot(root, source)
    for element in root.iter():
        tag = local_name(element.tag)
        for attribute in CLASS_ATTRIBUTES.get(tag, ()):
            value = android_attr(element, attribute)
            if value and (value.startswith(".") or "." not in value):
                set_android_attr(element, attribute, resolve_class_name(source, value))

    root.set("package", target)
    shared_user = android_attr(root, "sharedUserId")
    if shared_user and package_prefixed(shared_user, source):
        set_android_attr(
            root, "sharedUserId", replace_package_prefix(shared_user, source, target)
        )

    for element in root.iter():
        tag = local_name(element.tag)
        if tag in PERMISSION_DECLARATIONS | PERMISSION_REFERENCES:
            value = android_attr(element, "name")
            if value and package_prefixed(value, source):
                set_android_attr(
                    element, "name", replace_package_prefix(value, source, target)
                )

        for attribute in PERMISSION_ATTRIBUTES | PREFIX_IDENTITY_ATTRIBUTES:
            value = android_attr(element, attribute)
            if value and package_prefixed(value, source):
                set_android_attr(
                    element,
                    attribute,
                    replace_package_prefix(value, source, target),
                )

        if tag == "provider":
            authorities = android_attr(element, "authorities")
            if authorities:
                tokens = authorities.split(";")
                rewritten = [
                    replace_package_prefix(token, source, target)
                    if package_prefixed(token, source)
                    else token
                    for token in tokens
                ]
                set_android_attr(element, "authorities", ";".join(rewritten))

    # Do not silently guess how a newly introduced source-package field should
    # behave.  It may be identity or a code-facing identifier.
    for element in root.iter():
        tag = local_name(element.tag)
        if element.text and contains_package_token(element.text, source):
            raise RepackError(
                f"unclassified source package in manifest text under <{tag}>"
            )
        for qualified_name, value in element.attrib.items():
            attribute = local_name(qualified_name)
            if not manifest_occurrence_is_preserved(tag, attribute, value, source):
                raise RepackError(
                    "unclassified source-package manifest field: "
                    f"<{tag}>@{attribute}={value!r}"
                )

    transformed_components = component_snapshot(root, target)
    if transformed_components != original_components:
        raise RepackError("manifest component class semantics changed")
    expectation = VariantExpectation(
        package=target,
        identity=identity_snapshot(root),
        component_classes=original_components,
    )
    tree.write(manifest, encoding="utf-8", xml_declaration=True)
    return source, expectation


def replace_text_in_element(element: ET.Element, source: str, target: str) -> int:
    replacements = 0
    for node in element.iter():
        if node.text:
            count = node.text.count(source)
            replacements += count
            node.text = node.text.replace(source, target)
        if node.tail:
            count = node.tail.count(source)
            replacements += count
            node.tail = node.tail.replace(source, target)
    return replacements


def transform_resources(decoded: Path, source: str, target: str) -> None:
    candidates: list[tuple[Path, dict[str, object]]] = []
    for metadata in sorted(decoded.glob("resources/package_*/package.json")):
        try:
            document = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RepackError(f"unable to parse {metadata}: {error}") from error
        if document.get("package_name") == source:
            candidates.append((metadata, document))
    if len(candidates) != 1:
        raise RepackError(
            f"expected exactly one resource package named {source}, found "
            f"{len(candidates)}"
        )
    metadata, document = candidates[0]
    if document.get("package_id") != 0x7F:
        raise RepackError(
            f"main resource package id is not 0x7f: {document.get('package_id')!r}"
        )
    document["package_name"] = target
    metadata.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    resource_root = metadata.parent
    public_xml = resource_root / "res" / "values" / "public.xml"
    try:
        public_tree = ET.parse(public_xml)
    except (OSError, ET.ParseError) as error:
        raise RepackError(f"unable to parse {public_xml}: {error}") from error
    public_root = public_tree.getroot()
    if local_name(public_root.tag) != "resources":
        raise RepackError(f"{public_xml} root is not <resources>")
    if public_root.get("package") != source or public_root.get("id") != "0x7f":
        raise RepackError(
            f"unexpected public.xml namespace/id in {public_xml}: "
            f"{public_root.get('package')!r}/{public_root.get('id')!r}"
        )
    public_root.set("package", target)
    public_tree.write(public_xml, encoding="utf-8", xml_declaration=True)

    strings_root = resource_root / "res"
    expected_files = {
        strings_root / directory / "strings.xml" for directory in TARGET_STRING_DIRS
    }
    all_string_files = set(strings_root.glob("values*/strings.xml"))
    if not expected_files.issubset(all_string_files):
        missing = sorted(str(path) for path in expected_files - all_string_files)
        raise RepackError("required strings files are missing: " + ", ".join(missing))

    for strings_file in sorted(all_string_files):
        try:
            strings_tree = ET.parse(strings_file)
        except (OSError, ET.ParseError) as error:
            raise RepackError(f"unable to parse {strings_file}: {error}") from error
        root = strings_tree.getroot()
        keyed: dict[str, list[ET.Element]] = collections.defaultdict(list)
        for child in root:
            if local_name(child.tag) == "string" and child.get("name"):
                keyed[child.get("name", "")].append(child)

        if strings_file in expected_files:
            for key in TARGET_STRING_KEYS:
                elements = keyed.get(key, [])
                if len(elements) != 1:
                    raise RepackError(
                        f"expected one {key!r} in {strings_file}, found {len(elements)}"
                    )
                replacements = replace_text_in_element(elements[0], source, target)
                if replacements != 1:
                    raise RepackError(
                        f"expected one source package in {key!r} at {strings_file}, "
                        f"found {replacements}"
                    )

        # Exactly six messages are part of the transformation contract.  A new
        # locale/key containing the source package requires an explicit review.
        for key, elements in keyed.items():
            for element in elements:
                text = "".join(element.itertext())
                if contains_standalone_package(text, source):
                    raise RepackError(
                        f"unclassified source package in string {key!r} at {strings_file}"
                    )
        strings_tree.write(strings_file, encoding="utf-8", xml_declaration=True)


def remove_upstream_signatures(decoded: Path) -> None:
    signatures = decoded / "signatures"
    if signatures.exists():
        if not signatures.is_dir():
            raise RepackError(f"unexpected non-directory signature path: {signatures}")
        shutil.rmtree(signatures)
    meta_inf = decoded / "root" / "META-INF"
    if not meta_inf.exists():
        return
    for entry in meta_inf.iterdir():
        upper = entry.name.upper()
        if entry.is_file() and (
            upper == "MANIFEST.MF" or Path(upper).suffix in SIGNATURE_SUFFIXES
        ):
            entry.unlink()


def decoded_dex_digests(decoded: Path) -> dict[str, str]:
    dex_dir = decoded / "dex"
    result: dict[str, str] = {}
    if dex_dir.is_dir():
        for path in dex_dir.iterdir():
            if path.is_file() and DEX_RE.fullmatch(path.name):
                with path.open("rb") as stream:
                    result[path.name] = hash_stream(stream)
    return dict(sorted(result.items(), key=lambda item: dex_sort_key(item[0])))


def check_apkeditor_version(java: str, apkeditor: Path) -> None:
    # APKEditor 1.4.9 prints the requested version correctly but exits with 2
    # for this informational flag.  Inspect its output instead of treating the
    # unconventional status as a build failure.
    try:
        result = subprocess.run(
            (java, "-jar", str(apkeditor), "-version"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={
                key: value
                for key, value in os.environ.items()
                if key not in SENSITIVE_ENVIRONMENT
            },
        )
    except OSError as error:
        raise RepackError(f"unable to inspect APKEditor: {error}") from error
    output = result.stdout
    match = re.search(r"APKEditor version ([0-9.]+)", output)
    if match is None or match.group(1) != APKEDITOR_VERSION:
        found = match.group(1) if match else "unknown"
        raise RepackError(
            f"APKEditor {APKEDITOR_VERSION} is required; found {found}"
        )
    if result.returncode not in {0, 2}:
        raise RepackError(
            f"APKEditor version check failed ({result.returncode}): {output.rstrip()}"
        )


def decode_apk(java: str, apkeditor: Path, source: Path, output: Path) -> None:
    run_checked(
        (
            java,
            "-Xmx2g",
            "-jar",
            str(apkeditor),
            "d",
            "-t",
            "xml",
            "-dex",
            "-i",
            str(source),
            "-o",
            str(output),
        )
    )


def build_apk(java: str, apkeditor: Path, decoded: Path, output: Path) -> None:
    run_checked(
        (
            java,
            "-Xmx2g",
            "-jar",
            str(apkeditor),
            "b",
            "-i",
            str(decoded),
            "-o",
            str(output),
        )
    )


def zipalign_supports_page_size(zipalign: str) -> bool:
    try:
        result = subprocess.run(
            (zipalign, "-h"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={
                key: value
                for key, value in os.environ.items()
                if key not in SENSITIVE_ENVIRONMENT
            },
        )
    except OSError as error:
        raise RepackError(f"unable to inspect zipalign: {error}") from error
    return "-P" in result.stdout


def align_apk(zipalign: str, source: Path, output: Path, modern: bool) -> None:
    if modern:
        command = (zipalign, "-f", "-P", "16", "4", str(source), str(output))
    else:
        command = (zipalign, "-f", "-p", "4", str(source), str(output))
    run_checked(command)


def verify_alignment(zipalign: str, apk: Path, modern: bool) -> None:
    if modern:
        command = (zipalign, "-c", "-P", "16", "4", str(apk))
    else:
        command = (zipalign, "-c", "-p", "4", str(apk))
    run_checked(command)


def sign_apk(
    apksigner: str,
    source: Path,
    output: Path,
    keystore: Path,
    alias: str,
    signing_env: Mapping[str, str],
) -> None:
    run_checked(
        (
            apksigner,
            "sign",
            "--ks",
            str(keystore),
            "--ks-type",
            "PKCS12",
            "--ks-key-alias",
            alias,
            "--ks-pass",
            "env:KEYSTORE_PASSWORD",
            "--key-pass",
            "env:KEY_PASSWORD",
            "--v1-signing-enabled",
            "true",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "true",
            "--v4-signing-enabled",
            "false",
            "--out",
            str(output),
            str(source),
        ),
        env=signing_env,
    )


def parse_aapt_xmltree(text: str) -> list[tuple[str, str, str]]:
    attributes: list[tuple[str, str, str]] = []
    elements: list[tuple[int, str]] = []
    for line in text.splitlines():
        element_match = re.match(r"^(\s*)E: ([^ (]+)", line)
        if element_match:
            indent = len(element_match.group(1))
            while elements and elements[-1][0] >= indent:
                elements.pop()
            elements.append((indent, element_match.group(2)))
            continue
        attribute_match = re.match(r"^\s*A: (.+?)=(.*)$", line)
        if not attribute_match or not elements:
            continue
        left, right = attribute_match.groups()
        left = re.sub(r"\([^)]*\)$", "", left)
        attribute = left.rsplit(":", 1)[-1]
        if right.startswith('"'):
            value_match = re.match(r'"([^"]*)"', right)
            if value_match is None:
                continue
            value = value_match.group(1)
        else:
            value = right.split(None, 1)[0]
        attributes.append((elements[-1][1], attribute, value))
    return attributes


def snapshots_from_compiled_manifest(
    attributes: Iterable[tuple[str, str, str]], package: str
) -> tuple[
    collections.Counter[tuple[str, str, str]],
    collections.Counter[tuple[str, str, str]],
]:
    identity: collections.Counter[tuple[str, str, str]] = collections.Counter()
    components: collections.Counter[tuple[str, str, str]] = collections.Counter()
    for tag, attribute, value in attributes:
        if attribute in CLASS_ATTRIBUTES.get(tag, ()):
            components[(tag, attribute, resolve_class_name(package, value))] += 1
        include_identity = (
            (tag == "manifest" and attribute in {"package", "sharedUserId"})
            or (tag in PERMISSION_DECLARATIONS | PERMISSION_REFERENCES and attribute == "name")
            or attribute in PERMISSION_ATTRIBUTES | PREFIX_IDENTITY_ATTRIBUTES
            or (tag == "provider" and attribute == "authorities")
        )
        if include_identity:
            identity[(tag, attribute, value)] += 1
    return identity, components


def verify_resource_strings(dump: str, target: str) -> None:
    lines = dump.splitlines()
    positions: dict[str, list[int]] = collections.defaultdict(list)
    for index, line in enumerate(lines):
        match = re.match(r"^\s+resource \S+ string/(\S+)$", line)
        if match:
            positions[match.group(1)].append(index)
    for key in TARGET_STRING_KEYS:
        found = positions.get(key, [])
        if len(found) != 1:
            raise RepackError(
                f"compiled resources contain {len(found)} entries for string/{key}"
            )
        start = found[0] + 1
        end = next(
            (
                index
                for index in range(start, len(lines))
                if re.match(r"^\s+resource \S+ ", lines[index])
            ),
            len(lines),
        )
        block = "\n".join(lines[start:end])
        if block.count(target) != 2:
            raise RepackError(
                f"compiled string/{key} does not contain target in default and zh"
            )


def verify_signed_apk(
    *,
    apk: Path,
    expected: VariantExpectation,
    source: SourceModel,
    aapt2: str,
    apksigner: str,
    zipalign: str,
    modern_zipalign: bool,
) -> str:
    actual_dex = inspect_apk_zip(apk)
    if actual_dex != source.dex_digests:
        raise RepackError(f"DEX bytes changed in {apk.name}")
    verify_alignment(zipalign, apk, modern_zipalign)

    badging = read_badging(aapt2, apk)
    if badging.package != expected.package:
        raise RepackError(
            f"wrong output package in {apk.name}: {badging.package!r}"
        )
    for field in ("version_code", "version_name", "min_sdk", "target_sdk"):
        if getattr(badging, field) != getattr(source.badging, field):
            raise RepackError(f"{field} changed in {apk.name}")
    if badging.launchable_activity != source.badging.launchable_activity:
        raise RepackError(f"launchable activity changed in {apk.name}")

    resource_dump = run_checked((aapt2, "dump", "resources", str(apk)))
    resource_packages = re.findall(
        r"^Package name=(\S+) id=([0-9a-fA-F]+)$", resource_dump, re.MULTILINE
    )
    main_packages = [name for name, identifier in resource_packages if identifier == "7f"]
    if main_packages != [expected.package]:
        raise RepackError(
            f"wrong 0x7f resource package(s) in {apk.name}: {main_packages!r}"
        )
    verify_resource_strings(resource_dump, expected.package)

    manifest_dump = run_checked(
        (aapt2, "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml")
    )
    actual_identity, actual_components = snapshots_from_compiled_manifest(
        parse_aapt_xmltree(manifest_dump), expected.package
    )
    if actual_identity != expected.identity:
        raise RepackError(f"compiled manifest identity differs in {apk.name}")
    if actual_components != expected.component_classes:
        raise RepackError(f"compiled manifest component classes differ in {apk.name}")

    signature_output = run_checked(
        (
            apksigner,
            "verify",
            "--min-sdk-version",
            str(source.badging.min_sdk),
            "--verbose",
            "--print-certs",
            str(apk),
        )
    )
    for scheme in (1, 2, 3):
        if f"Verified using v{scheme} scheme" not in signature_output or not re.search(
            rf"Verified using v{scheme} scheme.*: true", signature_output
        ):
            raise RepackError(f"APK signature v{scheme} is missing in {apk.name}")
    if "Number of signers: 1" not in signature_output:
        raise RepackError(f"expected exactly one signer in {apk.name}")
    digest_match = re.search(
        r"Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]+)", signature_output
    )
    if digest_match is None:
        raise RepackError(f"unable to read signer certificate from {apk.name}")
    return digest_match.group(1).lower()


def copy_decoded(source: Path, target: Path) -> None:
    shutil.copytree(source, target, symlinks=False)


def publish_outputs(staged: Sequence[Path], output_dir: Path) -> list[Path]:
    published: list[Path] = []
    backups: dict[Path, Path] = {}
    backup_dir = Path(tempfile.mkdtemp(prefix=".repack-backup-", dir=output_dir))
    try:
        for item in staged:
            destination = output_dir / item.name
            if destination.exists():
                backup = backup_dir / item.name
                shutil.copy2(destination, backup)
                backups[destination] = backup
        try:
            for item in staged:
                destination = output_dir / item.name
                os.replace(item, destination)
                destination.chmod(0o644)
                published.append(destination)
        except BaseException:
            for destination in published:
                backup = backups.get(destination)
                if backup is not None:
                    os.replace(backup, destination)
                elif destination.exists():
                    destination.unlink()
            raise
    finally:
        shutil.rmtree(backup_dir)
    return published


def build_variants(args: argparse.Namespace) -> list[Path]:
    input_apk = Path(args.input).resolve()
    output_dir = Path(args.output_dir).resolve()
    apkeditor = Path(args.apkeditor).resolve()
    keystore = Path(args.keystore).resolve()
    if not apkeditor.is_file():
        raise RepackError(f"APKEditor jar not found: {apkeditor}")
    if not keystore.is_file():
        raise RepackError(f"PKCS12 keystore not found: {keystore}")
    if args.count < 1 or args.count > 99:
        raise RepackError("--count must be between 1 and 99")
    validate_package_name(args.target_base, "target base")
    targets = [f"{args.target_base}{number}" for number in range(1, args.count + 1)]
    for target in targets:
        validate_package_name(target, "target")

    password = os.environ.get("KEYSTORE_PASSWORD")
    if not password:
        raise RepackError("KEYSTORE_PASSWORD is required")
    signing_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"GITHUB_TOKEN", "GH_TOKEN"}
    }
    signing_env["KEY_PASSWORD"] = os.environ.get("KEY_PASSWORD") or password

    java = require_executable(args.java)
    aapt2 = require_executable(args.aapt2)
    apksigner = require_executable(args.apksigner)
    zipalign = require_executable(args.zipalign)
    check_apkeditor_version(java, apkeditor)
    modern_zipalign = zipalign_supports_page_size(zipalign)

    dex_digests = inspect_apk_zip(input_apk)
    source_badging = read_badging(aapt2, input_apk)
    validate_package_name(source_badging.package, "source")
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="bt-repack-") as temporary:
        work = Path(temporary)
        decoded_base = work / "decoded-base"
        decode_apk(java, apkeditor, input_apk, decoded_base)
        if decoded_dex_digests(decoded_base) != dex_digests:
            raise RepackError("APKEditor raw DEX decode did not preserve DEX bytes")
        try:
            manifest_root = ET.parse(decoded_base / "AndroidManifest.xml").getroot()
        except (OSError, ET.ParseError) as error:
            raise RepackError(f"unable to parse decoded manifest: {error}") from error
        source_package = manifest_root.get("package")
        if source_package != source_badging.package:
            raise RepackError(
                "source package differs between manifest and aapt2: "
                f"{source_package!r} vs {source_badging.package!r}"
            )
        source = SourceModel(
            package=source_badging.package,
            badging=source_badging,
            dex_digests=dex_digests,
            component_classes=component_snapshot(manifest_root, source_badging.package),
        )

        staged_outputs: list[Path] = []
        expectations: list[VariantExpectation] = []
        for target in targets:
            decoded = work / ("decoded-" + target)
            copy_decoded(decoded_base, decoded)
            discovered_source, expectation = transform_manifest(
                decoded / "AndroidManifest.xml", target
            )
            if discovered_source != source.package:
                raise RepackError("decoded source package changed between variants")
            if expectation.component_classes != source.component_classes:
                raise RepackError("source component class snapshot is inconsistent")
            transform_resources(decoded, source.package, target)
            remove_upstream_signatures(decoded)
            if decoded_dex_digests(decoded) != source.dex_digests:
                raise RepackError(f"DEX bytes changed while preparing {target}")

            unsigned = work / (target + "-unsigned.apk")
            aligned = work / (target + "-aligned.apk")
            signed = work / (target + ".apk")
            build_apk(java, apkeditor, decoded, unsigned)
            if inspect_apk_zip(unsigned) != source.dex_digests:
                raise RepackError(f"DEX bytes changed while building {target}")
            align_apk(zipalign, unsigned, aligned, modern_zipalign)
            sign_apk(
                apksigner,
                aligned,
                signed,
                keystore,
                args.ks_alias,
                signing_env,
            )
            staged_outputs.append(signed)
            expectations.append(expectation)

        signer_digests = {
            verify_signed_apk(
                apk=apk,
                expected=expectation,
                source=source,
                aapt2=aapt2,
                apksigner=apksigner,
                zipalign=zipalign,
                modern_zipalign=modern_zipalign,
            )
            for apk, expectation in zip(staged_outputs, expectations, strict=True)
        }
        if len(signer_digests) != 1:
            raise RepackError("variants were not signed by the same certificate")

        with tempfile.TemporaryDirectory(
            prefix=".repack-staging-", dir=output_dir
        ) as publication_staging:
            publication_dir = Path(publication_staging)
            publication_files: list[Path] = []
            for apk in staged_outputs:
                destination = publication_dir / apk.name
                shutil.copy2(apk, destination)
                publication_files.append(destination)
            return publish_outputs(publication_files, output_dir)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="upstream universal APK")
    parser.add_argument("--output-dir", default="dist", help="verified APK directory")
    parser.add_argument(
        "--apkeditor",
        default="tools/APKEditor-1.4.9.jar",
        help="pinned APKEditor 1.4.9 jar",
    )
    parser.add_argument("--keystore", required=True, help="PKCS12 signing keystore")
    parser.add_argument("--ks-alias", default="bt-clones", help="signing key alias")
    parser.add_argument(
        "--target-base", default="com.chinasoul.bt", help="variant package prefix"
    )
    parser.add_argument("--count", type=int, default=5, help="numbered variants")
    parser.add_argument("--java", default="java")
    parser.add_argument("--aapt2", default="aapt2")
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--zipalign", default="zipalign")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        outputs = build_variants(create_parser().parse_args(argv))
    except RepackError as error:
        print(f"repack: error: {error}", file=sys.stderr)
        return 1
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
