#!/usr/bin/env python3
"""Mirror eligible chinasoul/BT releases as independently installable APKs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


EXPECTED_ASSETS = tuple(f"com.chinasoul.bt{i}.apk" for i in range(1, 6))
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class SyncError(RuntimeError):
    pass


def run(command: Sequence[str], *, stdin: str | None = None) -> str:
    result = subprocess.run(
        list(command), input=stdin, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode:
        raise SyncError(f"command failed ({result.returncode}): {command[0]}\n{result.stdout.rstrip()}")
    return result.stdout


def api(endpoint: str, *, method: str = "GET", payload: Any | None = None) -> Any:
    command = ["gh", "api", "--method", method, endpoint]
    stdin = None
    if payload is not None:
        command += ["--input", "-"]
        stdin = json.dumps(payload, ensure_ascii=False)
    output = run(command, stdin=stdin)
    return json.loads(output) if output.strip() else None


def list_releases(repository: str) -> list[dict[str, Any]]:
    output = run([
        "gh", "api", "--paginate", "--slurp",
        f"repos/{repository}/releases?per_page=100",
    ])
    pages = json.loads(output)
    return [release for page in pages for release in page]


def eligible(release: dict[str, Any], state: dict[str, Any]) -> bool:
    if release.get("draft") or not release.get("published_at"):
        return False
    return (
        int(release["id"]) == int(state["bootstrap"]["release_id"])
        or int(release["id"]) not in set(state["historical_release_ids"])
    )


def universal_asset(release: dict[str, Any]) -> dict[str, Any] | None:
    matches = [
        asset for asset in release.get("assets", [])
        if asset.get("name") == "universal.apk" and asset.get("state") == "uploaded"
    ]
    if len(matches) > 1:
        raise SyncError(f"source release {release.get('id')} has duplicate universal.apk assets")
    return matches[0] if matches else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(release: dict[str, Any], asset: dict[str, Any], sha256: str) -> str:
    material = {
        "release_id": release["id"],
        "tag_name": release.get("tag_name"),
        "name": release.get("name"),
        "body": release.get("body"),
        "prerelease": bool(release.get("prerelease")),
        "asset_id": asset["id"],
        "asset_size": asset.get("size"),
        "asset_digest": asset.get("digest"),
        "asset_updated_at": asset.get("updated_at"),
        "download_sha256": sha256,
    }
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def target_complete(
    target: dict[str, Any] | None,
    source: dict[str, Any],
    record: dict[str, Any] | None = None,
) -> bool:
    if not target or target.get("draft"):
        return False
    names = sorted(asset.get("name") for asset in target.get("assets", []))
    complete = (
        target.get("name") == source.get("name")
        and target.get("body") == source.get("body")
        and bool(target.get("prerelease")) == bool(source.get("prerelease"))
        and names == sorted(EXPECTED_ASSETS)
    )
    expected_outputs = (record or {}).get("outputs")
    if not complete or not expected_outputs:
        return complete and record is None
    if set(expected_outputs) != set(EXPECTED_ASSETS):
        return False
    actual = {
        asset.get("name"): {
            "size": asset.get("size"),
            "sha256": (asset.get("digest") or "").removeprefix("sha256:"),
        }
        for asset in target.get("assets", [])
    }
    return all(actual.get(name) == expected_outputs[name] for name in EXPECTED_ASSETS)


def download_asset(asset: dict[str, Any], destination: Path) -> str:
    with destination.open("wb") as output:
        result = subprocess.run(
            ["gh", "api", "-H", "Accept: application/octet-stream", asset["url"]],
            stdout=output, stderr=subprocess.PIPE, check=False,
        )
    if result.returncode:
        raise SyncError(f"unable to download source asset {asset['id']}: {result.stderr.decode(errors='replace')}")
    if destination.stat().st_size != asset.get("size"):
        raise SyncError(f"source asset {asset['id']} size changed during download")
    digest = sha256_file(destination)
    declared = asset.get("digest")
    if declared and declared != f"sha256:{digest}":
        raise SyncError(f"source asset {asset['id']} SHA-256 does not match GitHub digest")
    return digest


def upload_assets(repository: str, tag: str, paths: Sequence[Path]) -> None:
    """Upload the complete asset set through gh's release upload endpoint."""
    run([
        "gh", "release", "upload", tag,
        *(str(path) for path in paths),
        "--repo", repository,
    ])


def prepare_target_release(repository: str, target: dict[str, Any] | None,
                           source: dict[str, Any], target_sha: str) -> int:
    fields = {
        "name": source.get("name"), "body": source.get("body"),
        "draft": True, "prerelease": bool(source.get("prerelease")),
        "make_latest": "false",
    }
    if target:
        if target.get("immutable"):
            raise SyncError(f"target release {source['tag_name']} is immutable")
        updated = api(f"repos/{repository}/releases/{target['id']}", method="PATCH", payload=fields)
        for asset in updated.get("assets", []):
            api(f"repos/{repository}/releases/assets/{asset['id']}", method="DELETE")
        return int(target["id"])
    fields.update({"tag_name": source["tag_name"], "target_commitish": target_sha})
    created = api(f"repos/{repository}/releases", method="POST", payload=fields)
    return int(created["id"])


def publish(repository: str, release_id: int, source: dict[str, Any]) -> dict[str, Any]:
    return api(
        f"repos/{repository}/releases/{release_id}", method="PATCH",
        payload={
            "name": source.get("name"), "body": source.get("body"),
            "draft": False, "prerelease": bool(source.get("prerelease")),
            "make_latest": "false",
        },
    )


def load_state(path: Path) -> dict[str, Any]:
    state = json.loads(path.read_text(encoding="utf-8"))
    if (
        state.get("schema") != 1
        or "bootstrap" not in state
        or "historical_release_ids" not in state
        or "processed" not in state
    ):
        raise SyncError("unsupported or incomplete state file")
    return state


def save_state(path: Path, state: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def persist_state_commit(state_path: Path, message: str) -> None:
    """Commit and push completed transactions before processing the next release."""
    status = run(["git", "status", "--porcelain", "--", str(state_path)])
    if not status.strip():
        return
    run(["git", "config", "user.name", "github-actions[bot]"])
    run([
        "git", "config", "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
    ])
    run(["git", "add", "--", str(state_path)])
    run(["git", "commit", "-m", message])
    branch = os.environ.get("GITHUB_REF_NAME")
    if not branch or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        raise SyncError("GITHUB_REF_NAME is missing or invalid")
    for attempt in range(3):
        result = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode == 0:
            return
        if attempt == 2:
            raise SyncError(f"unable to push synchronization state: {result.stdout.rstrip()}")
        run(["git", "pull", "--rebase", "origin", branch])


def output_metadata(paths: Sequence[Path]) -> dict[str, dict[str, Any]]:
    return {
        path.name: {"size": path.stat().st_size, "sha256": sha256_file(path)}
        for path in paths
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("state/releases.json"))
    parser.add_argument("--source-repo", default="chinasoul/BT")
    parser.add_argument("--target-repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--repack-script", type=Path, default=Path("scripts/repack.py"))
    parser.add_argument("--apkeditor", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-alias", default="bt-clones")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.target_repo or not REPOSITORY_RE.fullmatch(args.target_repo):
        raise SyncError("--target-repo must be OWNER/REPOSITORY")
    if not REPOSITORY_RE.fullmatch(args.source_repo):
        raise SyncError("--source-repo must be OWNER/REPOSITORY")
    state = load_state(args.state)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    sources = sorted(
        (release for release in list_releases(args.source_repo) if eligible(release, state)),
        key=lambda item: (item["published_at"], item["id"]),
    )
    targets = {release["tag_name"]: release for release in list_releases(args.target_repo)}
    target_repo = api(f"repos/{args.target_repo}")
    target_sha = api(f"repos/{args.target_repo}/git/ref/heads/{target_repo['default_branch']}")["object"]["sha"]
    for source in sources:
        asset = universal_asset(source)
        if asset is None:
            print(f"Source release {source['tag_name']} has no uploaded universal.apk; will retry later.")
            continue
        release_dir = args.work_dir / str(source["id"])
        shutil.rmtree(release_dir, ignore_errors=True)
        release_dir.mkdir()
        source_apk = release_dir / "universal.apk"
        digest = download_asset(asset, source_apk)
        current_fingerprint = fingerprint(source, asset, digest)
        record = state["processed"].get(source["tag_name"])
        target = targets.get(source["tag_name"])
        if target_complete(target, source, record if record else None):
            if not record:
                raise SyncError(
                    f"target {source['tag_name']} is complete but has no local state; "
                    "refusing a destructive replacement"
                )
            if record.get("fingerprint") == current_fingerprint:
                print(f"Already synchronized: {source['tag_name']}")
                continue

        dist = release_dir / "dist"
        run([
            sys.executable, str(args.repack_script), "--input", str(source_apk),
            "--output-dir", str(dist), "--apkeditor", str(args.apkeditor),
            "--keystore", str(args.keystore), "--ks-alias", args.ks_alias,
        ])
        outputs = [dist / name for name in EXPECTED_ASSETS]
        if sorted(path.name for path in dist.glob("*.apk")) != sorted(EXPECTED_ASSETS):
            raise SyncError(f"repacker produced an unexpected asset set for {source['tag_name']}")
        built_outputs = output_metadata(outputs)

        refreshed = api(f"repos/{args.source_repo}/releases/{source['id']}")
        refreshed_asset = universal_asset(refreshed)
        if refreshed_asset is None or fingerprint(refreshed, refreshed_asset, digest) != current_fingerprint:
            raise SyncError(f"source release {source['tag_name']} changed during the build; retry next run")

        release_id = prepare_target_release(args.target_repo, target, source, target_sha)
        upload_assets(args.target_repo, source["tag_name"], outputs)
        published = publish(args.target_repo, release_id, source)
        published = api(f"repos/{args.target_repo}/releases/{published['id']}")
        verification_record = {"outputs": built_outputs}
        if not target_complete(published, source, verification_record):
            raise SyncError(f"published assets failed remote verification for {source['tag_name']}")
        targets[source["tag_name"]] = published
        state["processed"][source["tag_name"]] = {
            "source_release_id": source["id"], "source_asset_id": asset["id"],
            "source_sha256": digest, "fingerprint": current_fingerprint,
            "outputs": built_outputs,
        }
        save_state(args.state, state)
        persist_state_commit(
            args.state, f"chore: sync upstream release {source['tag_name']}"
        )
        print(f"Synchronized: {source['tag_name']}")

    stable = [release for release in sources if not release.get("prerelease") and universal_asset(release)]
    if stable:
        newest = stable[-1]["tag_name"]
        target = targets.get(newest)
        if target and not target.get("draft"):
            api(f"repos/{args.target_repo}/releases/{target['id']}", method="PATCH", payload={"make_latest": "true"})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as error:
        print(f"sync-releases: error: {error}", file=sys.stderr)
        raise SystemExit(1)
