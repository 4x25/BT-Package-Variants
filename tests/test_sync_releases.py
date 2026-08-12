import copy
import hashlib
import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "sync_releases.py"
SPEC = importlib.util.spec_from_file_location("sync_releases", MODULE_PATH)
sync = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(sync)


STATE = {
    "bootstrap": {"tag": "v0.9.32", "release_id": 42,
                  "published_at": "2026-08-03T13:18:04Z"},
    "historical_release_ids": [41, 42],
    "processed": {}, "schema": 1,
}


def release(**changes):
    value = {
        "id": 42, "tag_name": "v0.9.33", "name": "v0.9.33", "body": "notes",
        "draft": False, "prerelease": False, "published_at": "2026-08-04T00:00:00Z",
        "assets": [{"id": 7, "name": "universal.apk", "state": "uploaded", "size": 3,
                    "digest": "sha256:abc", "updated_at": "2026-08-04T00:00:00Z"}],
    }
    value.update(changes)
    return value


class SyncReleaseTests(unittest.TestCase):
    def test_asset_upload_uses_release_upload_for_all_five_files(self):
        paths = [Path(name) for name in sync.EXPECTED_ASSETS]
        with mock.patch.object(sync, "run", return_value="") as run:
            sync.upload_assets("owner/repo", "v1", paths)
        run.assert_called_once_with([
            "gh", "release", "upload", "v1", *(str(path) for path in paths),
            "--repo", "owner/repo",
        ])

    def test_state_commit_pushes_the_current_workflow_branch(self):
        def fake_run(command, **_kwargs):
            return " M state/releases.json\n" if command[:2] == ["git", "status"] else ""
        completed = mock.Mock(returncode=0, stdout="")
        with mock.patch.object(sync, "run", side_effect=fake_run), \
             mock.patch.object(sync.subprocess, "run", return_value=completed) as process, \
             mock.patch.dict(sync.os.environ, {"GITHUB_REF_NAME": "main"}, clear=False):
            sync.persist_state_commit(
                Path("state/releases.json"), "chore: sync upstream release v1"
            )
        self.assertEqual(process.call_args.args[0], ["git", "push", "origin", "HEAD:main"])

    def test_scope_includes_bootstrap_and_new_id_even_with_old_timestamp(self):
        self.assertTrue(sync.eligible(release(id=42), STATE))
        self.assertTrue(sync.eligible(release(id=43, prerelease=True,
                                              published_at="2020-01-01T00:00:00Z"), STATE))
        self.assertFalse(sync.eligible(release(id=43, draft=True), STATE))
        self.assertFalse(sync.eligible(release(id=41), STATE))

    def test_only_exact_uploaded_universal_asset_is_selected(self):
        candidate = release(assets=[
            {"id": 1, "name": "universal-api19-22.apk", "state": "uploaded"},
            {"id": 2, "name": "preview.apk", "state": "uploaded"},
            {"id": 3, "name": "universal.apk", "state": "new"},
        ])
        self.assertIsNone(sync.universal_asset(candidate))
        candidate["assets"].append({"id": 4, "name": "universal.apk", "state": "uploaded"})
        self.assertEqual(sync.universal_asset(candidate)["id"], 4)

    def test_fingerprint_changes_for_asset_or_release_metadata(self):
        original = release()
        first = sync.fingerprint(original, original["assets"][0], "abc")
        changed = copy.deepcopy(original)
        changed["body"] = "new notes"
        self.assertNotEqual(sync.fingerprint(changed, changed["assets"][0], "abc"), first)
        changed = copy.deepcopy(original)
        changed["assets"][0]["id"] = 8
        self.assertNotEqual(sync.fingerprint(changed, changed["assets"][0], "abc"), first)

    def test_target_requires_exact_metadata_and_five_assets(self):
        source = release()
        target = {
            "draft": False, "name": source["name"], "body": source["body"],
            "prerelease": False,
            "assets": [{"name": name} for name in sync.EXPECTED_ASSETS],
        }
        self.assertTrue(sync.target_complete(target, source))
        target["assets"].append({"name": "unexpected.apk"})
        self.assertFalse(sync.target_complete(target, source))

    def test_target_compares_saved_asset_digests_and_sizes(self):
        source = release()
        target = {
            "draft": False, "name": source["name"], "body": source["body"],
            "prerelease": False,
            "assets": [
                {"name": name, "size": 10, "digest": f"sha256:{index}"}
                for index, name in enumerate(sync.EXPECTED_ASSETS)
            ],
        }
        record = {"outputs": {
            name: {"size": 10, "sha256": str(index)}
            for index, name in enumerate(sync.EXPECTED_ASSETS)
        }}
        self.assertTrue(sync.target_complete(target, source, record))
        target["assets"][0]["digest"] = "sha256:tampered"
        self.assertFalse(sync.target_complete(target, source, record))

    def test_state_round_trip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(STATE), encoding="utf-8")
            loaded = sync.load_state(path)
            loaded["processed"]["v0.9.32"] = {"fingerprint": hashlib.sha256(b"x").hexdigest()}
            sync.save_state(path, loaded)
            self.assertEqual(sync.load_state(path), loaded)
