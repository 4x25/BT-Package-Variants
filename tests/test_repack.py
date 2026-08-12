from __future__ import annotations

import json
import tempfile
import unittest
import warnings
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest import mock

from scripts import repack


ANDROID = "{http://schemas.android.com/apk/res/android}"


def write_manifest(path: Path, extra: str = "") -> None:
    path.write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.upstream.app">
  <permission android:name="com.upstream.app.INTERNAL" />
  <uses-permission android:name="com.upstream.app.INTERNAL" />
  <application android:name=".MainApp" android:process="com.upstream.app.worker">
    <activity android:name="MainActivity" android:taskAffinity="com.upstream.app.tasks" />
    <service android:name="com.upstream.app.SyncService" />
    <provider android:name="androidx.core.content.FileProvider"
              android:authorities="com.upstream.app.files;external.authority" />
    <receiver android:name=".Receiver">
      <intent-filter><action android:name="com.upstream.app.ACTION" /></intent-filter>
    </receiver>
    {extra}
  </application>
</manifest>''',
        encoding="utf-8",
    )


class ManifestTests(unittest.TestCase):
    def test_rewrites_identity_but_preserves_component_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "AndroidManifest.xml"
            write_manifest(manifest)
            source, expected = repack.transform_manifest(
                manifest, "com.chinasoul.bt1"
            )
            self.assertEqual(source, "com.upstream.app")
            root = ET.parse(manifest).getroot()
            self.assertEqual(root.get("package"), "com.chinasoul.bt1")
            application = root.find("application")
            assert application is not None
            self.assertEqual(application.get(ANDROID + "name"), "com.upstream.app.MainApp")
            self.assertEqual(
                application.get(ANDROID + "process"), "com.chinasoul.bt1.worker"
            )
            activity = application.find("activity")
            assert activity is not None
            self.assertEqual(
                activity.get(ANDROID + "name"), "com.upstream.app.MainActivity"
            )
            action = application.find("./receiver/intent-filter/action")
            assert action is not None
            self.assertEqual(action.get(ANDROID + "name"), "com.upstream.app.ACTION")
            provider = application.find("provider")
            assert provider is not None
            self.assertEqual(
                provider.get(ANDROID + "authorities"),
                "com.chinasoul.bt1.files;external.authority",
            )
            self.assertIn(
                ("application", "name", "com.upstream.app.MainApp"),
                expected.component_classes,
            )

    def test_unknown_source_package_attribute_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "AndroidManifest.xml"
            write_manifest(
                manifest,
                '<activity android:name=".DeepLink"><intent-filter>'
                '<data android:scheme="com.upstream.app" />'
                "</intent-filter></activity>",
            )
            with self.assertRaisesRegex(repack.RepackError, "unclassified"):
                repack.transform_manifest(manifest, "com.chinasoul.bt1")


class ResourceTests(unittest.TestCase):
    def make_resources(self, root: Path, *, include_all: bool = True) -> Path:
        package = root / "resources" / "package_1"
        (package / "res" / "values").mkdir(parents=True)
        (package / "res" / "values-zh").mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"package_id": 127, "package_name": "com.upstream.app"}),
            encoding="utf-8",
        )
        (package / "res" / "values" / "public.xml").write_text(
            '<resources package="com.upstream.app" id="0x7f" />',
            encoding="utf-8",
        )
        keys = repack.TARGET_STRING_KEYS if include_all else repack.TARGET_STRING_KEYS[:2]
        for directory in repack.TARGET_STRING_DIRS:
            body = "".join(
                f'<string name="{key}">Use com.upstream.app safely</string>'
                for key in keys
            )
            (package / "res" / directory / "strings.xml").write_text(
                f"<resources>{body}</resources>", encoding="utf-8"
            )
        return package

    def test_exact_six_strings_and_resource_namespace_are_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decoded = Path(directory)
            package = self.make_resources(decoded)
            repack.transform_resources(
                decoded, "com.upstream.app", "com.chinasoul.bt2"
            )
            metadata = json.loads((package / "package.json").read_text())
            self.assertEqual(metadata["package_name"], "com.chinasoul.bt2")
            public = ET.parse(package / "res" / "values" / "public.xml").getroot()
            self.assertEqual(public.get("package"), "com.chinasoul.bt2")
            for directory_name in repack.TARGET_STRING_DIRS:
                text = (package / "res" / directory_name / "strings.xml").read_text()
                self.assertEqual(text.count("com.chinasoul.bt2"), 3)
                self.assertNotIn("com.upstream.app", text)

    def test_missing_contract_string_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decoded = Path(directory)
            self.make_resources(decoded, include_all=False)
            with self.assertRaisesRegex(repack.RepackError, "expected one"):
                repack.transform_resources(
                    decoded, "com.upstream.app", "com.chinasoul.bt2"
                )

    def test_new_locale_source_package_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decoded = Path(directory)
            package = self.make_resources(decoded)
            extra = package / "res" / "values-fr"
            extra.mkdir()
            (extra / "strings.xml").write_text(
                '<resources><string name="new_key">com.upstream.app only</string></resources>',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(repack.RepackError, "unclassified"):
                repack.transform_resources(
                    decoded, "com.upstream.app", "com.chinasoul.bt2"
                )


class ZipTests(unittest.TestCase):
    def make_apk(self, path: Path, *, duplicate: bool = False) -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
            archive.writestr("resources.arsc", b"resources")
            archive.writestr("classes.dex", b"dex-one")
            archive.writestr("classes2.dex", b"dex-two")
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr("classes.dex", b"other")

    def test_dex_digest_set_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "input.apk"
            self.make_apk(apk)
            digests = repack.inspect_apk_zip(apk)
            self.assertEqual(list(digests), ["classes.dex", "classes2.dex"])
            self.assertEqual(len(digests["classes.dex"]), 64)

    def test_duplicate_zip_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "input.apk"
            self.make_apk(apk, duplicate=True)
            with self.assertRaisesRegex(repack.RepackError, "duplicate ZIP"):
                repack.inspect_apk_zip(apk)


class OutputParsingTests(unittest.TestCase):
    def test_aapt_tree_parser_preserves_tag_context(self) -> None:
        dump = '''  E: manifest (line=1)
    A: package="com.chinasoul.bt1" (Raw: "com.chinasoul.bt1")
      E: application (line=2)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.upstream.App" (Raw: "com.upstream.App")
'''
        parsed = repack.parse_aapt_xmltree(dump)
        self.assertEqual(
            parsed,
            [
                ("manifest", "package", "com.chinasoul.bt1"),
                ("application", "name", "com.upstream.App"),
            ],
        )


class ProcessTests(unittest.TestCase):
    @mock.patch("scripts.repack.subprocess.run")
    def test_apkeditor_version_accepts_known_exit_two_and_scrubs_secrets(
        self, run: mock.Mock
    ) -> None:
        run.return_value = mock.Mock(
            returncode=2,
            stdout="APKEditor version 1.4.9, ARSCLib version 1.3.9\n",
        )
        with mock.patch.dict(
            repack.os.environ,
            {
                "GITHUB_TOKEN": "github-secret",
                "GH_TOKEN": "gh-secret",
                "KEYSTORE_PASSWORD": "store-secret",
                "KEY_PASSWORD": "key-secret",
            },
        ):
            repack.check_apkeditor_version("java", Path("APKEditor.jar"))
        child_env = run.call_args.kwargs["env"]
        self.assertTrue(repack.SENSITIVE_ENVIRONMENT.isdisjoint(child_env))

    @mock.patch("scripts.repack.subprocess.run")
    def test_apkeditor_version_rejects_other_nonzero_exit(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(
            returncode=1,
            stdout="APKEditor version 1.4.9, ARSCLib version 1.3.9\n",
        )
        with self.assertRaisesRegex(repack.RepackError, "version check failed"):
            repack.check_apkeditor_version("java", Path("APKEditor.jar"))

    @mock.patch("scripts.repack.subprocess.run")
    def test_default_subprocess_environment_is_scrubbed(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(returncode=0, stdout="ok\n")
        with mock.patch.dict(
            repack.os.environ,
            {
                "GITHUB_TOKEN": "github-secret",
                "GH_TOKEN": "gh-secret",
                "KEYSTORE_PASSWORD": "store-secret",
                "KEY_PASSWORD": "key-secret",
            },
        ):
            self.assertEqual(repack.run_checked(("test-tool",)), "ok\n")
        child_env = run.call_args.kwargs["env"]
        self.assertTrue(repack.SENSITIVE_ENVIRONMENT.isdisjoint(child_env))


if __name__ == "__main__":
    unittest.main()
