import json
import tempfile
import unittest
from pathlib import Path

from warcraft3_protector import (
    ProtectionOptions,
    protect_jass,
    protect_lua,
    protect_project,
    verify_project,
)


class Warcraft3ProtectorTests(unittest.TestCase):
    def test_lua_comments_removed_but_string_preserved(self):
        source = '-- header\nlocal value = "--not-comment" -- trailing\nreturn value\n'
        protected = protect_lua(source)
        self.assertNotIn("header", protected)
        self.assertIn('"--not-comment"', protected)
        self.assertIn("return value", protected)

    def test_jass_comments_and_blank_lines_removed(self):
        source = "// header\n\nfunction Demo takes nothing returns nothing\n// inside\nendfunction\n"
        protected = protect_jass(source)
        self.assertNotIn("header", protected)
        self.assertEqual(protected, "function Demo takes nothing returns nothing\nendfunction\n")

    def _build_project(self, root: Path, *, private_report: bool = False, signing_key: str | None = None):
        source = root / "private-source"
        output = root / "release"
        asset = source / "Models" / "Hero" / "Attack.mdx"
        asset.parent.mkdir(parents=True)
        asset.write_bytes(b"model-data")
        (source / "war3map.lua").write_text(
            'local model = "Models\\\\Hero\\\\Attack.mdx" -- private name\n',
            encoding="utf-8",
        )
        result = protect_project(
            source,
            output,
            build_id="TEST-BUILD",
            options=ProtectionOptions(include_private_report=private_report),
            signing_key=signing_key,
        )
        return source, output, result

    def test_project_hides_original_paths_in_public_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            _, output, result = self._build_project(Path(temp))
            self.assertEqual(result.renamed_assets, 1)
            self.assertFalse((output / "Models" / "Hero" / "Attack.mdx").exists())
            script = (output / "war3map.lua").read_text(encoding="utf-8")
            self.assertNotIn("Models", script)
            self.assertIn("war3mapImported", script)

            manifest_text = result.manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            self.assertEqual(manifest["schema"], 2)
            self.assertNotIn("asset_mappings", manifest)
            self.assertNotIn("Models/Hero/Attack.mdx", manifest_text)
            self.assertFalse(manifest["protection"]["cryptographic_secrecy"])

    def test_private_report_is_written_outside_release(self):
        with tempfile.TemporaryDirectory() as temp:
            _, output, result = self._build_project(Path(temp), private_report=True)
            self.assertIsNotNone(result.private_report_path)
            self.assertNotEqual(result.private_report_path.parent, output)
            report = result.private_report_path.read_text(encoding="utf-8")
            self.assertIn("Models/Hero/Attack.mdx", report)

    def test_verification_detects_changed_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as temp:
            _, output, _ = self._build_project(Path(temp))
            self.assertTrue(verify_project(output).valid)
            (output / "war3map.lua").write_text("tampered\n", encoding="utf-8")
            (output / "extra.txt").write_text("unexpected\n", encoding="utf-8")
            verification = verify_project(output)
            self.assertFalse(verification.valid)
            self.assertIn("war3map.lua", verification.changed)
            self.assertIn("extra.txt", verification.unexpected)

    def test_signed_manifest_requires_correct_key(self):
        with tempfile.TemporaryDirectory() as temp:
            _, output, _ = self._build_project(Path(temp), signing_key="correct-secret")
            self.assertTrue(verify_project(output, signing_key="correct-secret").valid)
            self.assertFalse(verify_project(output, signing_key="wrong-secret").valid)
            self.assertFalse(verify_project(output).valid)

    def test_options_can_preserve_comments_and_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            output = root / "release"
            source.mkdir()
            (source / "model.mdx").write_bytes(b"model")
            (source / "war3map.lua").write_text("-- keep me\nlocal x = 1\n", encoding="utf-8")
            protect_project(
                source,
                output,
                options=ProtectionOptions(
                    randomize_assets=False,
                    strip_comments=False,
                    reduce_whitespace=False,
                ),
            )
            self.assertTrue((output / "model.mdx").exists())
            self.assertIn("-- keep me", (output / "war3map.lua").read_text(encoding="utf-8"))

    def test_output_cannot_be_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            with self.assertRaises(ValueError):
                protect_project(source, source / "release")


if __name__ == "__main__":
    unittest.main()
