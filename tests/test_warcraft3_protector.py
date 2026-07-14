import json
import tempfile
import unittest
from pathlib import Path

from warcraft3_protector import protect_jass, protect_lua, protect_project


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
        self.assertEqual(
            protected,
            "function Demo takes nothing returns nothing\nendfunction\n",
        )

    def test_project_randomizes_assets_rewrites_script_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "private-source"
            output = root / "release"
            asset = source / "Models" / "Hero" / "Attack.mdx"
            asset.parent.mkdir(parents=True)
            asset.write_bytes(b"model-data")
            (source / "war3map.lua").write_text(
                'local model = "Models\\\\Hero\\\\Attack.mdx" -- private name\n',
                encoding="utf-8",
            )

            result = protect_project(source, output, build_id="TEST-BUILD")

            self.assertEqual(result.renamed_assets, 1)
            self.assertEqual(result.protected_scripts, 1)
            self.assertFalse((output / "Models" / "Hero" / "Attack.mdx").exists())
            renamed = list((output / "war3mapImported").rglob("*.mdx"))
            self.assertEqual(len(renamed), 1)
            script = (output / "war3map.lua").read_text(encoding="utf-8")
            self.assertNotIn("Models", script)
            self.assertIn("war3mapImported", script)

            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["build_id"], "TEST-BUILD")
            self.assertFalse(manifest["protection"]["cryptographic_secrecy"])
            self.assertEqual(len(manifest["asset_mappings"]), 1)

    def test_output_cannot_be_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            with self.assertRaises(ValueError):
                protect_project(source, source / "release")


if __name__ == "__main__":
    unittest.main()
