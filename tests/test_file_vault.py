import json
import tempfile
import unittest
from pathlib import Path

from file_vault import classify_path, decrypt_vault, inventory, protect_files, verify_vault

PASSWORD = "correct horse battery staple"


class FileVaultTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_path(Path("CORE PHILOSOPHY 2.pdf")), "CONFIDENTIAL_IP")
        self.assertEqual(classify_path(Path("private.key")), "RESTRICTED_SECRET")
        self.assertEqual(classify_path(Path("image.png")), "INTERNAL")

    def test_inventory_hashes_and_classifies(self):
        with tempfile.TemporaryDirectory() as temp:
            document = Path(temp) / "strategy.pdf"
            document.write_bytes(b"strategy")
            report = inventory([document])
            self.assertEqual(report["summary"]["CONFIDENTIAL_IP"], 1)
            self.assertEqual(report["files"][0]["size"], 8)
            self.assertEqual(len(report["files"][0]["sha256"]), 64)

    def _fixture(self, root: Path):
        source = root / "source"
        source.mkdir()
        (source / "notes.txt").write_text("private logic", encoding="utf-8")
        nested = source / "models"
        nested.mkdir()
        (nested / "logic.lua").write_text("return 42\n", encoding="utf-8")
        return source

    def test_encrypt_verify_and_decrypt_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._fixture(root)
            vault = root / "protected.cpvault"
            result = protect_files([source], vault, PASSWORD, manifest_key="manifest-secret")
            self.assertTrue(result.vault_path.exists())
            self.assertGreater(result.elapsed_seconds, 0)
            self.assertTrue(verify_vault(vault, manifest_key="manifest-secret").valid)
            self.assertFalse(verify_vault(vault, manifest_key="wrong").valid)

            output = root / "restored"
            self.assertEqual(decrypt_vault(vault, output, PASSWORD), 2)
            self.assertEqual((output / "source" / "notes.txt").read_text(encoding="utf-8"), "private logic")
            self.assertEqual((output / "source" / "models" / "logic.lua").read_text(encoding="utf-8"), "return 42\n")
            self.assertTrue((output / ".codepatch" / "private-manifest.json").exists())

    def test_public_manifest_hides_names_and_plaintext_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Highly Secret Strategy.pdf"
            source.write_bytes(b"unique private content")
            vault = root / "protected.cpvault"
            result = protect_files([source], vault, PASSWORD)
            text = result.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn(source.name, text)
            self.assertNotIn("unique private content", text)
            manifest = json.loads(text)
            self.assertFalse(manifest["inventory_disclosed"])
            self.assertNotIn("files", manifest)

    def test_inventory_disclosure_requires_explicit_option(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "strategy.pdf"
            source.write_bytes(b"strategy")
            result = protect_files([source], root / "vault.cpvault", PASSWORD, disclose_inventory=True)
            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["inventory_disclosed"])
            self.assertEqual(manifest["files"][0]["path"], "strategy.pdf")

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.pdf"
            source.write_bytes(b"original")
            vault = root / "secret.cpvault"
            protect_files([source], vault, PASSWORD)
            data = bytearray(vault.read_bytes())
            data[-1] ^= 1
            vault.write_bytes(data)
            self.assertFalse(verify_vault(vault).valid)
            with self.assertRaises(Exception):
                decrypt_vault(vault, root / "output", PASSWORD)

    def test_wrong_password_fails_without_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            vault = root / "secret.cpvault"
            protect_files([source], vault, PASSWORD)
            output = root / "output"
            with self.assertRaises(Exception):
                decrypt_vault(vault, output, "wrong password but sufficiently long")
            self.assertFalse(output.exists())

    def test_truncated_and_invalid_headers_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, payload in (("short.cpvault", b"CPVAULT2"), ("wrong.cpvault", b"not-a-vault")):
                vault = root / name
                vault.write_bytes(payload)
                with self.assertRaises(ValueError):
                    decrypt_vault(vault, root / f"out-{name}", PASSWORD)

    def test_weak_password_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            with self.assertRaises(ValueError):
                protect_files([source], Path(temp) / "vault.cpvault", "too-short")

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            vault = root / "secret.cpvault"
            protect_files([source], vault, PASSWORD)
            with self.assertRaises(FileExistsError):
                protect_files([source], vault, PASSWORD)

    def test_manifest_contains_no_password(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            result = protect_files([source], root / "secret.cpvault", PASSWORD)
            manifest_text = result.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn(PASSWORD, manifest_text)
            self.assertFalse(json.loads(manifest_text)["security"]["password_stored"])


if __name__ == "__main__":
    unittest.main()
