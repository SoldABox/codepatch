import json
import tempfile
import unittest
from pathlib import Path

from file_vault import classify_path, decrypt_vault, inventory, protect_files, verify_vault


class FileVaultTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_path(Path("CORE PHILOSOPHY 2.pdf")), "CONFIDENTIAL_IP")
        self.assertEqual(classify_path(Path("private.key")), "RESTRICTED_SECRET")
        self.assertEqual(classify_path(Path("image.png")), "INTERNAL")

    def test_inventory_hashes_and_classifies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = root / "strategy.pdf"
            document.write_bytes(b"strategy")
            report = inventory([document])
            self.assertEqual(report["summary"]["CONFIDENTIAL_IP"], 1)
            self.assertEqual(report["files"][0]["size"], 8)
            self.assertEqual(len(report["files"][0]["sha256"]), 64)

    def test_encrypt_verify_and_decrypt_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "notes.txt").write_text("private logic", encoding="utf-8")
            nested = source / "models"
            nested.mkdir()
            (nested / "logic.lua").write_text("return 42\n", encoding="utf-8")
            vault = root / "protected.cpvault"

            result = protect_files(
                [source],
                vault,
                "correct horse battery staple",
                manifest_key="manifest-secret",
            )
            self.assertTrue(result.vault_path.exists())
            self.assertTrue(result.manifest_path.exists())
            self.assertTrue(verify_vault(vault, manifest_key="manifest-secret").valid)
            self.assertFalse(verify_vault(vault, manifest_key="wrong").valid)

            output = root / "restored"
            count = decrypt_vault(vault, output, "correct horse battery staple")
            self.assertEqual(count, 2)
            self.assertEqual((output / "source" / "notes.txt").read_text(encoding="utf-8"), "private logic")
            self.assertEqual((output / "source" / "models" / "logic.lua").read_text(encoding="utf-8"), "return 42\n")

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.pdf"
            source.write_bytes(b"original")
            vault = root / "secret.cpvault"
            protect_files([source], vault, "correct horse battery staple")
            data = bytearray(vault.read_bytes())
            data[-1] ^= 1
            vault.write_bytes(data)
            self.assertFalse(verify_vault(vault).valid)

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            vault = root / "secret.cpvault"
            protect_files([source], vault, "correct horse battery staple")
            with self.assertRaises(FileExistsError):
                protect_files([source], vault, "correct horse battery staple")

    def test_manifest_contains_no_password(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            vault = root / "secret.cpvault"
            password = "correct horse battery staple"
            result = protect_files([source], vault, password)
            manifest_text = result.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn(password, manifest_text)
            manifest = json.loads(manifest_text)
            self.assertFalse(manifest["security"]["password_stored"])


if __name__ == "__main__":
    unittest.main()
