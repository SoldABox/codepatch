import tempfile
import unittest
from pathlib import Path
from file_vault import protect_files, verify_vault, decrypt_vault

class VaultTests(unittest.TestCase):
    def test_round_trip_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); src=root/"secret.txt"; src.write_text("hello",encoding="utf-8")
            vault=root/"x.cpvault"
            result=protect_files([src],vault,"a"*20)
            checked=verify_vault(vault,result.manifest_path)
            self.assertTrue(checked.valid)
            out=root/"out"; self.assertEqual(decrypt_vault(vault,out,"a"*20),1)
            self.assertEqual((out/"secret.txt").read_text(encoding="utf-8"),"hello")

if __name__=="__main__": unittest.main()
