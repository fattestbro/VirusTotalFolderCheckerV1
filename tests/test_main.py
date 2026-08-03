import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import virus_checker as app

class HelperTests(unittest.TestCase):
    def test_rejects_same_scan_and_clean_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                app.validate_folder_paths(root, root)

    def test_rejects_clean_folder_inside_scan_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                app.validate_folder_paths(root, root / "clean")

    def test_unique_destination_adds_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "file.exe").write_text("x", encoding="utf-8")
            self.assertEqual(app.unique_destination(folder, "file.exe").name, "file (1).exe")

    def test_resolve_relative_path(self) -> None:
        result = app.resolve_config_path("notchecked", "notchecked")
        self.assertEqual(result, (app.BASE_DIR / "notchecked").resolve())


if __name__ == "__main__":
    unittest.main()
