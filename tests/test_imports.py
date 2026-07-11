from pathlib import Path
import importlib

PKG = "minisiem"


def test_package_importable():
    mod = importlib.import_module(PKG)
    assert mod.__name__ == PKG


def test_source_files_present():
    root = Path(__file__).resolve().parent.parent
    assert any(root.rglob("*.py"))
