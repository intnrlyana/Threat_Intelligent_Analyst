from pathlib import Path


def test_live_provider_exists_and_bundled_threat_data_is_absent() -> None:
    provider = Path(__file__).parents[1] / "backend" / "src" / "providers" / "virustotal_provider.py"
    data_dir = Path(__file__).parents[1] / "backend" / "src" / "data"
    assert provider.is_file()
    assert not list(data_dir.glob("*.json"))
