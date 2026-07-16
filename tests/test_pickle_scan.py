import pickle
from pathlib import Path

from pysentinel.scanners.pickle_scan import scan_pickle_and_model_file


def test_benign_pickle_is_parsed(tmp_path: Path):
    path = tmp_path / "sample.pkl"
    path.write_bytes(pickle.dumps({"x": [1, 2, 3]}))
    findings = scan_pickle_and_model_file(path, 1024 * 1024, 100)
    assert isinstance(findings, list)
