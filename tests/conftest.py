import json
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/fixtures/alternate-path.json"


@pytest.fixture
def raw_fixture():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def fixture_file(tmp_path, raw_fixture):
    def write(raw=None):
        path = tmp_path / "fixture.json"
        path.write_text(json.dumps(raw if raw is not None else raw_fixture), encoding="utf-8")
        return path

    return write
