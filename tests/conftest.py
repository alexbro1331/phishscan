import pytest

from tests.helpers import build_eml


@pytest.fixture
def write_eml(tmp_path):
    def _w(**kw):
        p = tmp_path / "sample.eml"
        p.write_bytes(build_eml(**kw))
        return p
    return _w
