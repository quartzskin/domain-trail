import pytest

from domain_trail import store


@pytest.fixture
def db(tmp_path):
    return store.connect(tmp_path / "t.db")
