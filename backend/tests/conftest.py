import pytest

from .helpers import FixtureSite


@pytest.fixture
def site():
    fixture = FixtureSite()
    yield fixture
    fixture.close()
