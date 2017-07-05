import pytest
import sdk_utils as utils


@pytest.fixture(scope='session')
def configure_universe(request):
    utils.configure_universe(request)
